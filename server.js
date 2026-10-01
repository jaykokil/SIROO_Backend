import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

dotenv.config();

import { buildXlsx } from './lib/xlsx.js';

const app = express();
// Behind Render/Railway/Nginx the real protocol comes from the proxy, so links
// the server builds (e.g. the POS webhook URL) use https.
app.set('trust proxy', 1);

// CORS_ORIGIN can list several sites, comma-separated — e.g. the admin panel
// and the user app: https://admin.siroo.in,https://app.siroo.in
const CORS_ORIGINS = (process.env.CORS_ORIGIN || '*').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: CORS_ORIGINS.includes('*') ? '*' : CORS_ORIGINS,
  credentials: !CORS_ORIGINS.includes('*'),
}));
app.use(express.json({ limit: '2mb' }));
app.disable('x-powered-by');   // don't advertise Express

// ═════════════════════════════════════════════════════════════════════════════
// SECURITY LAYER
// ═════════════════════════════════════════════════════════════════════════════

// Browser security headers. The API only returns JSON, so it can be strict.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (process.env.NODE_ENV === 'production')
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
  next();
});

// Strip MongoDB operators ($gt, $ne, $where…) and prototype keys from anything
// a client sends, so `{"email":{"$ne":null}}` can't turn into a database query.
const BAD_KEY = k => k.startsWith('$') || k === '__proto__' || k === 'constructor' || k === 'prototype';
function scrub(v, depth = 0) {
  if (depth > 20 || v === null || typeof v !== 'object') return v;
  if (Array.isArray(v)) return v.map(x => scrub(x, depth + 1));
  const out = {};
  for (const [k, val] of Object.entries(v)) if (!BAD_KEY(k)) out[k] = scrub(val, depth + 1);
  return out;
}
app.use((req, res, next) => {
  // The raw POS payload is logged as sent, but still scrubbed before use
  if (req.body && typeof req.body === 'object') req.body = scrub(req.body);
  const q = scrub(req.query || {});
  Object.defineProperty(req, 'query', { value: q, writable: true, configurable: true, enumerable: true });
  next();
});

// Small in-memory rate limiter (one server instance is enough for SIROO).
// failuresOnly: count only attempts that failed (for logins), so a whole bar
// signing in at shift start on one Wi-Fi is never blocked by its own staff.
function rateLimit({ windowMs, max, key, message, failuresOnly = false }) {
  const hits = new Map();
  setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (v.reset <= now) hits.delete(k); }, 60_000).unref();
  const bump = k => {
    const now = Date.now();
    let h = hits.get(k);
    if (!h || h.reset <= now) { h = { count: 0, reset: now + windowMs }; hits.set(k, h); }
    h.count += 1;
  };
  return (req, res, next) => {
    const k = key(req); const now = Date.now();
    const h = hits.get(k);
    if (h && h.reset > now && h.count >= max) {
      res.setHeader('Retry-After', Math.ceil((h.reset - now) / 1000));
      return res.status(429).json({ error: message || 'Too many requests. Please wait a moment and try again.' });
    }
    if (failuresOnly) res.on('finish', () => { if (res.statusCode === 401 || res.statusCode === 403 || res.statusCode === 400) bump(k); });
    else bump(k);
    next();
  };
}
const loginId = req => String(req.body?.email || req.body?.username || '').trim().toLowerCase().slice(0, 120);
// Password guessing: per IP, and per account from any IP
const loginLimitIp      = rateLimit({ windowMs: 15 * 60_000, max: 30, key: req => 'ip:' + req.ip,
  message: 'Too many login attempts from this network. Try again in 15 minutes.', failuresOnly: true });
const loginLimitAccount = rateLimit({ windowMs: 15 * 60_000, max: 8,  key: req => 'acct:' + loginId(req),
  message: 'Too many failed attempts for this account. Try again in 15 minutes.', failuresOnly: true });
const adminLoginLimit   = rateLimit({ windowMs: 15 * 60_000, max: 5,  key: req => 'admin:' + req.ip,
  message: 'Too many admin login attempts. Try again in 15 minutes.', failuresOnly: true });
// General ceiling per IP for the API (POS webhooks are excluded — bills can burst)
const apiLimit = rateLimit({ windowMs: 60_000, max: 600, key: req => 'api:' + req.ip });
app.use('/api', (req, res, next) => req.path.startsWith('/pos/webhook') ? next() : apiLimit(req, res, next));

// Constant-time string compare (no timing hints about how much matched)
function safeEqual(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}
// Regex from user text — escaped, so input like ".*" is matched literally
const rxEscape  = t => String(t ?? '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const exactCi   = t => new RegExp('^' + rxEscape(String(t ?? '').trim()) + '$', 'i');
const containsCi= t => new RegExp(rxEscape(String(t ?? '').trim().slice(0, 100)), 'i');

const IS_PROD = process.env.NODE_ENV === 'production';
const MONGO_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/siroo';
const JWT_SECRET = process.env.JWT_SECRET || 'siroo_dev_secret';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@siroo.in';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'siroo_admin_2024';
const PORT = process.env.PORT || 5000;

// On a live server, never run with the development defaults — anyone reading
// this code would know the admin password and could forge login tokens.
if (IS_PROD) {
  const missing = [];
  if (!process.env.MONGODB_URI) missing.push('MONGODB_URI');
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) missing.push('JWT_SECRET (32+ characters)');
  if (!process.env.ADMIN_EMAIL) missing.push('ADMIN_EMAIL');
  if (!process.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD === 'siroo_admin_2024' || process.env.ADMIN_PASSWORD.length < 12)
    missing.push('ADMIN_PASSWORD (12+ characters, not the default)');
  if (!process.env.CORS_ORIGIN || CORS_ORIGINS.includes('*')) missing.push('CORS_ORIGIN (the admin panel and app addresses, not *)');
  if (missing.length) {
    console.error('Refusing to start in production. Set these environment variables:\n  - ' + missing.join('\n  - '));
    process.exit(1);
  }
}
// Connection string with the password hidden, for logs
const MONGO_URI_SAFE = MONGO_URI.replace(/\/\/([^:@/]+):([^@/]+)@/, '//$1:****@');

// ─── Mongoose Schemas ────────────────────────────────────────────────────────

const userSchema = new mongoose.Schema({
  brandName: { type: String, required: true },
  ownerName: { type: String, required: true },
  mobile: String,
  email: { type: String, required: true, unique: true, lowercase: true },
  passwordHash: { type: String, required: true },
  subscriptionEnds: { type: Date, required: true },
  status: { type: String, enum: ['Active', 'Blocked'], default: 'Active' },
  tokensValidAfter: Date,   // logins issued before this (e.g. a password change) stop working
}, { timestamps: true });

const spiritCategorySchema = new mongoose.Schema({
  name:         { type: String, required: true, unique: true },
  gramToMlRatio:{ type: Number, required: true, min: 0.1, max: 2.0 },
  description:  String,
}, { timestamps: true });

const masterBottleSchema = new mongoose.Schema({
  name: { type: String, required: true },
  category: { type: String, required: true },
  bottleSizeMl: { type: Number, required: true },
  barcode: { type: String, required: true, unique: true },
  emptyBottleWeightG: { type: Number, required: true },
  image: String,
}, { timestamps: true });

const barSchema = new mongoose.Schema({
  name: { type: String, required: true },
  type: { type: String, enum: ['stockroom', 'bar'], required: true },
});

const outletSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  bars: [barSchema],
}, { timestamps: true });

const userProductSchema = new mongoose.Schema({
  userId:           { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  masterBottleId:   { type: mongoose.Schema.Types.ObjectId, ref: 'MasterBottle', required: true },
  outletIds:        [{ type: mongoose.Schema.Types.ObjectId, ref: 'Outlet' }],
  name:             String,
  category:         String,
  bottleSizeMl:     Number,
  fullBottleWeightG:Number,
  emptyBottleWeightG:Number,
  // How this item's stock is believed: weighed on a scale, or driven by the POS.
  // Anything that is physically counted must stay 'physical', otherwise the POS
  // would overwrite the very measurement we compare against.
  trackingMode: { type: String, enum: ['physical','pos'], default: 'physical' },

  // Excise (Maharashtra SCM portal) linkage
  scmItemCode:   String,
  scmBrandName:  String,
  scmSize:       String,
  bottlesPerCase:Number,
  barcode:          String,
  cost:             { type: Number, required: true },
  active:           { type: Boolean, default: true },
}, { timestamps: true });

const stockSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  outletId: { type: mongoose.Schema.Types.ObjectId, ref: 'Outlet', required: true },
  locationId: { type: String, required: true },
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'UserProduct', required: true },
  fullBottles: { type: Number, default: 0 },
  openMl: { type: Number, default: 0 },
}, { timestamps: true });
stockSchema.index({ userId: 1, outletId: 1, locationId: 1, productId: 1 }, { unique: true });

const inventoryLogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  outletId: { type: mongoose.Schema.Types.ObjectId, ref: 'Outlet' },
  outletName: String,
  locationId: String,
  locationName: String,
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'UserProduct' },
  productName: String,
  category: String,
  bottleSizeMl: Number,
  type: { type: String, default: 'closing' },
  openingFullBottles: Number,
  openingOpenMl: Number,
  emptyBottles: Number,
  remainingMl: Number,
  closingFullBottles: Number,
  closingOpenMl: Number,
  consumedMl: Number,
  consumedBottles: Number,
  countMethod: { type: String, enum: ['empty','full'], default: 'empty' },
  totalSell: Number,
  note: String,
  // POS comparison for the window since the previous count (copied from the
  // PosSettlement banked by this count, so the count screen can show it)
  settlementId:  { type: mongoose.Schema.Types.ObjectId, ref: 'PosSettlement' },
  posComparedAt: Date,
  posWindowFrom: Date,
  posBills:      Number,   // bill lines in the window
  posSoldQty:    Number,   // chargeable serves
  posSoldMl:     Number,   // chargeable ML billed
  posSalesValue: Number,
  ncQty:         Number,   // NC serves
  ncMl:          Number,   // NC ML — poured, not charged
  varianceMl:    Number,   // consumedMl − posSoldMl − ncMl
  at: { type: Date, default: Date.now },
}, { timestamps: true });

const historySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: String,
  userName: String,
  productName: String,
  outletName: String,
  locationName: String,
  fromLocationName: String,
  toLocationName: String,
  outletId: mongoose.Schema.Types.ObjectId,
  locationId: String,
  fromLocationId: String,
  toLocationId: String,
  productId: mongoose.Schema.Types.ObjectId,   // was silently dropped before — needed to aggregate per product
  reason: String,
  quantity: Number,
  qty: Number,
  consumedMl: Number,
  totalSell: Number,
  cost: Number,
  at: { type: Date, default: Date.now },
}, { timestamps: true });

const subUserSchema = new mongoose.Schema({
  userId:   { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },

  // Step 1 — credentials
  username: { type: String, required: true },      // login id, unique per parent account
  passwordHash: String,
  tokensValidAfter: Date,                           // logins issued before this stop working

  // Step 2 — who they are
  name:  { type: String, required: true },
  phone: String,
  email: String,

  // Step 3 — role
  designation: String,                              // Manager, Bar Staff, Controller, ...

  // Step 4 — access
  outletAccess: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Outlet' }],
  barAccess:    [String],                           // optional narrowing within an outlet
  sections:     [String],                           // keys from SECTIONS below
  financialAccess: { type: Boolean, default: false },// false hides every money value

  status:     { type: String, default: 'Active' },
  lastLoginAt: Date,
  lastActive: String,
}, { timestamps: true });
subUserSchema.index({ userId: 1, username: 1 }, { unique: true });

// Par level for one product at one bar / stock room.
// Maharashtra excise SCM portal catalogue. Every bottle the licensee sells must
// be reported under the portal's own Local Item Code, so this is the bridge
// between a SIROO product and what the portal will accept.
// ── POS MIRROR LEDGER ────────────────────────────────────────────────────────
// A second, independent stock ledger held per bar. It only ever moves because
// the POS moved, so the physical count stays untouched evidence to compare with.
// Nothing here is user-editable.
const posStockSchema = new mongoose.Schema({
  userId:     { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  outletId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Outlet', required: true },
  locationId: { type: String, required: true },          // always a bar
  productId:  { type: mongoose.Schema.Types.ObjectId, ref: 'UserProduct', required: true },

  // Mirror level. Allowed to go negative — that is a signal, not an error.
  fullBottles:{ type: Number, default: 0 },
  openMl:     { type: Number, default: 0 },

  // Running figures since the last settle, which is what variance is measured over
  anchoredAt:     { type: Date, default: Date.now },
  posConsumedMl:  { type: Number, default: 0 },          // chargeable ML only
  posSalesValue:  { type: Number, default: 0 },          // real revenue off the bill
  posLines:       { type: Number, default: 0 },
  posQty:         { type: Number, default: 0 },          // chargeable serves
  ncMl:           { type: Number, default: 0 },          // NC (non-chargeable) ML
  ncQty:          { type: Number, default: 0 },
  lastSaleAt:     Date,
}, { timestamps: true });
posStockSchema.index({ userId: 1, outletId: 1, locationId: 1, productId: 1 }, { unique: true });

// One row each time the mirror is re-anchored to a physical count.
const posSettlementSchema = new mongoose.Schema({
  userId:     { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  outletId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Outlet' },
  outletName: String,
  locationId: String,
  locationName: String,
  productId:  { type: mongoose.Schema.Types.ObjectId, ref: 'UserProduct' },
  productName:String,
  bottleSizeMl:Number,
  periodFrom: Date,
  periodTo:   { type: Date, default: Date.now },

  posConsumedMl:      Number,   // chargeable ML the POS says was poured
  posQty:             Number,
  ncMl:               Number,   // NC ML punched on the POS (poured, not charged)
  ncQty:              Number,
  physicalConsumedMl: Number,   // what the scale says was poured
  varianceMl:         Number,   // physical - pos - nc. positive = more gone than billed
  inventoryLogId:     { type: mongoose.Schema.Types.ObjectId, ref: 'InventoryLog' },
  varianceValue:      Number,   // variance costed at purchase price
  posSalesValue:      Number,   // revenue booked on those orders
  posLines:           Number,

  mirrorBeforeMl: Number,
  actualAfterMl:  Number,
  reason: { type: String, enum: ['count','manual'], default: 'count' },
}, { timestamps: true });
posSettlementSchema.index({ userId: 1, periodTo: -1 });

const scmItemSchema = new mongoose.Schema({
  itemType:      String,   // Spirits | Fermented Beer | Mild Beer | Wines
  itemName:      String,
  uom:           String,   // the portal's exact Size string, e.g. "180 ML(50)"
  localItemCode: { type: String, required: true, unique: true },
  bottleSizeMl:  Number,
  bottlesPerCase:Number,
}, { timestamps: true });
scmItemSchema.index({ itemName: 'text' });

const parStockSchema = new mongoose.Schema({
  userId:     { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  outletId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Outlet', required: true },
  locationId: { type: String, required: true },
  productId:  { type: mongoose.Schema.Types.ObjectId, ref: 'UserProduct', required: true },
  minBottles: { type: Number, required: true, min: 0 },
  active:     { type: Boolean, default: true },
  // Dismissing hides the alert until stock climbs back to par and falls again,
  // so ignoring it once does not silence it forever.
  dismissedAt:{ type: Date, default: null },
}, { timestamps: true });
parStockSchema.index({ userId: 1, outletId: 1, locationId: 1, productId: 1 }, { unique: true });

// ── POS Integration Engine Schemas ───────────────────────────────────────────

const posConfigSchema = new mongoose.Schema({
  userId:       { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  siRooOutletId:{ type: mongoose.Schema.Types.ObjectId, ref: 'Outlet', required: true },
  posName:      { type: String, required: true, default: 'petpooja' },
  label:        String,
  active:       { type: Boolean, default: true },

  // Petpooja's Global API is push-only: they POST to us on "SAVE AND PRINT".
  // There is no order or menu endpoint to poll, so webhook is the only real mode.
  syncMode:     { type: String, enum: ['webhook'], default: 'webhook' },

  // Identity + optional auth, exactly as the Global API defines them
  restID:       { type: String, index: true },  // properties.Restaurant.restID
  staticToken:  String,                         // matched against payload "token" / "Token"
  webhookKey:   String,                         // secret in the webhook URL — only Petpooja knows it
  autoDeduct:   { type: Boolean, default: true },// deduct stock as bills arrive

  lastEventAt:  Date,
  lastOrderId:  String,
  ordersReceived:{ type: Number, default: 0 },
}, { timestamps: true });
posConfigSchema.index({ userId: 1, restID: 1 });

// One row per POS item (or addon) the operator has pointed at real stock.
// The bar is set per mapping — that is what decides which stock gets deducted.
const menuMappingSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  posConfigId: { type: mongoose.Schema.Types.ObjectId, ref: 'PosConfig', required: true },
  kind:        { type: String, enum: ['item','addon'], default: 'item' },
  posItemId:   { type: String, required: true },   // itemid, or addon_id for addons
  posItemName: String,
  posCategory: String,

  // Where the stock comes off
  locationId:  { type: String, required: true },
  locationName:String,

  // What it comes off
  targetType:  { type: String, enum: ['bottle','prebatch','keg'], default: 'bottle' },
  bottleId:    { type: mongoose.Schema.Types.ObjectId, ref: 'UserProduct' }, // targetType 'bottle'
  pbRecipeId:  { type: mongoose.Schema.Types.ObjectId, ref: 'PbRecipe' },    // targetType 'prebatch'
  kegBeerId:   { type: mongoose.Schema.Types.ObjectId, ref: 'DraftBeer' },   // targetType 'keg'

  mlPerServe:  { type: Number, default: 0 },
  active:      { type: Boolean, default: true },
  notes:       String,
}, { timestamps: true });
menuMappingSchema.index({ posConfigId: 1, kind: 1, posItemId: 1 }, { unique: true });

// Items seen on live bills that nobody has mapped yet — the mapping inbox.
// With no menu API, this is the only way to discover what Petpooja is selling.
const posUnmappedItemSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  posConfigId: { type: mongoose.Schema.Types.ObjectId, ref: 'PosConfig', required: true },
  kind:        { type: String, enum: ['item','addon'], default: 'item' },
  posItemId:   { type: String, required: true },
  posItemName: String,
  posCategory: String,
  lastPrice:   Number,
  timesSeen:   { type: Number, default: 0 },
  qtySeen:     { type: Number, default: 0 },
  firstSeenAt: Date,
  lastSeenAt:  Date,
  ignored:     { type: Boolean, default: false },  // e.g. food — never stock-backed
}, { timestamps: true });
posUnmappedItemSchema.index({ posConfigId: 1, kind: 1, posItemId: 1 }, { unique: true });

// One row per billed line. lineIndex keeps repeated items in one bill distinct,
// and makes a re-printed bill idempotent rather than double-deducting.
const posSaleSchema = new mongoose.Schema({
  userId:         { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  posConfigId:    { type: mongoose.Schema.Types.ObjectId, ref: 'PosConfig' },
  siRooOutletId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Outlet' },

  posOrderId:     String,
  invoiceId:      String,
  lineIndex:      { type: Number, default: 0 },
  kind:           { type: String, enum: ['item','addon'], default: 'item' },
  posItemId:      String,
  posItemName:    String,
  posCategory:    String,

  quantity:       Number,
  unitPrice:      Number,
  lineTotal:      Number,
  lineDiscount:   Number,

  // Order-level context straight off the payload
  orderStatus:    { type: String, enum: ['Success','Cancelled'], default: 'Success' },
  orderType:      String,   // Dine In / Pick Up / Delivery
  paymentType:    String,   // Cash / Card / Online / Other / Part Payment
  orderFrom:      String,   // POS / Zomato / Swiggy ...
  subOrderType:   String,
  tableNo:        String,
  biller:         String,

  // Resolution
  mapped:         { type: Boolean, default: false },
  targetType:     String,
  bottleId:       { type: mongoose.Schema.Types.ObjectId, ref: 'UserProduct' },
  targetRefId:    mongoose.Schema.Types.ObjectId,  // PbBottle / Keg actually hit
  locationId:     String,
  locationName:   String,
  mlPerServe:     Number,
  totalMlDeducted:Number,

  deducted:       { type: Boolean, default: false },
  reversed:       { type: Boolean, default: false },
  shortfallMl:    { type: Number, default: 0 },   // wanted more than the bar had
  note:           String,

  servedMl:       Number,   // qty × ML per serve, whether or not real stock moved
  isNc:           { type: Boolean, default: false },  // NC / complimentary line
  ncReason:       String,
  mirroredAt:     Date,     // when this line was applied to the POS mirror
  kegLogId:       { type: mongoose.Schema.Types.ObjectId, ref: 'KegLog', default: null },     // keg count that used it
  pbCountId:      { type: mongoose.Schema.Types.ObjectId, ref: 'PbCountLog', default: null }, // pre-batch count that used it

  soldAt:         Date,
}, { timestamps: true });
posSaleSchema.index({ posConfigId: 1, posOrderId: 1, kind: 1, posItemId: 1, lineIndex: 1 }, { unique: true });
posSaleSchema.index({ userId: 1, soldAt: -1 });

// Raw payload audit — every push is kept so a bad bill can always be traced back.
const posWebhookLogSchema = new mongoose.Schema({
  posConfigId: { type: mongoose.Schema.Types.ObjectId, ref: 'PosConfig' },
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  restID:      String,
  event:       String,
  orderId:     String,
  orderStatus: String,
  ok:          Boolean,
  message:     String,
  linesTotal:  Number,
  linesMapped: Number,
  mlDeducted:  Number,
  payload:     mongoose.Schema.Types.Mixed,
  at:          { type: Date, default: Date.now },
}, { timestamps: true });
posWebhookLogSchema.index({ posConfigId: 1, at: -1 });

const reconciliationSchema = new mongoose.Schema({
  userId:           { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  siRooOutletId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Outlet' },
  posConfigId:      { type: mongoose.Schema.Types.ObjectId, ref: 'PosConfig' },
  bottleId:         { type: mongoose.Schema.Types.ObjectId, ref: 'UserProduct' },
  bottleName:       String,
  date:             Date,
  openingMl:        Number,
  closingMl:        Number,
  physicalConsumedMl: Number,
  posSalesML:       Number,
  ncMl:             Number,
  counts:           Number,
  variance:         Number,
  variancePct:      String,
  status:           { type: String, enum: ['OK','SHRINKAGE','SURPLUS','UNRECONCILED'], default: 'UNRECONCILED' },
}, { timestamps: true });

// ── Model Registrations ───────────────────────────────────────────────────────


// ── Pre-Batch Schemas ─────────────────────────────────────────────────────────

const pbIngredientSchema = new mongoose.Schema({
  name:        { type: String, required: true },
  density:     { type: Number, required: true, default: 1.00 }, // g/ml
  unit:        { type: String, default: 'ml' },
  description: String,
  isCustom:    { type: Boolean, default: false },
}, { timestamps: true });

const pbRecipeSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  outletId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Outlet', required: true },
  name:        { type: String, required: true },
  description: String,
  yieldMl:     { type: Number, required: true },  // total batch output in ml
  shelfLifeDays:{ type: Number, default: 7 },
  ingredients: [{
    type:        { type: String, enum: ['spirit','nonalcohol'], required: true },
    productId:   { type: mongoose.Schema.Types.ObjectId, ref: 'UserProduct' },   // for spirits
    ingredientId:{ type: mongoose.Schema.Types.ObjectId, ref: 'PbIngredient' }, // for non-alcohol
    name:        String,
    quantityMl:  { type: Number, required: true },
    density:     { type: Number, default: 1.00 },
  }],
  avgDensity:  Number, // auto-calculated
  active:      { type: Boolean, default: true },
}, { timestamps: true });

const pbBatchSchema = new mongoose.Schema({
  userId:        { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  outletId:      { type: mongoose.Schema.Types.ObjectId, ref: 'Outlet', required: true },
  locationId:    String,
  recipeId:      { type: mongoose.Schema.Types.ObjectId, ref: 'PbRecipe', required: true },
  recipeName:    String,
  batchNo:       { type: String, required: true, unique: true },
  producedAt:    { type: Date, default: Date.now },
  expiresAt:     Date,
  yieldMl:       Number,
  avgDensity:    Number,
  // Tare weight captured after bartender weighs filled bottle
  tareWeightG:   { type: Number, default: null },
  filledWeightG: { type: Number, default: null },
  remainingMl:   Number,
  status:        { type: String, enum: ['active','depleted','expired','wasted'], default: 'active' },
  notes:         String,
}, { timestamps: true });

const pbWastageSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  outletId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Outlet', required: true },
  batchId:   { type: mongoose.Schema.Types.ObjectId, ref: 'PbBatch', required: true },
  batchNo:   String,
  recipeName:String,
  wasteMl:   Number,
  reason:    String,
  at:        { type: Date, default: Date.now },
}, { timestamps: true });


const pbBottleSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  batchId:     { type: mongoose.Schema.Types.ObjectId, ref: 'PbBatch', required: true },
  batchNo:     String,
  recipeName:  String,
  outletId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Outlet' },
  locationId:  String,  // current location (stockroom or bar)
  locationName:String,
  tag:         String,  // auto-generated e.g. "MOJI-001"
  capacityMl:  Number,  // bottle capacity
  filledMl:    Number,  // ml poured in
  grossWeightG:Number,  // total weight of filled bottle from scale
  tareWeightG: Number,  // auto-calculated silently
  avgDensity:  Number,  // inherited from batch
  remainingMl: Number,
  status:      { type: String, enum: ['stockroom','assigned','depleted','wasted'], default: 'stockroom' },
  assignedTo:  String,  // bar name
  assignedAt:  Date,
}, { timestamps: true });


// One row per pre-batch bottle count, with the POS bills for that recipe at
// that bar since the previous count of the recipe there.
const pbCountLogSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  outletId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Outlet' },
  locationId:  String,
  locationName:String,
  bottleId:    { type: mongoose.Schema.Types.ObjectId, ref: 'PbBottle' },
  tag:         String,
  batchId:     { type: mongoose.Schema.Types.ObjectId, ref: 'PbBatch' },
  batchNo:     String,
  recipeId:    { type: mongoose.Schema.Types.ObjectId, ref: 'PbRecipe' },
  recipeName:  String,
  openingMl:   Number,
  remainingMl: Number,
  consumedMl:  Number,
  posWindowFrom: Date,
  posLines:    Number,
  posSoldQty:  Number,
  posSoldMl:   Number,
  posSalesValue: Number,
  ncQty:       Number,
  ncMl:        Number,
  varianceMl:  Number,   // consumed − POS sold − NC
  posConnected:Boolean,
  at:          { type: Date, default: Date.now },
}, { timestamps: true });
pbCountLogSchema.index({ userId: 1, recipeId: 1, locationId: 1, at: -1 });

// ── Draft Beer Brand ("Beers") Schema ─────────────────────────────────────────
// Draft beer is always treated as 1.01 g/ml — never asked for, never shown.
const BEER_DENSITY = 1.01;

const draftBeerSchema = new mongoose.Schema({
  userId:        { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  outletIds:     [{ type: mongoose.Schema.Types.ObjectId, ref: 'Outlet' }],
  masterBottleId:{ type: mongoose.Schema.Types.ObjectId, ref: 'MasterBottle', default: null },
  name:          { type: String, required: true },
  category:      { type: String, default: 'Beer' },
  source:        { type: String, enum: ['master','craft'], default: 'master' },
  densityGPerMl: { type: Number, default: BEER_DENSITY },
  // Serving sizes in ml — defaults per spec, editable per brand
  servings: {
    glassMl:   { type: Number, default: 330 },
    pitcherMl: { type: Number, default: 1500 },
    towerMl:   { type: Number, default: 3000 },
  },
  // Selling price per serve
  pricing: {
    glass:   { type: Number, default: 0 },
    pitcher: { type: Number, default: 0 },
    tower:   { type: Number, default: 0 },
  },
  active:        { type: Boolean, default: true },
  notes:         String,
}, { timestamps: true });
draftBeerSchema.index({ userId: 1, name: 1 }, { unique: true });

// ── Draft Beer Keg Schemas ────────────────────────────────────────────────────

const kegAssignmentSchema = new mongoose.Schema({
  barId:      String,
  barName:    String,
  assignedAt: { type: Date, default: Date.now },
}, { _id: false });

const kegSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  outletId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Outlet', required: true },
  outletName:  String,

  // Beer identity — linked to a Beers-list brand, or a manually typed draft name
  draftBeerId: { type: mongoose.Schema.Types.ObjectId, ref: 'DraftBeer', default: null },
  productId:   { type: mongoose.Schema.Types.ObjectId, ref: 'UserProduct', default: null },
  beerName:    { type: String, required: true },
  category:    { type: String, default: 'Beer' },

  kegTag:      { type: String, required: true },   // e.g. "Keg 1"
  capacityMl:  { type: Number, required: true },   // beer quantity when full
  fullWeightG: { type: Number, required: true },   // total weight of the full keg
  // Auto-derived: tare = fullWeight − (capacity × density). Never entered by the user.
  tareWeightG: { type: Number, required: true },
  densityGPerMl:{ type: Number, default: BEER_DENSITY },  // always 1.01 for draft beer

  costPerKeg:  { type: Number, default: 0 },       // optional, for stock valuation

  // Current location — stock room until assigned
  locationId:  String,
  locationName:String,
  assignments: [kegAssignmentSchema],              // a keg line may feed one or more bars

  // Live figures
  currentWeightG:  { type: Number, default: null },
  remainingMl:     { type: Number, default: 0 },
  totalConsumedMl: { type: Number, default: 0 },
  totalWastageMl:  { type: Number, default: 0 },

  // Sales recorded during inventory, by serve type
  totalGlasses:    { type: Number, default: 0 },
  totalPitchers:   { type: Number, default: 0 },
  totalTowers:     { type: Number, default: 0 },
  totalSoldMl:     { type: Number, default: 0 },
  totalSalesValue: { type: Number, default: 0 },

  status:      { type: String, enum: ['stockroom','active','closed'], default: 'stockroom' },
  connectedAt: { type: Date, default: Date.now },
  lastInventoryAt: Date,
  closedAt:    Date,
  notes:       String,
}, { timestamps: true });
kegSchema.index({ userId: 1, outletId: 1, kegTag: 1 }, { unique: true });

// One row per inventory cycle / lifecycle event — the audit trail
const kegLogSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  kegId:       { type: mongoose.Schema.Types.ObjectId, ref: 'Keg', required: true },
  kegTag:      String,
  beerName:    String,
  outletId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Outlet' },
  outletName:  String,
  locationId:  String,
  locationName:String,
  type:        { type: String, enum: ['register','assign','transfer','inventory','wastage','closing'], default: 'inventory' },
  weightG:     Number,   // current weight entered by the user
  openingMl:   Number,   // remaining before this cycle
  remainingMl: Number,   // remaining after this cycle
  consumedMl:  Number,   // gross drop over the cycle (includes wastage)
  wastageMl:   Number,
  netConsumedMl: Number, // consumed − wastage = what actually went out as sales
  wastageReason: String,
  // Sales entered for this cycle
  glassesSold:  Number,
  pitchersSold: Number,
  towersSold:   Number,
  soldMl:       Number,   // glasses×330 + pitchers×1500 + towers×3000
  salesValue:   Number,   // priced from the brand's per-serve rates
  varianceMl:   Number,   // net consumed − sold (unaccounted pour)
  posMode:     Boolean,  // sold figures came from the POS, wastage was derived
  ncMl:        Number,   // NC poured (from the POS)
  posLines:    Number,
  posWindowFrom: Date,
  totalSell:   Number,
  note:        String,
  at:          { type: Date, default: Date.now },
}, { timestamps: true });

const kegWastageSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  kegId:       { type: mongoose.Schema.Types.ObjectId, ref: 'Keg', required: true },
  kegTag:      String,
  beerName:    String,
  outletId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Outlet' },
  locationId:  String,
  locationName:String,
  wasteMl:     Number,
  reason:      String,   // Spillage | Foam | Cleaning | Other
  isFinal:     { type: Boolean, default: false },  // recorded at Declare Keg Empty
  at:          { type: Date, default: Date.now },
}, { timestamps: true });

const User          = mongoose.model('User',          userSchema);
const MasterBottle  = mongoose.model('MasterBottle',  masterBottleSchema);
const Outlet        = mongoose.model('Outlet',        outletSchema);
const UserProduct   = mongoose.model('UserProduct',   userProductSchema);
const Stock         = mongoose.model('Stock',         stockSchema);
const InventoryLog  = mongoose.model('InventoryLog',  inventoryLogSchema);
const History       = mongoose.model('History',       historySchema);
const SubUser       = mongoose.model('SubUser',       subUserSchema);
const ParStock      = mongoose.model('ParStock',      parStockSchema);
const ScmItem       = mongoose.model('ScmItem',       scmItemSchema);
const PosStock      = mongoose.model('PosStock',      posStockSchema);
const PbCountLog    = mongoose.model('PbCountLog',    pbCountLogSchema);
const PosSettlement = mongoose.model('PosSettlement', posSettlementSchema);
const SpiritCategory = mongoose.model('SpiritCategory', spiritCategorySchema);
const PbIngredient   = mongoose.model('PbIngredient',   pbIngredientSchema);
const PbBottle       = mongoose.model('PbBottle',       pbBottleSchema);
const PbRecipe       = mongoose.model('PbRecipe',       pbRecipeSchema);
const PbBatch        = mongoose.model('PbBatch',        pbBatchSchema);
const PbWastage      = mongoose.model('PbWastage',      pbWastageSchema);
const PosConfig     = mongoose.model('PosConfig',     posConfigSchema);
const MenuMapping   = mongoose.model('MenuMapping',   menuMappingSchema);
const PosSale       = mongoose.model('PosSale',       posSaleSchema);
const PosUnmapped   = mongoose.model('PosUnmapped',   posUnmappedItemSchema);
const PosWebhookLog = mongoose.model('PosWebhookLog', posWebhookLogSchema);
const Reconciliation = mongoose.model('Reconciliation', reconciliationSchema);
const DraftBeer      = mongoose.model('DraftBeer',      draftBeerSchema);
const Keg            = mongoose.model('Keg',            kegSchema);
const KegLog         = mongoose.model('KegLog',         kegLogSchema);
const KegWastage     = mongoose.model('KegWastage',     kegWastageSchema);

// ─── Helpers ────────────────────────────────────────────────────────────────

const now = () => new Date().toISOString();

function signToken(payload, expiresIn = '7d') {
  return jwt.sign(payload, JWT_SECRET, { expiresIn, algorithm: 'HS256' });
}
const verifyToken = token => jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });

async function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.auth = verifyToken(token);
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  // User routes need a user — an admin token is not accepted here
  if (!req.auth.userId) return res.status(401).json({ error: 'Invalid or expired token' });

  // Sub-users are checked live on every request, so disabling one, changing
  // their password or removing access takes effect at once — not in 7 days.
  if (req.auth.role === 'subuser') {
    try {
      const sub = await SubUser.findById(req.auth.subUserId)
        .select('status sections outletAccess financialAccess tokensValidAfter userId');
      if (!sub || String(sub.userId) !== String(req.auth.userId))
        return res.status(401).json({ error: 'Session expired. Please log in again.' });
      if (sub.status !== 'Active')
        return res.status(403).json({ error: 'This account has been disabled by your manager.' });
      if (sub.tokensValidAfter && req.auth.iat * 1000 < sub.tokensValidAfter.getTime() - 1000)
        return res.status(401).json({ error: 'Session expired. Please log in again.' });
      req.auth.sections        = sub.sections || [];
      req.auth.outletAccess    = (sub.outletAccess || []).map(String);
      req.auth.financialAccess = Boolean(sub.financialAccess);
    } catch (e) { return res.status(500).json({ error: 'Could not verify your session' }); }
  }
  // A sub-user acts inside the owner's account, so userId always points at the owner.
  financialFilter(req, res, next);
}

// ══════════════════════════════════════════════════════════════════════════════
// ACCESS CONTROL
//
// A sub-user's token carries their granted sections, outlets and money flag.
// The sidebar hides what they lack, but the API is what actually enforces it —
// a hidden section is still refused if called directly.
// ══════════════════════════════════════════════════════════════════════════════

const SECTIONS = [
  { key:'dashboard',   label:'Dashboard' },
  { key:'inventory',   label:'Inventory (take count)' },
  { key:'stockroom',   label:'Stock Room' },
  { key:'barinventory',label:'Bar Inventory' },
  { key:'addstock',    label:'Add Stock' },
  { key:'assign',      label:'Assign to Bar' },
  { key:'transfers',   label:'Transfers' },
  { key:'products',    label:'Products' },
  { key:'prebatch',    label:'Pre-Batch' },
  { key:'keg',         label:'Keg / Draft Beer' },
  { key:'parstock',    label:'Par Stock Alerts' },
  { key:'reports',     label:'Reports' },
  { key:'salesreport', label:'Sales Report' },
  { key:'excise',      label:'Excise Report' },
  { key:'history',     label:'History' },
  { key:'outlets',     label:'Outlets & Bars' },
  { key:'subusers',    label:'Sub-Users' },
  { key:'pos',         label:'POS Integration' },
  { key:'scale',       label:'Weighing Scale' },
  { key:'settings',    label:'Settings' },
];
const SECTION_KEYS = SECTIONS.map(s => s.key);

const isSub = req => req.auth?.role === 'subuser';

// Owners have everything; sub-users only what was ticked.
function hasSection(req, key) {
  if (!isSub(req)) return true;
  return Array.isArray(req.auth.sections) && req.auth.sections.includes(key);
}
function canSeeMoney(req) {
  return !isSub(req) || req.auth.financialAccess === true;
}
function allowedOutlets(req) {
  return isSub(req) ? (req.auth.outletAccess || []).map(String) : null; // null = all
}
function canUseOutlet(req, outletId) {
  const list = allowedOutlets(req);
  if (!list) return true;
  return !outletId || list.includes(String(outletId));
}

// Route guard. Accepts one key or several — any one of them is enough.
function requireSection(...keys) {
  return (req, res, next) => {
    if (keys.some(k => hasSection(req, k))) return next();
    const label = SECTIONS.find(s => s.key === keys[0])?.label || keys[0];
    return res.status(403).json({ error: `Your account does not have access to ${label}`, deniedSection: keys[0] });
  };
}

// Blocks an outlet the sub-user was never assigned, wherever it appears.
function guardOutlet(req, res, next) {
  const outletId = req.query.outletId || req.body?.outletId || req.params?.outletId;
  if (outletId && !canUseOutlet(req, outletId)) {
    return res.status(403).json({ error: 'You do not have access to this outlet' });
  }
  next();
}

// Money is stripped server-side, not just hidden in the UI, so a sub-user
// without financial access cannot read prices out of the network tab.
const MONEY_FIELDS = ['cost','totalSell','stockValue','totalStockValue','salesValue','unitPrice','lineTotal','lineDiscount','price','amount','totalCost','value',
  'posSalesValue','varianceValue','gapValue','costOfSales','totalValue','totalPosSales','totalVarianceValue',
  'menuValue','ncCostValue','totalNcCostValue'];
function stripMoney(payload) {
  if (Array.isArray(payload)) return payload.map(stripMoney);
  if (payload && typeof payload === 'object') {
    if (typeof payload.toObject === 'function') payload = payload.toObject();
    const out = {};
    for (const [k, v] of Object.entries(payload)) {
      if (MONEY_FIELDS.includes(k)) continue;
      out[k] = (v && typeof v === 'object') ? stripMoney(v) : v;
    }
    return out;
  }
  return payload;
}

// Wraps res.json once per request so every handler is covered automatically.
function financialFilter(req, res, next) {
  // Decided when the response is sent, using the access loaded for this request
  const original = res.json.bind(res);
  res.json = body => original(canSeeMoney(req) ? body : stripMoney(body));
  next();
}

function adminMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = verifyToken(token);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    req.auth = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

async function subscriptionCheck(req, res, next) {
  try {
    const user = await User.findById(req.auth.userId);
    if (!user) return res.status(401).json({ error: 'User not found' });
    if (user.status === 'Blocked') return res.status(403).json({ error: 'Account blocked. Contact SIROO support.' });
    if (new Date(user.subscriptionEnds) < new Date()) return res.status(403).json({ error: 'Subscription expired. Contact SIROO to renew.' });
    // Owner's password changed after this login was issued
    if (req.auth.role !== 'subuser' && user.tokensValidAfter && req.auth.iat * 1000 < user.tokensValidAfter.getTime() - 1000)
      return res.status(401).json({ error: 'Session expired. Please log in again.' });
    req.user = user;
    next();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

function locationName(outlet, locationId) {
  return outlet?.bars?.find(b => b._id?.toString() === locationId || b.id === locationId)?.name || '';
}

async function addHistory(userId, action, details = {}) {
  await History.create({ userId, action, at: new Date(), ...details }).catch(() => {});
}

// countMethod:
//   'empty' (default) — user enters the EMPTY bottle count. Original logic, untouched.
//   'full'            — user enters the REMAINING FULL bottle count; the difference
//                       against opening is treated as consumed bottles.
// Both paths end at the same ml maths, so downstream inventory/reporting is unchanged.
function calculateConsumption({ openingFullBottles, openingOpenMl, emptyBottles, remainingMl, bottleSizeMl, cost, countMethod = 'empty', closingFullBottles: closingFullInput }) {
  const size      = Math.max(1, Number(bottleSizeMl || 1));
  const openFull  = Math.max(0, Number(openingFullBottles || 0));
  const openMl    = Math.max(0, Number(openingOpenMl || 0));
  const closingMl = Math.max(0, Number(remainingMl || 0));

  // Total ml available at opening = open bottle + full bottles
  const totalOpeningMl = openMl + openFull * size;

  let closingFullBottles;
  if (countMethod === 'full') {
    // User physically counted the unopened bottles left on the shelf
    closingFullBottles = Math.max(0, Number(closingFullInput || 0));
  } else {
    // Existing behaviour — drain from the open bottle first, then count full bottles consumed
    const empties = Math.max(0, Number(emptyBottles || 0));
    closingFullBottles = Math.max(0, openFull - empties - (closingMl > 0 ? 1 : 0));
  }

  const totalClosingMl  = closingMl + closingFullBottles * size;
  const consumedMl      = Math.max(0, Math.round(totalOpeningMl - totalClosingMl));
  const consumedBottles = Math.max(0, openFull - closingFullBottles);

  const perMl = Number(cost || 0) / size;
  return { consumedMl, totalSell: Math.round(consumedMl * perMl), closingFullBottles, consumedBottles };
}

async function getOrCreateStock(userId, outletId, locationId, productId) {
  let line = await Stock.findOne({ userId, outletId, locationId, productId });
  if (!line) {
    line = await Stock.create({ userId, outletId, locationId, productId, fullBottles: 0, openMl: 0 });
  }
  return line;
}

async function enrichStock(userId, outletId, locationId) {
  const lines = await Stock.find({ userId, outletId, locationId });
  const result = [];
  for (const line of lines) {
    const p = await UserProduct.findById(line.productId);
    if (!p) continue;
    const stockValue = line.fullBottles * p.cost + (line.openMl / p.bottleSizeMl) * p.cost;
    result.push({
      productId: line.productId,
      id: p._id,
      name: p.name,
      category: p.category,
      bottleSizeMl: p.bottleSizeMl,
      cost: p.cost,
      barcode: p.barcode,
      fullBottles: line.fullBottles,
      openMl: Math.round(line.openMl),
      stockValue: Math.round(stockValue),
    });
  }
  return result;
}

// ─── Seed Master Bottles ────────────────────────────────────────────────────

// ══════════════════════════════════════════════════════════════════════════════
// POS INTEGRATION ENGINE
//
// Petpooja's Global API is event-driven and push-only: when the cashier hits
// "SAVE AND PRINT", Petpooja POSTs the bill to our webhook. There is no orders
// endpoint and no menu endpoint to pull from, so there is nothing to poll.
//
// Payload shape (per Global API doc):
//   { token, event: "orderdetails", properties: { Restaurant, Customer, Order,
//     Tax[], Discount[], OrderItem[{ ..., addon[] }] } }
// ══════════════════════════════════════════════════════════════════════════════

// The doc's own sample payloads use "token" in three places and "Token" in the
// aggregator example, so both spellings are accepted.
function readPayloadToken(body) {
  return body?.token ?? body?.Token ?? body?.properties?.token ?? '';
}

function petpoojaOrderDate(order) {
  // "2025-04-04 11:45:35" — parsed as local time, not UTC
  const raw = order?.created_on;
  if (!raw) return new Date();
  const m = String(raw).match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/);
  if (!m) { const d = new Date(raw); return isNaN(d) ? new Date() : d; }
  return new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
}

// Flatten a bill into billable lines. Addons carry their own id and their
// quantity multiplies the parent item's quantity.
function flattenOrderItems(orderItems = []) {
  const lines = [];
  let idx = 0;
  for (const item of orderItems) {
    const itemQty = Math.max(0, Number(item?.quantity ?? 1) || 0);
    lines.push({
      lineIndex:   idx++,
      kind:        'item',
      posItemId:   String(item?.itemid ?? item?.itemcode ?? '').trim(),
      posItemName: item?.name || '',
      posCategory: item?.category_name || '',
      quantity:    itemQty,
      unitPrice:   Number(item?.price || 0),
      lineTotal:   Number(item?.total || 0),
      lineDiscount:Number(item?.discount || 0),
    });
    for (const ad of item?.addon || []) {
      // addon quantity arrives as a string in the doc's samples
      const adQty = Math.max(0, Number(ad?.quantity ?? 1) || 0);
      lines.push({
        lineIndex:   idx++,
        kind:        'addon',
        posItemId:   String(ad?.addon_id ?? '').trim(),
        posItemName: ad?.name || '',
        posCategory: ad?.group_name || '',
        quantity:    itemQty * adQty,
        unitPrice:   Number(ad?.price || 0),
        lineTotal:   Number(ad?.price || 0) * itemQty * adQty,
        lineDiscount:0,
      });
    }
  }
  return lines.filter(l => l.posItemId);
}

// ── Full-bottle tolerance ────────────────────────────────────────────────────
// Scale readings and glass weights vary a little, so a reading within this many
// ML of the bottle size is an untouched full bottle (746 of 750 → 750).
// Applies to every bottle size.
const FULL_BOTTLE_TOLERANCE_ML = 10;
function snapFullBottle(ml, bottleSizeMl) {
  const size = Number(bottleSizeMl || 0);
  const v    = Math.max(0, Number(ml || 0));
  if (size > 0 && Math.abs(size - v) <= FULL_BOTTLE_TOLERANCE_ML) return size;
  return v;
}

// ── NC (non-chargeable) detection ────────────────────────────────────────────
// A bill is NC when the POS settles it as NC / complimentary. A single line is
// NC when it carries a price but was billed at zero (100% comped).
const NC_PATTERN = /(^|[^a-z])(nc|n\.c\.?|non[\s-]?charge(able)?|complimentary|comp)([^a-z]|$)/i;
function ncReasonForOrder(order = {}) {
  if (order.is_nc === true || order.is_nc === 1 || order.is_nc === '1') return 'NC bill';
  const fields = [order.payment_type, order.order_type, order.sub_order_type,
                  order.nc_reason, order.comment, order.settlement_type];
  for (const f of fields) if (f && NC_PATTERN.test(String(f))) return `NC bill (${String(f).trim()})`;
  return '';
}
function ncReasonForLine(line) {
  if (line.unitPrice > 0 && line.quantity > 0 && Number(line.lineTotal || 0) <= 0) return 'Item billed at zero';
  if (line.posItemName && /\(nc\)|\bnc\b/i.test(line.posItemName)) return 'NC item';
  return '';
}
// ML a POS line stands for
function saleMl(s) {
  if (s.servedMl !== undefined && s.servedMl !== null) return Number(s.servedMl) || 0;
  return Math.round(Number(s.quantity || 0) * Number(s.mlPerServe || 0));
}

// Copy a settlement's figures onto the count it belongs to
async function stampLogFromSettlement(st) {
  if (!st?.inventoryLogId) return;
  await InventoryLog.findByIdAndUpdate(st.inventoryLogId, {
    settlementId: st._id, posComparedAt: st.periodTo, posWindowFrom: st.periodFrom,
    posBills: st.posLines || 0, posSoldQty: st.posQty || 0,
    posSoldMl: st.posConsumedMl || 0, posSalesValue: st.posSalesValue || 0,
    ncQty: st.ncQty || 0, ncMl: st.ncMl || 0, varianceMl: st.varianceMl,
  }).catch(() => {});
}

// ── POS mirror helpers ───────────────────────────────────────────────────────
// The mirror only exists at bars, because that is where the POS sells from.
async function isBar(outletId, locationId) {
  const outlet = await Outlet.findById(outletId).catch(() => null);
  const bar = outlet?.bars?.find(b => String(b._id) === String(locationId));
  return bar && bar.type !== 'stockroom' ? bar : null;
}

async function getMirror(userId, outletId, locationId, productId) {
  return PosStock.findOneAndUpdate(
    { userId, outletId, locationId, productId },
    { $setOnInsert: { userId, outletId, locationId, productId, anchoredAt: new Date() } },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );
}

// Receipts have to land in both ledgers or the mirror drifts negative and the
// variance becomes meaningless. Consumption is the only thing that differs.
async function mirrorReceipt(userId, outletId, locationId, productId, bottles) {
  if (!bottles) return;
  if (!(await isBar(outletId, locationId))) return;      // stock room is not POS-facing
  const m = await getMirror(userId, outletId, locationId, productId);
  m.fullBottles += Number(bottles) || 0;
  await m.save();
}

// A POS sale drains the mirror. Negative is permitted and meaningful: it means
// stock arrived without being recorded, or an item is mapped to the wrong bar.
async function mirrorSale(userId, outletId, locationId, productId, ml, value, { isNc = false, qty = 0 } = {}) {
  const m = await getMirror(userId, outletId, locationId, productId);
  const p = await UserProduct.findById(productId).catch(() => null);
  const size = Math.max(1, Number(p?.bottleSizeMl || 750));

  // NC drinks leave the bottle too, so both kinds drain the mirror level
  const totalMl = m.fullBottles * size + m.openMl - Number(ml || 0);
  m.fullBottles = Math.floor(totalMl / size);
  m.openMl      = Math.round(totalMl - m.fullBottles * size);

  if (isNc) {
    m.ncMl  = (m.ncMl  || 0) + Number(ml || 0);
    m.ncQty = (m.ncQty || 0) + Number(qty || 0);
  } else {
    m.posConsumedMl += Number(ml || 0);
    m.posSalesValue += Number(value || 0);
    m.posQty         = (m.posQty || 0) + Number(qty || 0);
  }
  m.posLines      += Number(ml || 0) < 0 ? -1 : 1;   // a reversal takes its line back off
  if (Number(ml || 0) > 0) m.lastSaleAt = new Date();
  await m.save();
  return m;
}

// Re-anchor the mirror to a physical count and bank the variance for that period.
// Without this the mirror carries cumulative drift forever and no report is useful.
async function settleMirror({ userId, outletId, locationId, productId, actualFullBottles, actualOpenMl, physicalConsumedMl, reason = 'count', inventoryLogId }) {
  const bar = await isBar(outletId, locationId);
  if (!bar) return null;

  const m = await PosStock.findOne({ userId, outletId, locationId, productId });
  if (!m) return null;

  const p    = await UserProduct.findById(productId).catch(() => null);
  const size = Math.max(1, Number(p?.bottleSizeMl || 750));
  const outlet = await Outlet.findById(outletId).catch(() => null);

  const mirrorBeforeMl = m.fullBottles * size + m.openMl;
  const actualAfterMl  = Number(actualFullBottles || 0) * size + Number(actualOpenMl || 0);
  const posMl          = Number(m.posConsumedMl || 0);
  const ncMl           = Number(m.ncMl || 0);
  const physMl         = Number(physicalConsumedMl ?? 0);
  // NC was poured on purpose, so it is taken out of the variance
  const varianceMl     = Math.round(physMl - posMl - ncMl);
  const perMl          = Number(p?.cost || 0) / size;

  const settlement = await PosSettlement.create({
    userId, outletId, outletName: outlet?.name || '',
    locationId, locationName: bar.name,
    productId, productName: p?.name || '', bottleSizeMl: size,
    periodFrom: m.anchoredAt, periodTo: new Date(),
    posConsumedMl: posMl,
    posQty: m.posQty || 0,
    ncMl: Math.round(ncMl),
    ncQty: m.ncQty || 0,
    physicalConsumedMl: physMl,
    varianceMl,
    inventoryLogId: inventoryLogId || undefined,
    varianceValue: Math.round(varianceMl * perMl),
    posSalesValue: Math.round(m.posSalesValue || 0),
    posLines: m.posLines || 0,
    mirrorBeforeMl, actualAfterMl, reason,
  });

  // Reset the mirror to what was actually counted, and start a fresh period
  m.fullBottles    = Number(actualFullBottles || 0);
  m.openMl         = Math.round(Number(actualOpenMl || 0));
  m.posConsumedMl  = 0;
  m.posSalesValue  = 0;
  m.posLines       = 0;
  m.posQty         = 0;
  m.ncMl           = 0;
  m.ncQty          = 0;
  m.anchoredAt     = new Date();
  await m.save();

  await stampLogFromSettlement(settlement);
  return settlement;
}

// A bill cancelled after its period was already settled at a count. The mirror
// has since been re-anchored to the physical count, so it is left alone; the
// banked settlement (and its count) is corrected instead.
async function unwindSettledSale(sale, productId, locationId, outletId) {
  const st = await PosSettlement.findOne({
    userId: sale.userId, outletId, locationId: String(locationId), productId,
    periodFrom: { $lte: sale.createdAt }, periodTo: { $gte: sale.createdAt },
  }).sort({ periodTo: -1 });
  if (!st) return;
  const ml = saleMl(sale);
  if (sale.isNc) {
    st.ncMl  = Math.max(0, (st.ncMl  || 0) - ml);
    st.ncQty = Math.max(0, (st.ncQty || 0) - (sale.quantity || 0));
  } else {
    st.posConsumedMl = Math.max(0, (st.posConsumedMl || 0) - ml);
    st.posSalesValue = Math.round((st.posSalesValue || 0) - (sale.lineTotal || 0));
    st.posQty        = Math.max(0, (st.posQty || 0) - (sale.quantity || 0));
  }
  st.posLines   = Math.max(0, (st.posLines || 0) - 1);
  st.varianceMl = Math.round((st.physicalConsumedMl || 0) - (st.posConsumedMl || 0) - (st.ncMl || 0));
  const p = await UserProduct.findById(productId).catch(() => null);
  const size = Math.max(1, Number(p?.bottleSizeMl || st.bottleSizeMl || 750));
  st.varianceValue = Math.round(st.varianceMl * (Number(p?.cost || 0) / size));
  await st.save();
  await stampLogFromSettlement(st);
}

// ── Stock movement helpers ───────────────────────────────────────────────────
// ml > 0 deducts, ml < 0 puts stock back. Total millilitres are recomputed and
// split back into full bottles + open ml, which makes every move reversible.
async function moveBottleStock(userId, outletId, locationId, productId, ml) {
  const line = await Stock.findOne({ userId, outletId, locationId, productId });
  if (!line) return { ok: false, moved: 0, shortfall: Math.max(0, ml), reason: 'No stock for this product at the mapped bar' };

  const p    = await UserProduct.findById(productId).catch(() => null);
  const size = Math.max(1, Number(p?.bottleSizeMl || 750));

  const available = line.fullBottles * size + line.openMl;
  const wanted    = Number(ml);
  const moved     = wanted > 0 ? Math.min(wanted, available) : wanted;
  const shortfall = wanted > 0 ? Math.max(0, wanted - available) : 0;

  const remaining = Math.max(0, available - moved);
  line.fullBottles = Math.floor(remaining / size);
  line.openMl      = Math.round(remaining % size);
  await line.save();

  return { ok: true, moved, shortfall };
}

// Pre-batch: drain the bottles already sitting at that bar, oldest expiry first,
// so a cocktail sale never touches spirit bottle stock a second time.
async function movePrebatchStock(userId, outletId, locationId, recipeId, ml) {
  const filter = { userId, outletId, locationId, status: { $in: ['assigned','stockroom'] } };
  if (recipeId) filter.recipeId = recipeId;

  if (ml < 0) {
    const back = await PbBottle.findOne(filter).sort({ createdAt: -1 });
    if (!back) return { ok: false, moved: 0, shortfall: 0, reason: 'No pre-batch bottle to return to' };
    back.remainingMl = Math.min(back.filledMl, (back.remainingMl || 0) - ml);
    if (back.remainingMl > 0 && back.status === 'depleted') back.status = 'assigned';
    await back.save();
    return { ok: true, moved: ml, shortfall: 0, refId: back._id };
  }

  const bottles = await PbBottle.find({ ...filter, remainingMl: { $gt: 0 } })
    .sort({ expiresAt: 1, createdAt: 1 });
  if (!bottles.length) return { ok: false, moved: 0, shortfall: ml, reason: 'No pre-batch stock at the mapped bar' };

  let left = ml, moved = 0, refId = null;
  for (const b of bottles) {
    if (left <= 0) break;
    const take = Math.min(left, b.remainingMl || 0);
    if (take <= 0) continue;
    b.remainingMl = (b.remainingMl || 0) - take;
    if (b.remainingMl <= 0) b.status = 'depleted';
    await b.save();
    left -= take; moved += take;
    if (!refId) refId = b._id;
  }
  return { ok: moved > 0, moved, shortfall: Math.max(0, left), refId };
}

// Draft beer: pull from the live keg feeding that bar.
async function moveKegStock(userId, outletId, locationId, draftBeerId, ml) {
  const filter = {
    userId, outletId, status: 'active',
    $or: [{ locationId }, { 'assignments.barId': locationId }],
  };
  if (draftBeerId) filter.draftBeerId = draftBeerId;

  const kegs = await Keg.find(filter).sort({ connectedAt: 1 });
  if (!kegs.length) return { ok: false, moved: 0, shortfall: Math.max(0, ml), reason: 'No active keg at the mapped bar' };

  if (ml < 0) {
    const k = kegs[0];
    k.remainingMl     = Math.min(k.capacityMl, (k.remainingMl || 0) - ml);
    k.totalConsumedMl = Math.max(0, (k.totalConsumedMl || 0) + ml);
    await k.save();
    return { ok: true, moved: ml, shortfall: 0, refId: k._id };
  }

  let left = ml, moved = 0, refId = null;
  for (const k of kegs) {
    if (left <= 0) break;
    const take = Math.min(left, k.remainingMl || 0);
    if (take <= 0) continue;
    k.remainingMl     = (k.remainingMl || 0) - take;
    k.totalConsumedMl = (k.totalConsumedMl || 0) + take;
    k.totalSoldMl     = (k.totalSoldMl || 0) + take;
    await k.save();
    left -= take; moved += take;
    if (!refId) refId = k._id;
  }
  return { ok: moved > 0, moved, shortfall: Math.max(0, left), refId };
}

async function applyMappedMovement(cfg, mapping, ml) {
  const outletId   = cfg.siRooOutletId;
  const locationId = mapping.locationId;
  if (mapping.targetType === 'prebatch')
    return movePrebatchStock(cfg.userId, outletId, locationId, mapping.pbRecipeId, ml);
  if (mapping.targetType === 'keg')
    return moveKegStock(cfg.userId, outletId, locationId, mapping.kegBeerId, ml);
  return moveBottleStock(cfg.userId, outletId, locationId, mapping.bottleId, ml);
}

// ── Cancellation: put back everything this order took ────────────────────────
async function reversePosOrder(cfg, orderId) {
  // Every line of the bill — physically counted items are never "deducted", but
  // they did move the mirror, so they must be unwound too.
  const sales = await PosSale.find({ posConfigId: cfg._id, posOrderId: orderId, reversed: { $ne: true } });
  let returned = 0;
  for (const s of sales) {
    const mapping = await MenuMapping.findOne({ posConfigId: cfg._id, kind: s.kind, posItemId: s.posItemId });
    // Unwind the mirror by the ordered quantity, whether or not real stock moved
    const orderedMl = saleMl(s);
    const bottleId  = s.bottleId || mapping?.bottleId;
    const locId     = s.locationId || mapping?.locationId;
    if (s.mapped && s.targetType === 'bottle' && bottleId && locId && orderedMl > 0) {
      const m = await PosStock.findOne({ userId: cfg.userId, outletId: cfg.siRooOutletId, locationId: String(locId), productId: bottleId });
      if (m && s.createdAt && s.createdAt < m.anchoredAt) {
        // Already banked at a count — correct that settlement instead
        await unwindSettledSale(s, bottleId, locId, cfg.siRooOutletId).catch(() => {});
      } else {
        await mirrorSale(cfg.userId, cfg.siRooOutletId, locId, bottleId, -orderedMl, -(s.lineTotal || 0),
          { isNc: s.isNc, qty: -(s.quantity || 0) }).catch(() => {});
      }
    }
    if (s.deducted && mapping && s.totalMlDeducted > 0) {
      const r = await applyMappedMovement(cfg, mapping, -s.totalMlDeducted);
      if (r.ok) returned += s.totalMlDeducted;
    }
    s.reversed    = true;
    s.orderStatus = 'Cancelled';
    s.note        = 'Reversed — order cancelled on POS';
    await s.save();
  }
  return { reversedLines: sales.length, returnedMl: returned };
}

// ── Main webhook processor ───────────────────────────────────────────────────
async function processPetpoojaOrder(cfg, body) {
  const props  = body?.properties || {};
  const order  = props.Order || {};
  const orderId= String(order.orderID ?? order.customer_invoice_id ?? '').trim();
  if (!orderId) return { ok: false, message: 'Payload has no orderID' };

  const status = String(order.status || 'Success');
  const soldAt = petpoojaOrderDate(order);

  if (/cancel/i.test(status)) {
    const rev = await reversePosOrder(cfg, orderId);
    await PosConfig.findByIdAndUpdate(cfg._id, { lastEventAt: new Date(), lastOrderId: orderId });
    return { ok: true, cancelled: true, message: `Order ${orderId} cancelled — ${rev.reversedLines} line(s) reversed, ${rev.returnedMl} ML returned`, ...rev };
  }

  const lines = flattenOrderItems(props.OrderItem);
  const orderNc = ncReasonForOrder(order);
  let mappedCount = 0, mlDeducted = 0;

  for (const line of lines) {
    const key = { posConfigId: cfg._id, posOrderId: orderId, kind: line.kind, posItemId: line.posItemId, lineIndex: line.lineIndex };

    // Re-printing a bill pushes the same order again — never deduct or mirror
    // twice. Physically counted items are never "deducted", so a mapped line
    // that is already stored counts as handled.
    const existing = await PosSale.findOne(key);
    if (existing && !existing.reversed && (existing.deducted || existing.mapped || existing.mirroredAt)) continue;

    const mapping = await MenuMapping.findOne({ posConfigId: cfg._id, kind: line.kind, posItemId: line.posItemId, active: { $ne: false } });

    const base = {
      userId: cfg.userId, posConfigId: cfg._id, siRooOutletId: cfg.siRooOutletId,
      posOrderId: orderId, invoiceId: String(order.customer_invoice_id || ''),
      ...line,
      orderStatus: 'Success',
      orderType:   order.order_type   || '',
      paymentType: order.payment_type || '',
      orderFrom:   order.order_from   || '',
      subOrderType:order.sub_order_type || '',
      tableNo:     String(order.table_no || ''),
      biller:      order.biller || '',
      isNc:        Boolean(orderNc || ncReasonForLine(line)),
      ncReason:    orderNc || ncReasonForLine(line) || undefined,
      soldAt,
    };

    if (!mapping) {
      // No mapping yet — log the sale and drop the item into the mapping inbox.
      await PosSale.findOneAndUpdate(key, { ...base, mapped: false, totalMlDeducted: 0, deducted: false }, { upsert: true, new: true }).catch(() => {});
      await PosUnmapped.findOneAndUpdate(
        { posConfigId: cfg._id, kind: line.kind, posItemId: line.posItemId },
        {
          $set: { userId: cfg.userId, posItemName: line.posItemName, posCategory: line.posCategory, lastPrice: line.unitPrice, lastSeenAt: soldAt },
          $inc: { timesSeen: 1, qtySeen: line.quantity },
          $setOnInsert: { firstSeenAt: soldAt },
        },
        { upsert: true }
      ).catch(() => {});
      continue;
    }

    const wantMl = Math.round(line.quantity * Number(mapping.mlPerServe || 0));
    let moved = 0, shortfall = 0, refId = null, note = '';

    // The mirror always moves — that is the whole point of it.
    let mirroredAt;
    if (wantMl > 0 && mapping.targetType === 'bottle' && mapping.bottleId) {
      await mirrorSale(cfg.userId, cfg.siRooOutletId, mapping.locationId, mapping.bottleId, wantMl, line.lineTotal,
        { isNc: base.isNc, qty: line.quantity })
        .then(() => { mirroredAt = new Date(); })
        .catch(() => {});
    }

    // Real stock moves only for items nobody weighs. Touching a physically
    // counted item here would overwrite the measurement we exist to compare with.
    let allowRealDeduct = false;
    if (wantMl > 0 && cfg.autoDeduct) {
      if (mapping.targetType === 'bottle' && mapping.bottleId) {
        const prod = await UserProduct.findById(mapping.bottleId).catch(() => null);
        allowRealDeduct = prod?.trackingMode === 'pos';
        if (!allowRealDeduct) note = 'Physically counted item — POS recorded, real stock untouched';
      } else {
        // pre-batch and kegs are weighed too, so they stay on the physical ledger
        note = 'Physically counted item — POS recorded, real stock untouched';
      }
    } else if (!cfg.autoDeduct) {
      note = 'Auto-deduct off — recorded for comparison only';
    }

    if (allowRealDeduct) {
      const r = await applyMappedMovement(cfg, mapping, wantMl);
      moved     = Math.max(0, r.moved || 0);
      shortfall = r.shortfall || 0;
      refId     = r.refId || null;
      if (!r.ok) note = r.reason || 'Stock movement failed';
      else if (shortfall > 0) note = `Only ${moved} of ${wantMl} ML available at ${mapping.locationName || 'the mapped bar'}`;
    }

    mappedCount++; mlDeducted += moved;

    await PosSale.findOneAndUpdate(key, {
      ...base,
      mapped: true,
      targetType:   mapping.targetType,
      bottleId:     mapping.bottleId || null,
      targetRefId:  refId,
      locationId:   mapping.locationId,
      locationName: mapping.locationName,
      mlPerServe:   mapping.mlPerServe,
      servedMl:     wantMl,
      mirroredAt,
      totalMlDeducted: moved,
      deducted:     moved > 0,
      reversed:     false,
      shortfallMl:  shortfall,
      note,
    }, { upsert: true, new: true }).catch(() => {});
  }

  await PosConfig.findByIdAndUpdate(cfg._id, {
    lastEventAt: new Date(), lastOrderId: orderId, $inc: { ordersReceived: 1 },
  });

  if (mlDeducted > 0) {
    await addHistory(cfg.userId, 'POS_SALE', {
      outletId: cfg.siRooOutletId,
      productName: `POS order ${orderId}`,
      consumedMl: mlDeducted, totalSell: Number(order.total || 0),
      notes: `${cfg.label || cfg.posName} · ${order.order_from || 'POS'}`,
    });
  }

  return {
    ok: true,
    message: `Order ${orderId}: ${lines.length} line(s), ${mappedCount} mapped, ${mlDeducted} ML deducted`,
    linesTotal: lines.length, linesMapped: mappedCount, mlDeducted,
  };
}

// Nothing to schedule — webhooks are pushed to us. Kept so startup stays unchanged.
async function loadPosAdapters() {
  const n = await PosConfig.countDocuments({ active: true }).catch(() => 0);
  console.log(`[POS] ${n} active connection(s) — webhook mode, awaiting pushes on /api/pos/webhook/:configId`);
}

async function seedSpiritCategories() {
  const defaults = [
    { name: 'Whisky',  gramToMlRatio: 0.93, description: 'Scotch, Bourbon, Irish, Japanese' },
    { name: 'Vodka',   gramToMlRatio: 0.91, description: 'All vodka spirits' },
    { name: 'Rum',     gramToMlRatio: 0.94, description: 'White, dark, spiced rum' },
    { name: 'Gin',     gramToMlRatio: 0.92, description: 'London dry, contemporary gin' },
    { name: 'Tequila', gramToMlRatio: 0.93, description: 'Blanco, reposado, anejo' },
    { name: 'Cognac',  gramToMlRatio: 0.94, description: 'VS, VSOP, XO cognac' },
    { name: 'Beer',    gramToMlRatio: 1.00, description: 'Lager, ale, stout' },
    { name: 'Wine',    gramToMlRatio: 0.99, description: 'Red, white, rose wine' },
  ];
  for (const d of defaults) {
    await SpiritCategory.updateOne({ name: d.name }, { $setOnInsert: d }, { upsert: true }).catch(() => {});
  }
  console.log('Spirit categories seeded');
}

async function seedMasterBottles() {
  const seeds = [
    { name: 'Johnnie Walker Black Label', category: 'Whisky', bottleSizeMl: 750, barcode: '890100000001', emptyBottleWeightG: 650 },
    { name: 'Grey Goose Vodka', category: 'Vodka', bottleSizeMl: 1000, barcode: '890100000002', emptyBottleWeightG: 560 },
    { name: 'Jameson Irish Whisky', category: 'Whisky', bottleSizeMl: 750, barcode: '890100000003', emptyBottleWeightG: 610 },
    { name: 'Bombay Sapphire', category: 'Gin', bottleSizeMl: 750, barcode: '890100000004', emptyBottleWeightG: 520 },
    { name: "Jack Daniel's No.7", category: 'Whisky', bottleSizeMl: 750, barcode: '890100000005', emptyBottleWeightG: 620 },
    { name: 'Hennessy VS', category: 'Cognac', bottleSizeMl: 700, barcode: '890100000006', emptyBottleWeightG: 680 },
    { name: 'Absolut Vodka', category: 'Vodka', bottleSizeMl: 750, barcode: '890100000007', emptyBottleWeightG: 540 },
    { name: 'Bacardi Carta Blanca', category: 'Rum', bottleSizeMl: 750, barcode: '890100000008', emptyBottleWeightG: 420 },
    { name: 'Kingfisher Premium', category: 'Beer', bottleSizeMl: 650, barcode: '890100000009', emptyBottleWeightG: 260 },
  ];
  for (const s of seeds) {
    await MasterBottle.updateOne({ barcode: s.barcode }, { $setOnInsert: s }, { upsert: true }).catch(() => {});
  }
  console.log('Master bottles seeded');
}

// ─── Routes ─────────────────────────────────────────────────────────────────

app.get('/', (_, res) => res.json({ name: 'SIROO API', status: 'running' }));
app.get('/api/health', (_, res) => res.json({ ok: true, time: now() }));

// ── Spirit Categories ──────────────────────────────────────────────────────
app.get('/api/admin/categories', adminMiddleware, async (req, res) => {
  res.json(await SpiritCategory.find().sort({ name: 1 }));
});

app.get('/api/categories', async (req, res) => {
  res.json(await SpiritCategory.find().sort({ name: 1 }));
});

app.post('/api/admin/categories', adminMiddleware, async (req, res) => {
  try {
    const { name, gramToMlRatio, description } = req.body;
    if (!name || !gramToMlRatio) return res.status(400).json({ error: 'Name and gram:ml ratio are required' });
    const ratio = Number(gramToMlRatio);
    if (ratio <= 0 || ratio > 2) return res.status(400).json({ error: 'Ratio must be between 0.1 and 2.0' });
    const cat = await SpiritCategory.findOneAndUpdate(
      { name: exactCi(name) },
      { name, gramToMlRatio: ratio, description },
      { upsert: true, new: true }
    );
    res.json(cat);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/categories/:id', adminMiddleware, async (req, res) => {
  try {
    const { name, gramToMlRatio, description } = req.body;
    const cat = await SpiritCategory.findByIdAndUpdate(
      req.params.id,
      { name, gramToMlRatio: Number(gramToMlRatio), description },
      { new: true }
    );
    res.json(cat);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/categories/:id', adminMiddleware, async (req, res) => {
  await SpiritCategory.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
});

// ── Admin Auth ──────────────────────────────────────────────────────────────
app.post('/api/admin/login', adminLoginLimit, async (req, res) => {
  const { email, password } = req.body;
  if (typeof email !== 'string' || typeof password !== 'string' || !email || !password)
    return res.status(400).json({ error: 'Email and password required' });
  // Both checks always run, so the response time says nothing about which was wrong
  const emailOk = safeEqual(email.trim().toLowerCase(), ADMIN_EMAIL.toLowerCase());
  const passOk  = safeEqual(password, ADMIN_PASSWORD);
  if (!emailOk || !passOk) {
    console.warn(`[security] failed admin login from ${req.ip} at ${new Date().toISOString()}`);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  console.log(`[security] admin login from ${req.ip} at ${new Date().toISOString()}`);
  const token = signToken({ role: 'admin', email: ADMIN_EMAIL }, '12h');
  res.json({ token, admin: { email: ADMIN_EMAIL, name: 'SIROO Admin' } });
});

// ── User Auth ───────────────────────────────────────────────────────────────
app.post('/api/auth/login', loginLimitIp, loginLimitAccount, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (typeof email !== 'string' || typeof password !== 'string' || !email.trim() || !password)
      return res.status(400).json({ error: 'Email and password required' });
    if (password.length > 200) return res.status(400).json({ error: 'Invalid login or password' });
    const user = await User.findOne({ email: email.trim().toLowerCase() });

    // Not an owner — try sub-users, who sign in with a username rather than an email
    if (!user) {
      const sub = await SubUser.findOne({ username: exactCi(email) });
      if (!sub || !sub.passwordHash) return res.status(401).json({ error: 'Invalid login or password' });
      if (!(await bcrypt.compare(password, sub.passwordHash))) return res.status(401).json({ error: 'Invalid login or password' });
      if (sub.status !== 'Active') return res.status(403).json({ error: 'This account has been disabled by your manager.' });

      const owner = await User.findById(sub.userId);
      if (!owner) return res.status(401).json({ error: 'Parent account not found' });
      if (owner.status === 'Blocked') return res.status(403).json({ error: 'Account blocked. Contact SIROO support.' });
      if (new Date(owner.subscriptionEnds) < new Date()) {
        return res.status(403).json({ error: 'Subscription expired. Contact SIROO to renew.', subscriptionExpired: true });
      }

      sub.lastLoginAt = new Date(); sub.lastActive = 'Just now';
      await sub.save();

      const token = signToken({
        role: 'subuser',
        userId: owner._id.toString(),          // acts inside the owner's data
        subUserId: sub._id.toString(),
        sections: sub.sections || [],
        outletAccess: (sub.outletAccess || []).map(String),
        financialAccess: Boolean(sub.financialAccess),
        brandName: owner.brandName,
      });
      return res.json({
        token,
        user: {
          id: owner._id, brandName: owner.brandName, ownerName: sub.name,
          email: sub.email || sub.username, subscriptionEnds: owner.subscriptionEnds,
          isSubUser: true, designation: sub.designation,
          sections: sub.sections || [],
          outletAccess: (sub.outletAccess || []).map(String),
          financialAccess: Boolean(sub.financialAccess),
        },
      });
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ error: 'Invalid email or password' });
    if (user.status === 'Blocked') return res.status(403).json({ error: 'Account blocked. Contact SIROO support.' });
    if (new Date(user.subscriptionEnds) < new Date()) {
      return res.status(403).json({ error: 'Subscription expired. Contact SIROO to renew.', subscriptionExpired: true });
    }
    const token = signToken({ role: 'user', userId: user._id.toString(), brandName: user.brandName });
    res.json({
      token,
      user: {
        id: user._id, brandName: user.brandName, ownerName: user.ownerName, email: user.email,
        subscriptionEnds: user.subscriptionEnds,
        isSubUser: false, sections: SECTION_KEYS, outletAccess: [], financialAccess: true,
      }
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Admin: Users (CRUD) ─────────────────────────────────────────────────────
app.get('/api/admin/users', adminMiddleware, async (req, res) => {
  const users = await User.find().select('-passwordHash').sort({ createdAt: -1 });
  res.json(users);
});

app.post('/api/admin/users', adminMiddleware, async (req, res) => {
  try {
    const { brandName, ownerName, mobile, email, password, subscriptionEnds } = req.body;
    if (!brandName || !ownerName || !email || !password || !subscriptionEnds) {
      return res.status(400).json({ error: 'Brand, owner, email, password and subscription date are required' });
    }
    if (String(password).length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    const passwordHash = await bcrypt.hash(String(password), 12);
    const user = await User.create({ brandName, ownerName, mobile, email: String(email).trim().toLowerCase(), passwordHash, subscriptionEnds });
    res.json({ ...user.toObject(), passwordHash: undefined, password });
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: 'Email already exists' });
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/admin/users/:id', adminMiddleware, async (req, res) => {
  try {
    const { brandName, ownerName, mobile, email, password, subscriptionEnds, status } = req.body;
    const update = { brandName, ownerName, mobile, email, subscriptionEnds, status };
    if (password) {
      if (String(password).length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
      update.passwordHash = await bcrypt.hash(String(password), 12);
      update.tokensValidAfter = new Date();      // signs the owner out on every device
    }
    for (const k of Object.keys(update)) if (update[k] === undefined) delete update[k];
    const user = await User.findByIdAndUpdate(req.params.id, update, { new: true }).select('-passwordHash');
    res.json(user);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/users/:id/status', adminMiddleware, async (req, res) => {
  const user = await User.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true }).select('-passwordHash');
  res.json(user);
});

// ── Admin: Master Bottles ───────────────────────────────────────────────────
app.get('/api/master-bottles', async (req, res) => {
  const q = String(req.query.q || '').toLowerCase();
  const bottles = await MasterBottle.find(q ? { $or: [{ name: containsCi(q) }, { category: containsCi(q) }] } : {});
  res.json(bottles);
});

// Bottle photos are uploaded from the admin panel as a data URL
// (data:image/png;base64,...) and kept on the master bottle itself, so they
// survive redeploys without any file storage. Old http(s) links still work.
const MAX_IMAGE_CHARS = 1_400_000;   // ≈1 MB image; the admin panel shrinks photos first
function cleanBottleImage(v) {
  if (v === undefined) return undefined;
  if (v === null || v === '') return '';
  const s = String(v);
  if (/^https?:\/\//i.test(s)) return s;
  if (!/^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=]+$/i.test(s))
    throw Object.assign(new Error('Upload a PNG, JPG, WEBP or GIF image'), { status: 400 });
  if (s.length > MAX_IMAGE_CHARS)
    throw Object.assign(new Error('Image is too large — please use a photo under 1 MB'), { status: 400 });
  return s;
}

app.post('/api/admin/master-bottles/:id/image', adminMiddleware, async (req, res) => {
  try {
    const image = cleanBottleImage(req.body.image ?? req.body.dataUrl);
    const bottle = await MasterBottle.findByIdAndUpdate(req.params.id, { image }, { new: true });
    if (!bottle) return res.status(404).json({ error: 'Master bottle not found' });
    res.json(bottle);
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

app.post('/api/admin/master-bottles', adminMiddleware, async (req, res) => {
  try {
    const { name, category, bottleSizeMl, barcode } = req.body;
    let image;
    try { image = cleanBottleImage(req.body.image); }
    catch (err) { return res.status(400).json({ error: err.message }); }
    if (!name || !category || !bottleSizeMl || !barcode) {
      return res.status(400).json({ error: 'Name, category, bottle size and barcode are required' });
    }
    // Upsert: if barcode already exists update it, otherwise create new
    const bottle = await MasterBottle.findOneAndUpdate(
      { barcode },
      { name, category, bottleSizeMl: Number(bottleSizeMl), barcode, ...(image ? { image } : {}) },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    res.json(bottle);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/admin/master-bottles/:id', adminMiddleware, async (req, res) => {
  try {
    const update = { ...req.body };
    if ('image' in update) update.image = cleanBottleImage(update.image);
    const bottle = await MasterBottle.findByIdAndUpdate(req.params.id, update, { new: true });
    res.json(bottle);
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

app.delete('/api/admin/master-bottles/:id', adminMiddleware, async (req, res) => {
  const used = await UserProduct.exists({ masterBottleId: req.params.id });
  if (used) return res.status(400).json({ error: 'Cannot delete — bottle already in use by a client' });
  await MasterBottle.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
});

// ── Admin: Outlets & Bars ───────────────────────────────────────────────────
app.get('/api/admin/outlets', adminMiddleware, async (req, res) => {
  const outlets = await Outlet.find(req.query.userId ? { userId: req.query.userId } : {});
  res.json(outlets);
});

app.post('/api/admin/outlets', adminMiddleware, async (req, res) => {
  try {
    const { userId, outletName } = req.body;
    if (!userId || !outletName) return res.status(400).json({ error: 'userId and outletName required' });
    const outlet = await Outlet.create({
      userId,
      name: outletName,
      bars: [{ name: 'Stock Room', type: 'stockroom' }],
    });
    res.json(outlet);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/outlets/:id', adminMiddleware, async (req, res) => {
  const outlet = await Outlet.findByIdAndUpdate(req.params.id, { name: req.body.outletName }, { new: true });
  res.json(outlet);
});

app.post('/api/admin/outlets/:outletId/bars', adminMiddleware, async (req, res) => {
  const outlet = await Outlet.findById(req.params.outletId);
  if (!outlet) return res.status(404).json({ error: 'Outlet not found' });
  outlet.bars.push({ name: req.body.name, type: 'bar' });
  await outlet.save();
  res.json(outlet);
});

app.put('/api/admin/outlets/:outletId/bars/:barId', adminMiddleware, async (req, res) => {
  const outlet = await Outlet.findById(req.params.outletId);
  const bar = outlet?.bars.id(req.params.barId);
  if (!bar) return res.status(404).json({ error: 'Bar not found' });
  bar.name = req.body.name;
  await outlet.save();
  res.json(outlet);
});

// ── User: Outlets ───────────────────────────────────────────────────────────
// Outlets drive navigation everywhere, so this is not gated on a section — but a
// sub-user only ever receives the outlets assigned to them. Filtering here rather
// than in the browser means an unassigned outlet is never sent in the first place.
app.get('/api/outlets', authMiddleware, subscriptionCheck, async (req, res) => {
  const filter = { userId: req.auth.userId };
  const allowed = allowedOutlets(req);
  if (allowed) filter._id = { $in: allowed };
  res.json(await Outlet.find(filter));
});

// ── User: Products ──────────────────────────────────────────────────────────
app.get('/api/user-products', authMiddleware, subscriptionCheck, requireSection('products'), async (req, res) => {
  const q = String(req.query.q || '').toLowerCase();
  const category = req.query.category;
  let filter = { userId: req.auth.userId };
  if (q) filter.$or = [{ name: containsCi(q) }, { category: containsCi(q) }];
  if (category) filter.category = category;
  res.json(await UserProduct.find(filter));
});

app.post('/api/user-products', authMiddleware, subscriptionCheck, requireSection('products'), async (req, res) => {
  try {
    const { masterBottleId, cost, fullBottleWeightG, outletIds } = req.body;
    const master = await MasterBottle.findById(masterBottleId);
    if (!master) return res.status(400).json({ error: 'Select a valid admin bottle' });
    const costNum = Number(cost || 0);
    if (!costNum || costNum <= 0) return res.status(400).json({ error: 'Bottle price is compulsory' });
    const existing = await UserProduct.findOne({ userId: req.auth.userId, masterBottleId: master._id });
    if (existing) return res.status(409).json({ error: 'This bottle is already in your product list' });

    // Calculate emptyBottleWeightG from fullBottleWeightG using spirit category gram:ml ratio
    let emptyBottleWeightG = master.emptyBottleWeightG || 0;
    const fullWt = Number(fullBottleWeightG || 0);
    if (fullWt > 0) {
      // Look up category ratio
      const cat = await SpiritCategory.findOne({ name: exactCi(master.category) });
      const ratio = cat ? cat.gramToMlRatio : 1.0;
      const spiritWeightG = master.bottleSizeMl * ratio;
      emptyBottleWeightG  = Math.round(fullWt - spiritWeightG);
    }

    const product = await UserProduct.create({
      userId:            req.auth.userId,
      masterBottleId:    master._id,
      outletIds:         Array.isArray(outletIds) ? outletIds : [],
      name:              master.name,
      category:          master.category,
      bottleSizeMl:      master.bottleSizeMl,
      fullBottleWeightG: fullWt || null,
      emptyBottleWeightG,
      barcode:           master.barcode,
      cost:              costNum,
      active:            true,
    });
    await addHistory(req.auth.userId, 'ADD_USER_PRODUCT', { productName: product.name, cost: costNum });
    res.json(product);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/user-products/:id', authMiddleware, subscriptionCheck, requireSection('products'), async (req, res) => {
  try {
    const p = await UserProduct.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!p) return res.status(404).json({ error: 'Product not found' });

    const { cost, active, fullBottleWeightG, emptyBottleWeightG, bottleSizeMl, name, category } = req.body;

    if (cost !== undefined) {
      const c = Number(cost);
      if (!c || c <= 0) return res.status(400).json({ error: 'Bottle cost must be greater than zero' });
      p.cost = c;
    }
    if (active !== undefined)   p.active   = Boolean(active);
    if (name?.trim())           p.name     = name.trim();
    if (category?.trim())       p.category = category.trim();

    if (bottleSizeMl !== undefined && Number(bottleSizeMl) > 0) p.bottleSizeMl = Number(bottleSizeMl);

    // Full bottle weight drives the tare, unless the user overrides it explicitly
    if (fullBottleWeightG !== undefined && fullBottleWeightG !== '' && fullBottleWeightG !== null) {
      const fullWt = Number(fullBottleWeightG);
      if (!fullWt || fullWt <= 0) return res.status(400).json({ error: 'Full bottle weight must be greater than zero' });
      p.fullBottleWeightG = fullWt;
      if (emptyBottleWeightG === undefined || emptyBottleWeightG === '' || emptyBottleWeightG === null) {
        const cat   = await SpiritCategory.findOne({ name: exactCi(p.category) });
        const ratio = cat ? cat.gramToMlRatio : 1.0;
        const empty = Math.round(fullWt - p.bottleSizeMl * ratio);
        if (empty <= 0) return res.status(400).json({ error: 'Full bottle weight must be greater than the weight of its contents' });
        p.emptyBottleWeightG = empty;
      }
    }
    if (emptyBottleWeightG !== undefined && emptyBottleWeightG !== '' && emptyBottleWeightG !== null) {
      const empty = Number(emptyBottleWeightG);
      if (!empty || empty <= 0) return res.status(400).json({ error: 'Empty bottle weight must be greater than zero' });
      if (p.fullBottleWeightG && empty >= p.fullBottleWeightG)
        return res.status(400).json({ error: 'Empty bottle weight must be less than the full bottle weight' });
      p.emptyBottleWeightG = empty;
    }

    await p.save();
    await addHistory(req.auth.userId, 'EDIT_USER_PRODUCT', { productName: p.name, cost: p.cost });
    res.json(p);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/user-products/:id', authMiddleware, subscriptionCheck, requireSection('products'), async (req, res) => {
  const p = await UserProduct.findOne({ _id: req.params.id, userId: req.auth.userId });
  if (!p) return res.status(404).json({ error: 'Product not found' });
  const inStock = await Stock.findOne({ userId: req.auth.userId, productId: p._id, $or: [{ fullBottles: { $gt: 0 } }, { openMl: { $gt: 0 } }] });
  if (inStock) return res.status(400).json({ error: 'Cannot delete — stock exists. Remove stock first.' });
  await UserProduct.deleteOne({ _id: p._id });
  await addHistory(req.auth.userId, 'DELETE_USER_PRODUCT', { productName: p.name });
  res.json({ ok: true });
});

app.get('/api/user-products/by-barcode/:barcode', authMiddleware, subscriptionCheck, async (req, res) => {
  const p = await UserProduct.findOne({ userId: req.auth.userId, barcode: req.params.barcode });
  if (!p) return res.status(404).json({ error: 'Product not found' });
  res.json(p);
});

// ── Stock ───────────────────────────────────────────────────────────────────
app.get('/api/stock', authMiddleware, subscriptionCheck, requireSection('inventory','stockroom','barinventory'), guardOutlet, async (req, res) => {
  res.json(await enrichStock(req.auth.userId, req.query.outletId, req.query.locationId));
});

app.post('/api/stock/add', authMiddleware, subscriptionCheck, requireSection('addstock'), guardOutlet, async (req, res) => {
  try {
    const { outletId, locationId, productId, quantity, reason } = req.body;
    const outlet = await Outlet.findOne({ _id: outletId, userId: req.auth.userId });
    const loc = outlet?.bars.find(b => b._id?.toString() === locationId || b.id === locationId);
    if (!loc || loc.type !== 'stockroom') return res.status(400).json({ error: 'Stock can only be added to Stock Room' });
    const line = await getOrCreateStock(req.auth.userId, outletId, locationId, productId);
    line.fullBottles += Number(quantity || 0);
    await line.save();
    await mirrorReceipt(req.auth.userId, outletId, locationId, productId, Number(quantity || 0)).catch(() => {});
    const p = await UserProduct.findById(productId);
    await addHistory(req.auth.userId, 'ADD_STOCK', { outletId, locationId, productId: p?._id, productName: p?.name, qty: Number(quantity), outletName: outlet?.name, locationName: loc?.name, reason: reason || 'Add Stock' });
    res.json({ ok: true, stock: await enrichStock(req.auth.userId, outletId, locationId) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/stock/assign', authMiddleware, subscriptionCheck, requireSection('assign'), guardOutlet, async (req, res) => {
  try {
    const { outletId, fromStockRoomId, toBarId, productId, quantity } = req.body;
    if (!productId || Number(quantity) <= 0) return res.status(400).json({ error: 'Select bottle and valid quantity' });
    const srcLine = await getOrCreateStock(req.auth.userId, outletId, fromStockRoomId, productId);
    if (srcLine.fullBottles < Number(quantity)) return res.status(400).json({ error: 'Insufficient stock in Stock Room' });
    srcLine.fullBottles -= Number(quantity);
    await srcLine.save();
    const dstLine = await getOrCreateStock(req.auth.userId, outletId, toBarId, productId);
    dstLine.fullBottles += Number(quantity);
    await dstLine.save();
    await mirrorReceipt(req.auth.userId, outletId, toBarId, productId, Number(quantity || 0)).catch(() => {});
    const outlet = await Outlet.findById(outletId);
    const p = await UserProduct.findById(productId);
    await addHistory(req.auth.userId, 'ASSIGN', { outletId, fromLocationId: fromStockRoomId, toLocationId: toBarId, fromLocationName: locationName(outlet, fromStockRoomId), toLocationName: locationName(outlet, toBarId), productId: p?._id, productName: p?.name, quantity: Number(quantity), outletName: outlet?.name });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/stock/transfer', authMiddleware, subscriptionCheck, requireSection('transfers'), guardOutlet, async (req, res) => {
  try {
    const { outletId, fromLocationId, toLocationId, productId, quantity } = req.body;
    const outlet = await Outlet.findOne({ _id: outletId, userId: req.auth.userId });
    const from = outlet?.bars.find(b => b._id?.toString() === fromLocationId || b.id === fromLocationId);
    const to = outlet?.bars.find(b => b._id?.toString() === toLocationId || b.id === toLocationId);
    if (!from || !to) return res.status(400).json({ error: 'Invalid location' });
    if (fromLocationId === toLocationId) return res.status(400).json({ error: 'From and To cannot be same' });
    if (!productId || Number(quantity) <= 0) return res.status(400).json({ error: 'Select bottle and valid quantity' });
    if (from.type === 'stockroom' && to.type === 'bar') return res.status(400).json({ error: 'Use Assign Inventory for Stock Room → Bar' });
    const srcLine = await getOrCreateStock(req.auth.userId, outletId, fromLocationId, productId);
    if (srcLine.fullBottles < Number(quantity)) return res.status(400).json({ error: 'Insufficient stock in source location' });
    srcLine.fullBottles -= Number(quantity);
    await srcLine.save();
    const dstLine = await getOrCreateStock(req.auth.userId, outletId, toLocationId, productId);
    dstLine.fullBottles += Number(quantity);
    await dstLine.save();
    // a transfer moves the mirror too, so neither bar drifts
    await mirrorReceipt(req.auth.userId, outletId, toLocationId, productId, Number(quantity || 0)).catch(() => {});
    await mirrorReceipt(req.auth.userId, outletId, fromLocationId, productId, -Number(quantity || 0)).catch(() => {});
    const p = await UserProduct.findById(productId);
    await addHistory(req.auth.userId, 'TRANSFER', { outletId, fromLocationId, toLocationId, fromLocationName: from.name, toLocationName: to.name, productId: p?._id, productName: p?.name, quantity: Number(quantity), outletName: outlet?.name });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Manual inventory correction from the Stock Room / Bar table
app.post('/api/stock/adjust', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const { outletId, locationId, productId, fullBottles, openMl, reason } = req.body;
    if (!productId) return res.status(400).json({ error: 'Select a bottle' });

    const product = await UserProduct.findOne({ _id: productId, userId: req.auth.userId });
    if (!product) return res.status(400).json({ error: 'Product not found' });

    const outlet = await Outlet.findOne({ _id: outletId, userId: req.auth.userId });
    const loc = outlet?.bars?.find(b => b._id?.toString() === locationId || b.id === locationId);
    if (!loc) return res.status(400).json({ error: 'Invalid location' });

    const newFull = Math.round(Number(fullBottles ?? 0));
    const newOpen = Math.round(Number(openMl ?? 0));
    if (isNaN(newFull) || newFull < 0) return res.status(400).json({ error: 'Full bottles must be zero or more' });
    if (isNaN(newOpen) || newOpen < 0) return res.status(400).json({ error: 'Open ML must be zero or more' });
    if (newOpen > product.bottleSizeMl)
      return res.status(400).json({ error: `Open ML cannot exceed the bottle size of ${product.bottleSizeMl} ML` });

    const line = await getOrCreateStock(req.auth.userId, outletId, locationId, productId);
    const prevFull = line.fullBottles;
    const prevOpen = Math.round(line.openMl);
    if (prevFull === newFull && prevOpen === newOpen)
      return res.status(400).json({ error: 'No change — the values are the same as the current stock' });

    line.fullBottles = newFull;
    line.openMl      = newOpen;
    await line.save();

    // Recorded as an inventory log so it flows through to reports and audit
    const size    = Math.max(1, product.bottleSizeMl || 1);
    const deltaMl = (newOpen + newFull * size) - (prevOpen + prevFull * size);
    await InventoryLog.create({
      userId: req.auth.userId,
      outletId, outletName: outlet?.name || '',
      locationId, locationName: loc?.name || '',
      productId, productName: product.name,
      category: product.category,
      bottleSizeMl: product.bottleSizeMl,
      type: 'adjustment',
      openingFullBottles: prevFull, openingOpenMl: prevOpen,
      closingFullBottles: newFull,  closingOpenMl: newOpen,
      emptyBottles: 0,
      remainingMl:  newOpen,
      consumedMl:   deltaMl < 0 ? Math.abs(deltaMl) : 0,
      consumedBottles: Math.max(0, prevFull - newFull),
      totalSell: 0,
      note: reason || 'Manual stock correction',
      at: new Date(),
    });
    await addHistory(req.auth.userId, 'STOCK_ADJUST', {
      outletId, locationId, outletName: outlet?.name, locationName: loc?.name,
      productId: product._id, productName: product.name,
      quantity: newFull, qty: newFull, reason: reason || 'Manual stock correction',
    });

    res.json({ ok: true, stock: await enrichStock(req.auth.userId, outletId, locationId) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Inventory ───────────────────────────────────────────────────────────────
app.post('/api/inventory/closing', authMiddleware, subscriptionCheck, requireSection('inventory'), guardOutlet, async (req, res) => {
  try {
    const { outletId, locationId, productId, emptyBottles, type = 'closing',
            countMethod = 'empty', closingFullBottles: closingFullInput } = req.body;
    let { remainingMl } = req.body;
    const product = await UserProduct.findOne({ _id: productId, userId: req.auth.userId });
    if (!product) return res.status(400).json({ error: 'Product not found' });
    if (!['empty','full'].includes(countMethod)) return res.status(400).json({ error: 'Invalid count method' });
    const outlet = await Outlet.findById(outletId);
    const loc = outlet?.bars?.find(b => b._id?.toString() === locationId);
    const line = await getOrCreateStock(req.auth.userId, outletId, locationId, productId);
    const openingFullBottles = line.fullBottles;
    const openingOpenMl      = Math.round(line.openMl);

    if (countMethod === 'full') {
      const cf = Number(closingFullInput);
      if (closingFullInput === undefined || closingFullInput === null || closingFullInput === '' || isNaN(cf))
        return res.status(400).json({ error: 'Enter the remaining full bottle count' });
      if (cf < 0) return res.status(400).json({ error: 'Full bottle count cannot be negative' });
      if (cf > openingFullBottles)
        return res.status(400).json({ error: `Remaining full bottles (${cf}) cannot exceed the opening count of ${openingFullBottles}` });
    }
    // Within ±10 ML of the bottle size counts as a full bottle (746 of 750 → 750)
    remainingMl = snapFullBottle(remainingMl, product.bottleSizeMl);
    if (Number(remainingMl || 0) > product.bottleSizeMl)
      return res.status(400).json({ error: `Remaining ML cannot exceed the bottle size of ${product.bottleSizeMl} ML` });

    // Consumption calc — passes opening state and the selected count method
    const calc = calculateConsumption({
      openingFullBottles,
      openingOpenMl,
      emptyBottles,
      remainingMl,
      bottleSizeMl: product.bottleSizeMl,
      cost: product.cost,
      countMethod,
      closingFullBottles: closingFullInput,
    });

    const closingOpenMl = Math.max(0, Number(remainingMl || 0));
    line.fullBottles    = calc.closingFullBottles;
    line.openMl         = closingOpenMl;
    await line.save();

    const log = await InventoryLog.create({
      userId: req.auth.userId,
      outletId, outletName: outlet?.name || '',
      locationId, locationName: loc?.name || '',
      productId, productName: product.name,
      category: product.category,
      bottleSizeMl: product.bottleSizeMl,
      type,
      countMethod,
      openingFullBottles, openingOpenMl,
      // In full-count mode the emptied bottles are derived from the difference
      emptyBottles:     countMethod === 'full' ? calc.consumedBottles : Number(emptyBottles || 0),
      remainingMl:      Math.round(Number(remainingMl || 0)),
      closingFullBottles: calc.closingFullBottles,
      closingOpenMl,
      consumedMl:      calc.consumedMl,
      consumedBottles: calc.consumedBottles,
      totalSell:       calc.totalSell,
      at: new Date(),
    });
    // The count is the anchor: bank the variance for the period just ended and
    // reset the mirror to what was actually measured.
    // The settlement is linked to this count and its figures are copied onto it
    // (POS sold, NC, variance for bills since the previous count).
    const settlement = await settleMirror({
      userId: req.auth.userId, outletId, locationId, productId,
      actualFullBottles: calc.closingFullBottles,
      actualOpenMl: closingOpenMl,
      physicalConsumedMl: calc.consumedMl,
      reason: 'count',
      inventoryLogId: log._id,
    }).catch(err => { console.error('[POS] settle failed', err); return null; });

    await addHistory(req.auth.userId, 'INVENTORY_CLOSING', { outletId, outletName: outlet?.name, locationId, locationName: loc?.name, productId: product._id, productName: product.name, consumedMl: calc.consumedMl, totalSell: calc.totalSell });
    res.json(settlement ? await InventoryLog.findById(log._id) : log);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/inventory/no-inventory', authMiddleware, subscriptionCheck, async (req, res) => {
  await addHistory(req.auth.userId, 'NO_INVENTORY_TAKEN', req.body);
  res.json({ ok: true });
});

app.get('/api/inventory/recent', authMiddleware, subscriptionCheck, requireSection('inventory'), async (req, res) => {
  const logs = await InventoryLog.find({ userId: req.auth.userId }).sort({ at: -1 }).limit(25);
  res.json(logs);
});

// ── Reports & History ───────────────────────────────────────────────────────
// Current stock on hand for an outlet / location — powers the "Stock Check" report
app.get('/api/reports/stock-check', authMiddleware, subscriptionCheck, requireSection('reports'), guardOutlet, async (req, res) => {
  try {
    const { outletId, locationId, productId } = req.query;
    const filter = { userId: req.auth.userId };
    if (outletId)   filter.outletId   = outletId;
    if (locationId) filter.locationId = locationId;
    if (productId)  filter.productId  = productId;

    const lines   = await Stock.find(filter);
    const outlets = await Outlet.find({ userId: req.auth.userId });
    const outletById = new Map(outlets.map(o => [String(o._id), o]));

    const rows = [];
    let totalStockValue = 0, totalFullBottles = 0, totalOpenMl = 0;

    for (const line of lines) {
      const p = await UserProduct.findById(line.productId).catch(() => null);
      if (!p) continue;
      const outlet = outletById.get(String(line.outletId));
      const loc    = outlet?.bars?.find(b => String(b._id) === String(line.locationId));
      const size   = Number(p.bottleSizeMl || 0) || 1;
      const totalMl     = line.fullBottles * size + line.openMl;
      const stockValue  = Math.round(line.fullBottles * p.cost + (line.openMl / size) * p.cost);

      totalStockValue  += stockValue;
      totalFullBottles += line.fullBottles;
      totalOpenMl      += line.openMl;

      rows.push({
        _id: line._id,
        outletId: line.outletId,   outletName:   outlet?.name || '',
        locationId: line.locationId, locationName: loc?.name || '',
        locationType: loc?.type || '',
        productId: line.productId, productName: p.name,
        category: p.category, bottleSizeMl: p.bottleSizeMl, cost: p.cost,
        fullBottles: line.fullBottles,
        openMl: Math.round(line.openMl),
        totalMl: Math.round(totalMl),
        equivalentBottles: Math.round((totalMl / size) * 100) / 100,
        stockValue,
      });
    }

    rows.sort((a, b) =>
      (a.outletName || '').localeCompare(b.outletName || '') ||
      (a.locationName || '').localeCompare(b.locationName || '') ||
      (a.productName || '').localeCompare(b.productName || '')
    );

    res.json({
      rows,
      summary: {
        lines: rows.length,
        totalFullBottles,
        totalOpenMl: Math.round(totalOpenMl),
        totalStockValue,
        outOfStock: rows.filter(r => r.totalMl <= 0).length,
      },
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/reports', authMiddleware, subscriptionCheck, requireSection('reports'), guardOutlet, async (req, res) => {
  try {
    const { outletId, locationId, productId, type, dateFrom, dateTo } = req.query;
    const filter = { userId: req.auth.userId };
    if (outletId)   filter.outletId   = outletId;
    if (locationId) filter.locationId = locationId;
    if (productId)  filter.productId  = productId;
    if (type)       filter.type       = type;
    if (dateFrom || dateTo) {
      filter.at = {};
      if (dateFrom) filter.at.$gte = new Date(dateFrom);
      if (dateTo)   { const d = new Date(dateTo); d.setHours(23,59,59,999); filter.at.$lte = d; }
    }

    // Merge inventory logs + history rows (add stock, assign, transfer)
    const [invLogs, histRows] = await Promise.all([
      InventoryLog.find(filter).sort({ at: -1 }).limit(500),
      History.find({
        userId: req.auth.userId,
        action: { $in: ['ADD_STOCK','ASSIGN','TRANSFER'] },
        ...(outletId ? { outletId } : {}),
        ...(dateFrom || dateTo ? { at: filter.at } : {}),
      }).sort({ at: -1 }).limit(500),
    ]);

    // Enrich inv logs (fill product details if missing from old records)
    const productCache = new Map();
    async function productFor(id) {
      if (!id) return null;
      const key = String(id);
      if (productCache.has(key)) return productCache.get(key);
      const p = await UserProduct.findById(id).catch(() => null);
      productCache.set(key, p);
      return p;
    }

    const enriched = await Promise.all(invLogs.map(async (l) => {
      let row = l.toObject();
      const p = await productFor(l.productId);
      if (!row.category || !row.bottleSizeMl) {
        if (p) { row.category = p.category; row.bottleSizeMl = p.bottleSizeMl; }
      }
      // Cost per bottle — never stored on the log, always resolved from the product
      if (row.cost == null || row.cost === '') row.cost = p?.cost ?? '';
      if (!row.outletName) {
        const o = await Outlet.findById(l.outletId).catch(() => null);
        if (o) {
          row.outletName = o.name;
          row.locationName = o.bars?.find(b => b._id?.toString() === l.locationId)?.name || '';
        }
      }
      return row;
    }));

    // Build history rows into same shape
    const histEnriched = await Promise.all(histRows.map(async h => {
      const p = await productFor(h.productId);
      return {
        _id: h._id, at: h.at,
        outletId: h.outletId, locationId: h.locationId || h.fromLocationId,
        productId: h.productId,
        outletName: h.outletName || '', locationName: h.locationName || h.fromLocationName || '',
        productName: h.productName || p?.name || '',
        category: p?.category || '', bottleSizeMl: p?.bottleSizeMl || '',
        cost: h.cost ?? p?.cost ?? '',
        type: h.action, openingFullBottles: '', openingOpenMl: '',
        closingFullBottles: '', closingOpenMl: '',
        consumedMl: h.consumedMl || '', totalSell: h.totalSell || '',
        quantity: h.quantity || h.qty || '',
      };
    }));

    const allRows = [...enriched, ...histEnriched].sort((a,b) => new Date(b.at) - new Date(a.at));

    const totalConsumption = enriched.reduce((a,l) => a + (l.consumedMl || 0), 0);
    const totalSell        = enriched.reduce((a,l) => a + (l.totalSell  || 0), 0);

    const stockLines = await Stock.find({ userId: req.auth.userId });
    let stockValue = 0;
    for (const line of stockLines) {
      const p = await UserProduct.findById(line.productId).catch(()=>null);
      if (p) stockValue += line.fullBottles * p.cost + (line.openMl / p.bottleSizeMl) * p.cost;
    }

    res.json({ totalConsumption, totalSell, stockValue: Math.round(stockValue), rows: allRows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/history', authMiddleware, subscriptionCheck, requireSection('history'), async (req, res) => {
  const history = await History.find({ userId: req.auth.userId }).sort({ at: -1 }).limit(200);
  res.json(history);
});

// ── Sub-Users ───────────────────────────────────────────────────────────────
// ── Sub-Users ────────────────────────────────────────────────────────────────
// Owners manage their own staff. A sub-user can never reach these routes.
const ownerOnly = (req, res, next) =>
  isSub(req) ? res.status(403).json({ error: 'Only the account owner can manage sub-users' }) : next();

// The section catalogue the access step is built from
app.get('/api/sections', authMiddleware, (_, res) => res.json(SECTIONS));

// What the signed-in account is allowed to do — the client uses this to build the sidebar
app.get('/api/me/access', authMiddleware, subscriptionCheck, async (req, res) => {
  if (!isSub(req)) {
    return res.json({ isSubUser: false, sections: SECTION_KEYS, outletAccess: [], financialAccess: true, designation: null });
  }
  const sub = await SubUser.findById(req.auth.subUserId);
  if (!sub || sub.status !== 'Active') return res.status(403).json({ error: 'This account has been disabled.' });
  res.json({
    isSubUser: true, name: sub.name, designation: sub.designation,
    sections: sub.sections || [],
    outletAccess: (sub.outletAccess || []).map(String),
    financialAccess: Boolean(sub.financialAccess),
  });
});

app.get('/api/sub-users', authMiddleware, subscriptionCheck, ownerOnly, async (req, res) => {
  const subs = await SubUser.find({ userId: req.auth.userId }).select('-passwordHash').sort({ createdAt: -1 });
  res.json(subs);
});

// Creation, edit and delete now live on the admin side only.
app.post('/api/sub-users', authMiddleware, subscriptionCheck, (req, res) =>
  res.status(403).json({ error: 'Sub-users are set up by SIROO. Contact support to add a user.' }));
app.post('/api/sub-users/_disabled', authMiddleware, subscriptionCheck, ownerOnly, async (req, res) => {
  try {
    const { username, password, name, phone, email, designation,
            outletAccess = [], barAccess = [], sections = [], financialAccess } = req.body;

    if (!username || !String(username).trim()) return res.status(400).json({ error: 'Login ID is required' });
    if (!password || String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    if (!name || !String(name).trim())           return res.status(400).json({ error: 'Name is required' });

    const uname = String(username).trim();
    const clash = await SubUser.findOne({ username: exactCi(uname) });
    if (clash) return res.status(409).json({ error: `Login ID "${uname}" is already taken` });
    if (await User.findOne({ email: uname.toLowerCase() }))
      return res.status(409).json({ error: 'That login ID collides with an owner account' });

    // Only outlets the owner actually has
    const owned = await Outlet.find({ userId: req.auth.userId }).select('_id');
    const ownedIds = owned.map(o => String(o._id));
    const outlets = (outletAccess || []).map(String).filter(id => ownedIds.includes(id));

    const sub = await SubUser.create({
      userId: req.auth.userId,
      username: uname,
      passwordHash: await bcrypt.hash(String(password), 12),
      name: String(name).trim(), phone, email, designation,
      outletAccess: outlets, barAccess,
      sections: (sections || []).filter(s => SECTION_KEYS.includes(s)),
      financialAccess: Boolean(financialAccess),
      status: 'Active', lastActive: 'New',
    });
    const out = sub.toObject(); delete out.passwordHash;
    res.json(out);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/sub-users/:id', authMiddleware, subscriptionCheck, (req, res) =>
  res.status(403).json({ error: 'Sub-users are managed by SIROO. Contact support to make changes.' }));
app.put('/api/sub-users/_disabled/:id', authMiddleware, subscriptionCheck, ownerOnly, async (req, res) => {
  try {
    const sub = await SubUser.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!sub) return res.status(404).json({ error: 'Sub-user not found' });

    const { username, password, name, phone, email, designation,
            outletAccess, barAccess, sections, financialAccess, status } = req.body;

    if (username && String(username).trim() !== sub.username) {
      const uname = String(username).trim();
      const clash = await SubUser.findOne({ username: exactCi(uname), _id: { $ne: sub._id } });
      if (clash) return res.status(409).json({ error: `Login ID "${uname}" is already taken` });
      sub.username = uname;
    }
    if (password) {
      if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
      sub.passwordHash = await bcrypt.hash(String(password), 12);
      sub.tokensValidAfter = new Date();          // signs this staff member out everywhere
    }
    if (name !== undefined)        sub.name = name;
    if (phone !== undefined)       sub.phone = phone;
    if (email !== undefined)       sub.email = email;
    if (designation !== undefined) sub.designation = designation;
    if (barAccess !== undefined)   sub.barAccess = barAccess;
    if (status !== undefined)      sub.status = status;
    if (financialAccess !== undefined) sub.financialAccess = Boolean(financialAccess);
    if (sections !== undefined)    sub.sections = (sections || []).filter(s => SECTION_KEYS.includes(s));
    if (outletAccess !== undefined) {
      const owned = await Outlet.find({ userId: req.auth.userId }).select('_id');
      const ownedIds = owned.map(o => String(o._id));
      sub.outletAccess = (outletAccess || []).map(String).filter(id => ownedIds.includes(id));
    }
    await sub.save();
    const out = sub.toObject(); delete out.passwordHash;
    res.json(out);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/sub-users/:id', authMiddleware, subscriptionCheck, (req, res) =>
  res.status(403).json({ error: 'Sub-users are managed by SIROO. Contact support to remove a user.' }));

// ── Scale Bridge Proxy ──────────────────────────────────────────────────────
app.get('/api/scale/status', async (_, res) => {
  const url = process.env.SCALE_BRIDGE_URL || 'http://127.0.0.1:5055';
  try { const r = await fetch(`${url}/status`); res.json(await r.json()); }
  catch { res.json({ connected: false, bridge: false, message: 'Scale bridge not running' }); }
});

app.post('/api/scale/connect', async (_, res) => {
  const url = process.env.SCALE_BRIDGE_URL || 'http://127.0.0.1:5055';
  try { const r = await fetch(`${url}/connect`, { method: 'POST' }); res.json(await r.json()); }
  catch { res.json({ connected: false, bridge: false, message: 'Scale bridge not running' }); }
});

// Scale reading → remaining ML for a bottle. The bottle's empty weight and the
// spirit's gram:ML ratio stay on the server; the scale only supplies grams.
async function scaleToRemaining(userId, productId, data) {
  const product = productId
    ? await UserProduct.findOne({ _id: productId, userId }).catch(() => null)
    : null;
  let gramToMlRatio = 1.0;
  if (product?.category) {
    const cat = await SpiritCategory.findOne({ name: exactCi(product.category) }).catch(() => null);
    if (cat?.gramToMlRatio) gramToMlRatio = cat.gramToMlRatio;
  }
  const bottleSizeMl = product?.bottleSizeMl || 750;
  let remainingMl;
  if (data.weightG !== undefined && data.weightG !== null && data.weightG !== '') {
    const liquidWeightG = Math.max(0, Number(data.weightG) - (product?.emptyBottleWeightG || 0));
    remainingMl = Math.round(liquidWeightG / gramToMlRatio);
  } else {
    remainingMl = Number(data.remainingMl || 0);
  }
  remainingMl = Math.max(0, Math.min(bottleSizeMl, snapFullBottle(remainingMl, bottleSizeMl)));
  return { remainingMl, isFullBottle: remainingMl === bottleSizeMl, gramToMlRatio };
}

// The browser reads the scale itself (the bridge runs on the bar's PC, which a
// live server can't reach) and sends the weight here to be turned into ML.
app.post('/api/scale/convert', authMiddleware, subscriptionCheck, requireSection('scale','inventory'), async (req, res) => {
  try {
    const { productId, weightG, remainingMl } = req.body;
    if ((weightG === undefined || weightG === null || weightG === '') && remainingMl === undefined)
      return res.status(400).json({ error: 'No scale reading received' });
    if (weightG !== undefined && weightG !== null && weightG !== '' && !(Number(weightG) >= 0 && Number(weightG) < 100000))
      return res.status(400).json({ error: 'Scale reading looks wrong — place the bottle and read again' });
    res.json({ connected: true, ...(await scaleToRemaining(req.auth.userId, productId, { weightG, remainingMl })) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Local development only: the server asks a bridge on the same machine.
app.post('/api/scale/read', authMiddleware, requireSection('scale','inventory'), async (req, res) => {
  const url = process.env.SCALE_BRIDGE_URL || 'http://127.0.0.1:5055';
  const { productId, readAgain } = req.body;
  const product = await UserProduct.findOne({ _id: productId, userId: req.auth.userId }).catch(() => null);

  try {
    const r = await fetch(`${url}/read`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        bottleSizeMl:       product?.bottleSizeMl || 750,
        emptyBottleWeightG: product?.emptyBottleWeightG || 0,
        samples:            readAgain ? 1 : 2,
      }),
    });
    const data = await r.json();
    return res.json({ ...data, ...(await scaleToRemaining(req.auth.userId, productId, data)) });
  } catch {
    res.json({ connected: false, simulated: true, remainingMl: 0, message: 'Scale bridge not running. Please start the scale bridge and connect the device.' });
  }
});


// ══════════════════════════════════════════════════════════════════════════════
// PRE-BATCH MODULE ROUTES
// ══════════════════════════════════════════════════════════════════════════════

function generateBatchNo(recipeName) {
  const prefix = (recipeName||'BATCH').replace(/[^A-Z0-9]/gi,'').toUpperCase().slice(0,4);
  const ts     = Date.now().toString(36).toUpperCase();
  return `PB-${prefix}-${ts}`;
}

function calcAvgDensity(ingredients) {
  const totalMl     = ingredients.reduce((s,i) => s + Number(i.quantityMl||0), 0);
  if (!totalMl) return 1.00;
  const weightedSum = ingredients.reduce((s,i) => s + Number(i.quantityMl||0) * Number(i.density||1), 0);
  return Math.round((weightedSum / totalMl) * 10000) / 10000;
}

// ── Ingredients (non-alcoholic) ───────────────────────────────────────────────
app.get('/api/pb/ingredients', authMiddleware, subscriptionCheck, requireSection('prebatch'), async (req, res) => {
  const q = req.query.q;
  const filter = q ? { name: containsCi(q) } : {};
  res.json(await PbIngredient.find(filter).sort({ name: 1 }));
});

app.post('/api/pb/ingredients', authMiddleware, subscriptionCheck, requireSection('prebatch'), async (req, res) => {
  try {
    const { name, density, unit, description } = req.body;
    if (!name) return res.status(400).json({ error: 'Name is required' });
    const ing = await PbIngredient.findOneAndUpdate(
      { name: exactCi(name) },
      { name, density: Number(density||1.00), unit: unit||'ml', description, isCustom: false },
      { upsert: true, new: true }
    );
    res.json(ing);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/pb/ingredients/:id', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const ing = await PbIngredient.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(ing);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/pb/ingredients/:id', authMiddleware, subscriptionCheck, async (req, res) => {
  const used = await PbRecipe.exists({ 'ingredients.ingredientId': req.params.id });
  if (used) return res.status(400).json({ error: 'Ingredient is used in a recipe. Remove from recipes first.' });
  await PbIngredient.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
});

// ── Recipe Master ──────────────────────────────────────────────────────────────
app.get('/api/pb/recipes', authMiddleware, subscriptionCheck, requireSection('prebatch'), async (req, res) => {
  const { outletId } = req.query;
  const filter = { userId: req.auth.userId };
  if (outletId) filter.outletId = outletId;
  res.json(await PbRecipe.find(filter).sort({ name: 1 }));
});

app.post('/api/pb/recipes', authMiddleware, subscriptionCheck, requireSection('prebatch'), async (req, res) => {
  try {
    const { outletId, name, description, yieldMl, shelfLifeDays, ingredients } = req.body;
    if (!outletId || !name || !yieldMl || !ingredients?.length)
      return res.status(400).json({ error: 'Outlet, name, yield and at least one ingredient are required' });
    const avgDensity = calcAvgDensity(ingredients);
    const recipe = await PbRecipe.create({ userId: req.auth.userId, outletId, name, description, yieldMl: Number(yieldMl), shelfLifeDays: Number(shelfLifeDays||7), ingredients, avgDensity });
    res.json(recipe);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/pb/recipes/:id', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    if (req.body.ingredients) req.body.avgDensity = calcAvgDensity(req.body.ingredients);
    const recipe = await PbRecipe.findOneAndUpdate({ _id: req.params.id, userId: req.auth.userId }, req.body, { new: true });
    res.json(recipe);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/pb/recipes/:id', authMiddleware, subscriptionCheck, async (req, res) => {
  const hasBatches = await PbBatch.exists({ recipeId: req.params.id, status: 'active' });
  if (hasBatches) return res.status(400).json({ error: 'Recipe has active batches. Cannot delete.' });
  await PbRecipe.findOneAndDelete({ _id: req.params.id, userId: req.auth.userId });
  res.json({ ok: true });
});

// ── Produce Batch ──────────────────────────────────────────────────────────────
app.post('/api/pb/produce', authMiddleware, subscriptionCheck, requireSection('prebatch'), async (req, res) => {
  try {
    const { recipeId, outletId, locationId, multiplier = 1, notes } = req.body;
    const recipe = await PbRecipe.findOne({ _id: recipeId, userId: req.auth.userId });
    if (!recipe) return res.status(400).json({ error: 'Recipe not found' });
    const mult = Number(multiplier) || 1;

    for (const ing of recipe.ingredients) {
      if (ing.type !== 'spirit' || !ing.productId) continue;
      const qtyMl  = Number(ing.quantityMl) * mult;
      const line   = await Stock.findOne({ userId: req.auth.userId, outletId, locationId, productId: ing.productId });
      if (!line) return res.status(400).json({ error: `No stock found for ${ing.name} in this location` });
      const product    = await UserProduct.findById(ing.productId);
      const bottleSize = product?.bottleSizeMl || 750;
      const availableMl = line.fullBottles * bottleSize + line.openMl;
      if (availableMl < qtyMl) return res.status(400).json({ error: `Insufficient stock: ${ing.name} needs ${qtyMl}ml, only ${Math.round(availableMl)}ml available` });
      if (line.openMl >= qtyMl) {
        line.openMl -= qtyMl;
      } else {
        let remaining    = qtyMl - line.openMl;
        line.openMl      = 0;
        const bottlesNeeded = Math.ceil(remaining / bottleSize);
        line.fullBottles = Math.max(0, line.fullBottles - bottlesNeeded);
        line.openMl      = Math.max(0, bottlesNeeded * bottleSize - remaining);
      }
      await line.save();
      await addHistory(req.auth.userId, 'PREBATCH_DEDUCT', { outletId, locationId, productId: ing.productId, productName: ing.name, qty: qtyMl });
    }

    const yieldMl    = recipe.yieldMl * mult;
    const avgDensity = recipe.avgDensity || calcAvgDensity(recipe.ingredients);
    const expiresAt  = new Date(Date.now() + (recipe.shelfLifeDays || 7) * 86400000);
    const batchNo    = generateBatchNo(recipe.name);

    const batch = await PbBatch.create({
      userId: req.auth.userId, outletId, locationId,
      recipeId: recipe._id, recipeName: recipe.name,
      batchNo, yieldMl, avgDensity, remainingMl: yieldMl,
      producedAt: new Date(), expiresAt, status: 'active', notes,
    });

    await addHistory(req.auth.userId, 'PREBATCH_PRODUCE', { outletId, productName: recipe.name, qty: yieldMl });
    res.json(batch);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Tare weight ────────────────────────────────────────────────────────────────
app.post('/api/pb/batches/:id/tare', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const batch     = await PbBatch.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!batch) return res.status(404).json({ error: 'Batch not found' });
    const filledWt  = Number(req.body.filledWeightG);
    const tareWt    = Math.round((filledWt - batch.yieldMl * batch.avgDensity) * 10) / 10;
    batch.filledWeightG = filledWt;
    batch.tareWeightG   = tareWt;
    await batch.save();
    res.json({ ...batch.toObject(), calculatedTareWeightG: tareWt });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Weigh (daily inventory) ────────────────────────────────────────────────────
app.post('/api/pb/batches/:id/weigh', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const batch = await PbBatch.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!batch) return res.status(404).json({ error: 'Batch not found' });
    if (batch.tareWeightG == null) return res.status(400).json({ error: 'Tare weight not set yet.' });
    const liquidWt    = Math.max(0, Number(req.body.grossWeightG) - batch.tareWeightG);
    const remainingMl = Math.round(liquidWt / batch.avgDensity);
    batch.remainingMl = Math.min(remainingMl, batch.yieldMl);
    if (batch.remainingMl <= 0) batch.status = 'depleted';
    await batch.save();
    res.json({ remainingMl: batch.remainingMl, status: batch.status });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Batch inventory & history ──────────────────────────────────────────────────
app.get('/api/pb/batches/history', authMiddleware, subscriptionCheck, async (req, res) => {
  const filter = { userId: req.auth.userId };
  if (req.query.outletId) filter.outletId = req.query.outletId;
  res.json(await PbBatch.find(filter).sort({ producedAt: -1 }).limit(200));
});

app.get('/api/pb/batches', authMiddleware, subscriptionCheck, async (req, res) => {
  const filter = { userId: req.auth.userId, status: { $in: ['active'] } };
  if (req.query.outletId) filter.outletId = req.query.outletId;
  await PbBatch.updateMany({ userId: req.auth.userId, status: 'active', expiresAt: { $lt: new Date() } }, { status: 'expired' });
  res.json(await PbBatch.find(filter).sort({ producedAt: -1 }));
});

// ── Wastage ────────────────────────────────────────────────────────────────────
app.post('/api/pb/wastage', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const { batchId, wasteMl, reason } = req.body;
    const batch = await PbBatch.findOne({ _id: batchId, userId: req.auth.userId });
    if (!batch) return res.status(404).json({ error: 'Batch not found' });
    batch.remainingMl = Math.max(0, batch.remainingMl - Number(wasteMl||0));
    if (batch.remainingMl <= 0 || reason?.toLowerCase().includes('discard')) { batch.status = 'wasted'; batch.remainingMl = 0; }
    await batch.save();
    const w = await PbWastage.create({ userId: req.auth.userId, outletId: batch.outletId, batchId: batch._id, batchNo: batch.batchNo, recipeName: batch.recipeName, wasteMl: Number(wasteMl||0), reason });
    res.json(w);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/pb/wastage', authMiddleware, subscriptionCheck, async (req, res) => {
  const filter = { userId: req.auth.userId };
  if (req.query.outletId) filter.outletId = req.query.outletId;
  res.json(await PbWastage.find(filter).sort({ at: -1 }).limit(200));
});

// ── Seed non-alcoholic ingredients ────────────────────────────────────────────
async function seedPbIngredients() {
  const defaults = [
    { name:'Sugar Syrup', density:1.33 },{ name:'Simple Syrup', density:1.28 },
    { name:'Honey Syrup', density:1.40 },{ name:'Lime Juice', density:1.02 },
    { name:'Lemon Juice', density:1.02 },{ name:'Orange Juice', density:1.04 },
    { name:'Pineapple Juice', density:1.05 },{ name:'Cranberry Juice', density:1.06 },
    { name:'Coconut Cream', density:1.06 },{ name:'Grenadine', density:1.18 },
    { name:'Blue Curacao', density:1.10 },{ name:'Triple Sec', density:1.04 },
    { name:'Ginger Syrup', density:1.30 },{ name:'Rose Syrup', density:1.30 },
    { name:'Orgeat', density:1.25 },{ name:'Falernum', density:1.15 },
    { name:'Bitters (Aromatic)', density:0.98 },{ name:'Soda Water', density:1.00 },
    { name:'Water', density:1.00 },{ name:'Egg White', density:1.03 },
  ];
  for (const d of defaults) {
    await PbIngredient.updateOne({ name: d.name }, { $setOnInsert: { ...d, unit:'ml', isCustom:false } }, { upsert:true }).catch(()=>{});
  }
  console.log('Pre-batch ingredients seeded');
}


// ── Pre-Batch Bottle Routes ───────────────────────────────────────────────────

// Create bottles from a batch (called after produce)
app.post('/api/pb/batches/:id/bottles', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const batch = await PbBatch.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!batch) return res.status(404).json({ error: 'Batch not found' });

    const { bottles } = req.body; // array of { capacityMl, filledMl, grossWeightG, tag? }
    if (!bottles?.length) return res.status(400).json({ error: 'At least one bottle required' });

    const created = [];
    let tagCounter = 1;

    for (const b of bottles) {
      const filledMl    = Number(b.filledMl || b.capacityMl);
      const grossWt     = Number(b.grossWeightG);
      const avgDensity  = batch.avgDensity || 1.0;
      // Silent tare calculation — never shown to user
      const liquidWt    = filledMl * avgDensity;
      const tareWeightG = Math.round((grossWt - liquidWt) * 10) / 10;
      // Auto-generate tag: e.g. MOJI-001
      const prefix = (batch.recipeName||'BATCH').replace(/[^A-Z0-9]/gi,'').toUpperCase().slice(0,4);
      const tag    = b.tag || `${prefix}-${String(tagCounter).padStart(3,'0')}`;
      tagCounter++;

      const bottle = await PbBottle.create({
        userId:      req.auth.userId,
        batchId:     batch._id,
        batchNo:     batch.batchNo,
        recipeName:  batch.recipeName,
        outletId:    batch.outletId,
        locationId:  batch.locationId,
        tag,
        capacityMl:  Number(b.capacityMl),
        filledMl,
        grossWeightG: grossWt,
        tareWeightG,
        avgDensity,
        remainingMl: filledMl,
        status:      'stockroom',
      });
      created.push(bottle);
    }

    // Update batch remaining after bottling
    const totalBottled = created.reduce((s,b) => s + b.filledMl, 0);
    batch.remainingMl  = Math.max(0, (batch.remainingMl||batch.yieldMl) - totalBottled);
    if (batch.remainingMl <= 0) batch.status = 'depleted';
    await batch.save();

    res.json({ bottles: created, batch });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Get bottles (for stock room or bar)
app.get('/api/pb/bottles', authMiddleware, subscriptionCheck, requireSection('prebatch'), async (req, res) => {
  const { outletId, locationId, status } = req.query;
  const filter = { userId: req.auth.userId };
  if (outletId)   filter.outletId   = outletId;
  if (locationId) filter.locationId = locationId;
  if (status)     filter.status     = status;
  else            filter.status     = { $in: ['stockroom','assigned'] };
  res.json(await PbBottle.find(filter).sort({ createdAt: -1 }));
});

// Assign bottle from stock room to bar
app.post('/api/pb/bottles/:id/assign', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const { toBarId, toBarName } = req.body;
    const bottle = await PbBottle.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!bottle) return res.status(404).json({ error: 'Bottle not found' });
    if (bottle.status !== 'stockroom') return res.status(400).json({ error: 'Bottle is not in stock room' });

    bottle.locationId   = toBarId;
    bottle.locationName = toBarName;
    bottle.status       = 'assigned';
    bottle.assignedTo   = toBarName;
    bottle.assignedAt   = new Date();
    await bottle.save();

    await addHistory(req.auth.userId, 'PREBATCH_ASSIGN', {
      outletId: bottle.outletId, productName: bottle.recipeName,
      toLocationName: toBarName, notes: `Bottle ${bottle.tag}`,
    });

    res.json(bottle);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Count a pre-batch bottle (scale weight or typed ML) and compare with the POS.
// POS side = bills for this recipe at this bar since the previous count of the
// recipe there. With several open bottles of one recipe, weigh them together:
// the per-bottle split can look uneven, the recipe total is what is accurate.
async function countPbBottle(userId, bottle, { grossWeightG, remainingMl: typedMl }) {
  let remainingMl;
  if (typedMl !== undefined && typedMl !== null && typedMl !== '') remainingMl = Math.round(Number(typedMl));
  else {
    const liquidWt = Math.max(0, Number(grossWeightG) - (bottle.tareWeightG || 0));
    remainingMl = Math.round(liquidWt / (bottle.avgDensity || 1.0));
  }
  remainingMl = Math.max(0, Math.min(snapFullBottle(remainingMl, bottle.filledMl), bottle.filledMl || remainingMl));

  const openingMl  = Number(bottle.remainingMl ?? bottle.filledMl ?? 0);
  const consumedMl = Math.max(0, openingMl - remainingMl);
  bottle.remainingMl = remainingMl;
  if (bottle.remainingMl <= 0) bottle.status = 'depleted';
  await bottle.save();

  const batch    = await PbBatch.findById(bottle.batchId).catch(() => null);
  const recipeId = batch?.recipeId || null;

  // POS window — only for bottles sitting at a bar with a mapping for the recipe
  let pos = { posConnected: false, soldMl: 0, soldQty: 0, salesValue: 0, ncMl: 0, ncQty: 0, lines: 0 }, since = null, sales = [];
  if (recipeId && bottle.status !== 'stockroom' && bottle.locationId) {
    const cfgs = await PosConfig.find({ userId, siRooOutletId: bottle.outletId, active: true }).select('_id');
    const mappings = cfgs.length ? await MenuMapping.find({
      posConfigId: { $in: cfgs.map(c => c._id) }, targetType: 'prebatch',
      pbRecipeId: recipeId, locationId: String(bottle.locationId), active: { $ne: false },
    }) : [];
    if (mappings.length) {
      const prev = await PbCountLog.findOne({ userId, recipeId, locationId: String(bottle.locationId) }).sort({ at: -1 });
      since = prev?.at || bottle.assignedAt || bottle.createdAt;
      sales = await PosSale.find({
        userId, reversed: { $ne: true }, pbCountId: null,
        $or: mappings.map(m => ({ posConfigId: m.posConfigId, kind: m.kind, posItemId: m.posItemId })),
        locationId: String(bottle.locationId),
        createdAt: { $gt: since, $lte: new Date() },
      });
      pos = { posConnected: true, ...sumPosLines(sales) };
    }
  }

  const log = await PbCountLog.create({
    userId, outletId: bottle.outletId, locationId: bottle.locationId, locationName: bottle.locationName,
    bottleId: bottle._id, tag: bottle.tag, batchId: bottle.batchId, batchNo: bottle.batchNo,
    recipeId, recipeName: bottle.recipeName,
    openingMl, remainingMl, consumedMl,
    posConnected: pos.posConnected, posWindowFrom: since || undefined,
    posLines: pos.lines, posSoldQty: pos.soldQty, posSoldMl: pos.soldMl, posSalesValue: pos.salesValue,
    ncQty: pos.ncQty, ncMl: pos.ncMl,
    varianceMl: pos.posConnected ? Math.round(consumedMl - pos.soldMl - pos.ncMl) : undefined,
  });
  if (sales.length) await PosSale.updateMany({ _id: { $in: sales.map(x => x._id) } }, { $set: { pbCountId: log._id } });
  return log;
}

function pbCountResult(bottle, log) {
  // Only remaining ML and the comparison — no weights or density to frontend
  return {
    remainingMl: bottle.remainingMl, status: bottle.status, tag: bottle.tag,
    batchNo: bottle.batchNo, recipeName: bottle.recipeName,
    openingMl: log.openingMl, consumedMl: log.consumedMl,
    posConnected: log.posConnected, posWindowFrom: log.posWindowFrom,
    posLines: log.posLines, posSoldQty: log.posSoldQty, posSoldMl: log.posSoldMl,
    ncQty: log.ncQty, ncMl: log.ncMl, varianceMl: log.varianceMl,
  };
}

// Weigh bottle — update remaining ML (calculation hidden from user)
app.post('/api/pb/bottles/:id/weigh', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const bottle = await PbBottle.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!bottle) return res.status(404).json({ error: 'Bottle not found' });
    const log = await countPbBottle(req.auth.userId, bottle, { grossWeightG: req.body.grossWeightG, remainingMl: req.body.remainingMl });
    res.json(pbCountResult(bottle, log));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Pre-batch bottles at a location, for the Inventory screen (search by batch
// number or bottle tag). Open to inventory users, not only pre-batch managers.
app.get('/api/inventory/pb-bottles', authMiddleware, subscriptionCheck, requireSection('inventory','prebatch'), guardOutlet, async (req, res) => {
  try {
    const { outletId, locationId, q } = req.query;
    if (!outletId || !locationId) return res.json([]);
    const filter = { userId: req.auth.userId, outletId, locationId: String(locationId), status: { $in: ['stockroom','assigned'] } };
    const term = String(q || '').trim();
    if (term) {
      const rx = new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      filter.$or = [{ batchNo: rx }, { tag: rx }, { recipeName: rx }];
    }
    const rows = await PbBottle.find(filter).sort({ batchNo: 1, tag: 1 }).limit(30);
    res.json(rows.map(b => ({
      _id: b._id, tag: b.tag, batchNo: b.batchNo, recipeName: b.recipeName,
      capacityMl: b.capacityMl, filledMl: b.filledMl, remainingMl: b.remainingMl,
      status: b.status, locationName: b.locationName,
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Count a pre-batch bottle from the Inventory screen
app.post('/api/inventory/pb-bottles/:id/count', authMiddleware, subscriptionCheck, requireSection('inventory','prebatch'), async (req, res) => {
  try {
    const bottle = await PbBottle.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!bottle) return res.status(404).json({ error: 'Bottle not found' });
    if (!canUseOutlet(req, bottle.outletId)) return res.status(403).json({ error: 'You do not have access to this outlet' });
    const { grossWeightG, remainingMl } = req.body;
    if ((grossWeightG === undefined || grossWeightG === '' || grossWeightG === null) &&
        (remainingMl === undefined || remainingMl === '' || remainingMl === null))
      return res.status(400).json({ error: 'Read the scale or type the remaining ML' });
    if (remainingMl !== undefined && remainingMl !== '' && Number(remainingMl) > Number(bottle.filledMl || 0) + FULL_BOTTLE_TOLERANCE_ML)
      return res.status(400).json({ error: `Remaining ML cannot exceed the ${bottle.filledMl} ML poured into this bottle` });
    const log = await countPbBottle(req.auth.userId, bottle, { grossWeightG, remainingMl });
    await addHistory(req.auth.userId, 'PREBATCH_COUNT', {
      outletId: bottle.outletId, locationId: bottle.locationId, locationName: bottle.locationName,
      productName: `${bottle.recipeName} (${bottle.tag})`, consumedMl: log.consumedMl, quantity: bottle.remainingMl,
      notes: `Batch ${bottle.batchNo}`,
    }).catch(() => {});
    res.json(pbCountResult(bottle, log));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Wastage for a bottle
app.post('/api/pb/bottles/:id/wastage', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const { wasteMl, reason } = req.body;
    const bottle = await PbBottle.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!bottle) return res.status(404).json({ error: 'Bottle not found' });
    bottle.remainingMl = Math.max(0, bottle.remainingMl - Number(wasteMl||0));
    if (bottle.remainingMl <= 0 || reason?.toLowerCase().includes('discard')) {
      bottle.status      = 'wasted';
      bottle.remainingMl = 0;
    }
    await bottle.save();
    await PbWastage.create({
      userId: req.auth.userId, outletId: bottle.outletId,
      batchId: bottle.batchId, batchNo: bottle.batchNo,
      recipeName: bottle.recipeName, wasteMl: Number(wasteMl||0), reason,
    });
    res.json(bottle);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Pre-batch report data
app.get('/api/pb/report', authMiddleware, subscriptionCheck, requireSection('prebatch','reports'), async (req, res) => {
  try {
    const { outletId, from, to } = req.query;
    const filter = { userId: req.auth.userId };
    if (outletId) filter.outletId = outletId;
    if (from||to) { filter.producedAt = {}; if(from) filter.producedAt.$gte=new Date(from); if(to){const d=new Date(to);d.setHours(23,59,59,999);filter.producedAt.$lte=d;} }

    const [batches, bottles, wastage] = await Promise.all([
      PbBatch.find(filter).sort({ producedAt: -1 }),
      PbBottle.find({ userId: req.auth.userId, ...(outletId?{outletId}:{}) }).sort({ createdAt: -1 }),
      PbWastage.find({ userId: req.auth.userId, ...(outletId?{outletId}:{}) }).sort({ at: -1 }),
    ]);

    const totalProduced  = batches.reduce((s,b) => s + (b.yieldMl||0), 0);
    const totalWasted    = wastage.reduce((s,w) => s + (w.wasteMl||0), 0);
    const activeBottles  = bottles.filter(b => b.status==='assigned'||b.status==='stockroom');
    const totalRemaining = activeBottles.reduce((s,b) => s + (b.remainingMl||0), 0);

    res.json({ batches, bottles, wastage, summary: { totalProduced, totalWasted, totalRemaining, activeBatches: batches.filter(b=>b.status==='active').length } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// ── Draft Beer Keg Routes ─────────────────────────────────────────────────────

const WASTAGE_REASONS = ['Spillage', 'Foam', 'Cleaning', 'Line Flush', 'Other'];

// Tare is derived, never entered: tare = full weight − (capacity × 1.01)
function calcTareWeight(fullWeightG, capacityMl, density = BEER_DENSITY) {
  const d = Number(density) > 0 ? Number(density) : BEER_DENSITY;
  return Math.round((Number(fullWeightG) - Number(capacityMl) * d) * 10) / 10;
}

// Remaining beer from a scale reading, clamped to the keg's capacity
function calcRemainingMl(currentWeightG, tareWeightG, capacityMl, density = BEER_DENSITY) {
  const d = Number(density) > 0 ? Number(density) : BEER_DENSITY;
  const liquidG = Number(currentWeightG) - Number(tareWeightG);
  const ml = Math.round(liquidG / d);
  return Math.max(0, Math.min(ml, Number(capacityMl)));
}

// Convert serve counts into ml + revenue using the brand's own sizes and prices
function calcServingSales(beer, { glasses = 0, pitchers = 0, towers = 0 }) {
  const g = Math.max(0, Math.round(Number(glasses  || 0)));
  const p = Math.max(0, Math.round(Number(pitchers || 0)));
  const t = Math.max(0, Math.round(Number(towers   || 0)));
  const sz = beer?.servings || {};
  const pr = beer?.pricing  || {};
  const glassMl   = Number(sz.glassMl   ?? 330);
  const pitcherMl = Number(sz.pitcherMl ?? 1500);
  const towerMl   = Number(sz.towerMl   ?? 3000);
  return {
    glassesSold: g, pitchersSold: p, towersSold: t,
    soldMl:     g * glassMl + p * pitcherMl + t * towerMl,
    salesValue: Math.round(g * Number(pr.glass || 0) + p * Number(pr.pitcher || 0) + t * Number(pr.tower || 0)),
  };
}

function kegSellValue(keg, ml) {
  if (!keg.costPerKeg || !keg.capacityMl) return 0;
  return Math.round((Number(ml) / Number(keg.capacityMl)) * Number(keg.costPerKeg));
}

async function logKeg(keg, type, extra = {}) {
  return KegLog.create({
    userId:     keg.userId,
    kegId:      keg._id,
    kegTag:     keg.kegTag,
    beerName:   keg.beerName,
    outletId:   keg.outletId,
    outletName: keg.outletName,
    locationId: keg.locationId,
    locationName: keg.locationName,
    type,
    at: new Date(),
    ...extra,
  }).catch(() => {});
}

// Static reference data for the UI
app.get('/api/kegs/wastage-reasons', authMiddleware, (_, res) => res.json(WASTAGE_REASONS));

// ── Beers (draft beer brand list used by kegs) ──────────────────────────────
app.get('/api/draft-beers', authMiddleware, subscriptionCheck, requireSection('keg'), async (req, res) => {
  try {
    const { outletId, active } = req.query;
    const filter = { userId: req.auth.userId };
    if (outletId) filter.$or = [{ outletIds: outletId }, { outletIds: { $size: 0 } }];
    if (active === 'true') filter.active = true;
    res.json(await DraftBeer.find(filter).sort({ name: 1 }));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/draft-beers', authMiddleware, subscriptionCheck, requireSection('keg'), async (req, res) => {
  try {
    const { masterBottleId, name, category, outletIds, pricing, servings, notes } = req.body;

    let beerName = (name || '').trim();
    let beerCat  = (category || 'Beer').trim();
    let source   = 'craft';
    let masterId = null;

    if (masterBottleId) {
      const master = await MasterBottle.findById(masterBottleId);
      if (!master) return res.status(400).json({ error: 'Selected beer brand not found in the master list' });
      beerName = master.name;
      beerCat  = master.category || 'Beer';
      source   = 'master';
      masterId = master._id;
    }
    if (!beerName) return res.status(400).json({ error: 'Select a beer brand or enter a craft beer name' });

    const dup = await DraftBeer.findOne({ userId: req.auth.userId, name: new RegExp('^' + beerName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i') });
    if (dup) return res.status(409).json({ error: `"${beerName}" is already in your Beers list` });

    const price = {
      glass:   Number(pricing?.glass   || 0),
      pitcher: Number(pricing?.pitcher || 0),
      tower:   Number(pricing?.tower   || 0),
    };
    if (price.glass <= 0 && price.pitcher <= 0 && price.tower <= 0)
      return res.status(400).json({ error: 'Enter a price for at least one serve size' });

    const beer = await DraftBeer.create({
      userId: req.auth.userId,
      outletIds: Array.isArray(outletIds) ? outletIds : [],
      masterBottleId: masterId,
      name: beerName,
      category: beerCat,
      source,
      densityGPerMl: BEER_DENSITY,
      servings: {
        glassMl:   Number(servings?.glassMl   || 330),
        pitcherMl: Number(servings?.pitcherMl || 1500),
        towerMl:   Number(servings?.towerMl   || 3000),
      },
      pricing: price,
      notes,
    });
    await addHistory(req.auth.userId, 'ADD_DRAFT_BEER', { productName: beer.name });
    res.json(beer);
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: 'This beer is already in your Beers list' });
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/draft-beers/:id', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const beer = await DraftBeer.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!beer) return res.status(404).json({ error: 'Beer not found' });

    const { name, pricing, servings, outletIds, active, notes } = req.body;
    if (name?.trim() && beer.source === 'craft') beer.name = name.trim();
    if (Array.isArray(outletIds)) beer.outletIds = outletIds;
    if (active !== undefined) beer.active = Boolean(active);
    if (notes !== undefined)  beer.notes  = notes;

    if (pricing) {
      if (pricing.glass   !== undefined) beer.pricing.glass   = Number(pricing.glass   || 0);
      if (pricing.pitcher !== undefined) beer.pricing.pitcher = Number(pricing.pitcher || 0);
      if (pricing.tower   !== undefined) beer.pricing.tower   = Number(pricing.tower   || 0);
      if (beer.pricing.glass <= 0 && beer.pricing.pitcher <= 0 && beer.pricing.tower <= 0)
        return res.status(400).json({ error: 'Enter a price for at least one serve size' });
    }
    if (servings) {
      if (Number(servings.glassMl)   > 0) beer.servings.glassMl   = Number(servings.glassMl);
      if (Number(servings.pitcherMl) > 0) beer.servings.pitcherMl = Number(servings.pitcherMl);
      if (Number(servings.towerMl)   > 0) beer.servings.towerMl   = Number(servings.towerMl);
    }
    beer.densityGPerMl = BEER_DENSITY;

    await beer.save();
    await addHistory(req.auth.userId, 'EDIT_DRAFT_BEER', { productName: beer.name });
    res.json(beer);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/draft-beers/:id', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const beer = await DraftBeer.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!beer) return res.status(404).json({ error: 'Beer not found' });
    const used = await Keg.findOne({ userId: req.auth.userId, draftBeerId: beer._id });
    if (used) return res.status(400).json({ error: 'This beer is used by an existing keg and cannot be deleted. Mark it inactive instead.' });
    await DraftBeer.deleteOne({ _id: beer._id });
    await addHistory(req.auth.userId, 'DELETE_DRAFT_BEER', { productName: beer.name });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Report (declared before /:id routes) ──
app.get('/api/kegs/report', authMiddleware, subscriptionCheck, requireSection('keg','reports'), async (req, res) => {
  try {
    const { outletId, locationId, from, to } = req.query;
    const base = { userId: req.auth.userId };
    if (outletId) base.outletId = outletId;

    const logFilter = { ...base };
    if (locationId) logFilter.locationId = locationId;
    if (from || to) {
      logFilter.at = {};
      if (from) logFilter.at.$gte = new Date(from);
      if (to)   { const d = new Date(to); d.setHours(23,59,59,999); logFilter.at.$lte = d; }
    }

    const [kegs, logs, wastage] = await Promise.all([
      Keg.find(base).sort({ createdAt: -1 }),
      KegLog.find(logFilter).sort({ at: -1 }),
      KegWastage.find({ ...base, ...(locationId ? { locationId } : {}) }).sort({ at: -1 }),
    ]);

    const inventoryLogs   = logs.filter(l => l.type === 'inventory' || l.type === 'closing');
    const totalCapacity   = kegs.reduce((s, k) => s + (k.capacityMl || 0), 0);
    const totalConsumed   = inventoryLogs.reduce((s, l) => s + (l.consumedMl || 0), 0);
    const totalWasted     = wastage.reduce((s, w) => s + (w.wasteMl || 0), 0);
    const totalNet        = inventoryLogs.reduce((s, l) => s + (l.netConsumedMl || 0), 0);
    const totalSell       = inventoryLogs.reduce((s, l) => s + (l.salesValue || l.totalSell || 0), 0);
    const totalGlasses    = inventoryLogs.reduce((s, l) => s + (l.glassesSold  || 0), 0);
    const totalPitchers   = inventoryLogs.reduce((s, l) => s + (l.pitchersSold || 0), 0);
    const totalTowers     = inventoryLogs.reduce((s, l) => s + (l.towersSold   || 0), 0);
    const totalSoldMl     = inventoryLogs.reduce((s, l) => s + (l.soldMl       || 0), 0);
    const activeKegs      = kegs.filter(k => k.status === 'active');
    const totalRemaining  = activeKegs.reduce((s, k) => s + (k.remainingMl || 0), 0);

    res.json({
      kegs, logs, wastage,
      summary: {
        totalKegs: kegs.length,
        activeKegs: activeKegs.length,
        closedKegs: kegs.filter(k => k.status === 'closed').length,
        stockroomKegs: kegs.filter(k => k.status === 'stockroom').length,
        totalCapacity, totalConsumed, totalWasted, totalNet, totalRemaining, totalSell,
        totalGlasses, totalPitchers, totalTowers, totalSoldMl,
        // Net poured that recorded sales don't account for
        varianceMl: totalNet - totalSoldMl,
        wastagePct: totalConsumed ? ((totalWasted / totalConsumed) * 100).toFixed(1) : '0.0',
      },
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── List kegs ──
// locationId matches the keg's current location OR any bar it is assigned to
app.get('/api/kegs', authMiddleware, subscriptionCheck, requireSection('keg'), async (req, res) => {
  try {
    const { outletId, locationId, status } = req.query;
    const filter = { userId: req.auth.userId };
    if (outletId) filter.outletId = outletId;
    if (status)   filter.status   = status;
    if (locationId) {
      filter.$or = [{ locationId }, { 'assignments.barId': locationId }];
    }
    res.json(await Keg.find(filter).sort({ createdAt: -1 }));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Register a new keg ──
app.post('/api/kegs', authMiddleware, subscriptionCheck, requireSection('keg'), async (req, res) => {
  try {
    const {
      outletId, locationId, draftBeerId, beerName,
      kegTag, capacityMl, fullWeightG, costPerKeg, notes,
    } = req.body;

    if (!outletId)                  return res.status(400).json({ error: 'Select an outlet' });
    if (!kegTag?.trim())            return res.status(400).json({ error: 'Keg tag is required (e.g. Keg 1)' });
    if (!Number(capacityMl))        return res.status(400).json({ error: 'Enter keg capacity in millilitres' });
    if (!Number(fullWeightG))       return res.status(400).json({ error: 'Enter total weight of the full keg in grams' });

    const outlet = await Outlet.findOne({ _id: outletId, userId: req.auth.userId });
    if (!outlet) return res.status(400).json({ error: 'Outlet not found' });

    const loc = outlet.bars.find(b => b._id?.toString() === locationId || b.id === locationId);
    if (!loc || loc.type !== 'stockroom') return res.status(400).json({ error: 'Kegs can only be created in the Stock Room' });

    // Resolve the beer from the Beers list, or fall back to a typed-in name
    let beer = null, name = (beerName || '').trim(), category = 'Beer';
    if (draftBeerId) {
      beer = await DraftBeer.findOne({ _id: draftBeerId, userId: req.auth.userId });
      if (!beer) return res.status(400).json({ error: 'Selected beer not found in your Beers list' });
      name = beer.name;
      category = beer.category || 'Beer';
    }
    if (!name) return res.status(400).json({ error: 'Select a beer from your Beers list, or enter the draft beer name' });

    const dup = await Keg.findOne({ userId: req.auth.userId, outletId, kegTag: kegTag.trim() });
    if (dup) return res.status(400).json({ error: `Keg tag "${kegTag.trim()}" already exists in this outlet` });

    // Draft beer density is fixed at 1.01 g/ml — never asked for
    const density = BEER_DENSITY;
    const tareWeightG = calcTareWeight(fullWeightG, capacityMl, density);
    if (tareWeightG <= 0) return res.status(400).json({ error: 'Total weight must be greater than the beer quantity' });

    const keg = await Keg.create({
      userId: req.auth.userId,
      outletId, outletName: outlet.name,
      draftBeerId: beer?._id || null,
      beerName: name, category,
      kegTag: kegTag.trim(),
      capacityMl:  Number(capacityMl),
      fullWeightG: Number(fullWeightG),
      tareWeightG,
      densityGPerMl: density,
      costPerKeg: Number(costPerKeg || 0),
      locationId, locationName: loc.name,
      currentWeightG: Number(fullWeightG),
      remainingMl: Number(capacityMl),
      status: 'stockroom',
      notes,
    });

    await logKeg(keg, 'register', {
      weightG: Number(fullWeightG), openingMl: 0,
      remainingMl: Number(capacityMl), consumedMl: 0, wastageMl: 0, netConsumedMl: 0,
      note: `Keg registered · capacity ${capacityMl} ML`,
    });
    await addHistory(req.auth.userId, 'KEG_REGISTER', {
      outletId, locationId, outletName: outlet.name, locationName: loc.name,
      productName: `${name} (${keg.kegTag})`, quantity: Number(capacityMl),
    });

    res.json(keg);
  } catch (e) {
    if (e.code === 11000) return res.status(400).json({ error: 'A keg with this tag already exists in this outlet' });
    res.status(500).json({ error: e.message });
  }
});

// ── Edit keg (before it goes active) ──
app.put('/api/kegs/:id', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const keg = await Keg.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!keg) return res.status(404).json({ error: 'Keg not found' });
    if (keg.status === 'closed') return res.status(400).json({ error: 'A closed keg cannot be edited' });

    const { beerName, kegTag, capacityMl, fullWeightG, costPerKeg, notes } = req.body;

    if (beerName?.trim()) keg.beerName = beerName.trim();
    if (kegTag?.trim())   keg.kegTag   = kegTag.trim();
    if (notes !== undefined) keg.notes = notes;
    if (costPerKeg !== undefined) keg.costPerKeg = Number(costPerKeg || 0);

    // Capacity / weight can only change while no inventory has been taken
    const touchesWeights = capacityMl !== undefined || fullWeightG !== undefined;
    if (touchesWeights) {
      if (keg.lastInventoryAt) return res.status(400).json({ error: 'Capacity and weight cannot be changed after inventory has started' });
      if (capacityMl  !== undefined) keg.capacityMl  = Number(capacityMl);
      if (fullWeightG !== undefined) keg.fullWeightG = Number(fullWeightG);
      keg.densityGPerMl = BEER_DENSITY;
      keg.tareWeightG   = calcTareWeight(keg.fullWeightG, keg.capacityMl, keg.densityGPerMl);
      if (keg.tareWeightG <= 0) return res.status(400).json({ error: 'Total weight must be greater than the beer quantity' });
      keg.remainingMl    = keg.capacityMl;
      keg.currentWeightG = keg.fullWeightG;
    }

    await keg.save();
    res.json(keg);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Delete keg (only while untouched) ──
app.delete('/api/kegs/:id', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const keg = await Keg.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!keg) return res.status(404).json({ error: 'Keg not found' });
    if (keg.lastInventoryAt) return res.status(400).json({ error: 'This keg has inventory history and cannot be deleted' });
    await Keg.deleteOne({ _id: keg._id });
    await KegLog.deleteMany({ kegId: keg._id });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Assign keg from Stock Room to one or more bars ──
app.post('/api/kegs/:id/assign', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const { bars } = req.body;   // [{ barId, barName }] or [barId]
    const keg = await Keg.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!keg) return res.status(404).json({ error: 'Keg not found' });
    if (keg.status === 'closed') return res.status(400).json({ error: 'This keg is closed' });
    if (!bars?.length) return res.status(400).json({ error: 'Select at least one bar' });

    const outlet = await Outlet.findOne({ _id: keg.outletId, userId: req.auth.userId });
    const resolved = [];
    for (const entry of bars) {
      const barId = typeof entry === 'string' ? entry : entry.barId;
      const bar = outlet?.bars.find(b => b._id?.toString() === barId || b.id === barId);
      if (!bar) return res.status(400).json({ error: 'Invalid bar selected' });
      if (bar.type !== 'bar') return res.status(400).json({ error: `${bar.name} is not a bar` });
      resolved.push({ barId, barName: bar.name, assignedAt: new Date() });
    }

    // Keep any earlier assignments, add the new ones
    const existing = keg.assignments.filter(a => !resolved.find(r => r.barId === a.barId));
    keg.assignments  = [...existing, ...resolved];
    keg.locationId   = resolved[0].barId;
    keg.locationName = resolved.map(r => r.barName).join(', ');
    keg.status       = 'active';
    await keg.save();

    await logKeg(keg, 'assign', {
      remainingMl: keg.remainingMl,
      note: `Assigned to ${resolved.map(r => r.barName).join(', ')}`,
    });
    await addHistory(req.auth.userId, 'KEG_ASSIGN', {
      outletId: keg.outletId, outletName: keg.outletName,
      toLocationName: resolved.map(r => r.barName).join(', '),
      productName: `${keg.beerName} (${keg.kegTag})`, quantity: keg.remainingMl,
    });

    res.json(keg);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Transfer keg between locations ──
app.post('/api/kegs/:id/transfer', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const { toLocationId } = req.body;
    const keg = await Keg.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!keg) return res.status(404).json({ error: 'Keg not found' });
    if (keg.status === 'closed') return res.status(400).json({ error: 'This keg is closed' });

    const outlet = await Outlet.findOne({ _id: keg.outletId, userId: req.auth.userId });
    const to = outlet?.bars.find(b => b._id?.toString() === toLocationId || b.id === toLocationId);
    if (!to) return res.status(400).json({ error: 'Invalid destination' });
    if (toLocationId === keg.locationId) return res.status(400).json({ error: 'Keg is already at this location' });

    const fromName = keg.locationName;
    keg.locationId   = toLocationId;
    keg.locationName = to.name;
    if (to.type === 'bar') {
      if (!keg.assignments.find(a => a.barId === toLocationId)) {
        keg.assignments.push({ barId: toLocationId, barName: to.name, assignedAt: new Date() });
      }
      keg.status = 'active';
    } else {
      keg.status = 'stockroom';
    }
    await keg.save();

    await logKeg(keg, 'transfer', { remainingMl: keg.remainingMl, note: `Transferred from ${fromName} to ${to.name}` });
    await addHistory(req.auth.userId, 'KEG_TRANSFER', {
      outletId: keg.outletId, outletName: keg.outletName,
      fromLocationName: fromName, toLocationName: to.name,
      productName: `${keg.beerName} (${keg.kegTag})`, quantity: keg.remainingMl,
    });

    res.json(keg);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Inventory cycle: user enters only the current weight ──
app.post('/api/kegs/:id/inventory', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const { currentWeightG, wastageMl, wastageReason, locationId,
            glasses, pitchers, towers } = req.body;
    const keg = await Keg.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!keg) return res.status(404).json({ error: 'Keg not found' });
    if (keg.status === 'closed') return res.status(400).json({ error: 'This keg is closed' });
    if (currentWeightG === undefined || currentWeightG === null || currentWeightG === '')
      return res.status(400).json({ error: 'Enter the current weight of the keg' });

    const weight = Number(currentWeightG);
    if (weight < keg.tareWeightG)
      return res.status(400).json({ error: 'Current weight is below the empty keg weight — please re-check the reading' });
    if (weight > keg.fullWeightG)
      return res.status(400).json({ error: 'Current weight is higher than the full keg weight — please re-check the reading' });

    const openingMl   = keg.remainingMl ?? keg.capacityMl;
    const remainingMl = calcRemainingMl(weight, keg.tareWeightG, keg.capacityMl, keg.densityGPerMl);
    const consumedMl  = Math.max(0, openingMl - remainingMl);

    // POS-driven keg: sales come from the bills, and whatever left the keg
    // beyond what was billed (sold + NC) is wastage. Only the reason is asked.
    const pos = await kegPosWindow(keg);
    let waste, netConsumedMl, sales, varianceMl;
    if (pos.posConnected) {
      const billedMl = pos.soldMl + pos.ncMl;
      waste = Math.max(0, consumedMl - billedMl);
      if (waste > 0 && !wastageReason)
        return res.status(400).json({ error: `${waste} ML is unaccounted for by the POS — choose a wastage reason` });
      netConsumedMl = Math.max(0, consumedMl - waste);
      sales = { glassesSold: 0, pitchersSold: 0, towersSold: 0, soldMl: pos.soldMl, salesValue: pos.salesValue };
      // negative only when the POS billed more than physically left the keg
      varianceMl = netConsumedMl - billedMl;
    } else {
      waste = Math.max(0, Number(wastageMl || 0));
      if (waste > consumedMl)
        return res.status(400).json({ error: `Wastage cannot exceed the ${consumedMl} ML consumed this cycle` });
      netConsumedMl = Math.max(0, consumedMl - waste);

      // Sales for this cycle, entered as serve counts
      const beer = keg.draftBeerId ? await DraftBeer.findById(keg.draftBeerId) : null;
      sales = calcServingSales(beer, { glasses, pitchers, towers });
      // Sales plus wastage cannot exceed what physically left the keg this cycle
      if (sales.soldMl > netConsumedMl)
        return res.status(400).json({
          error: `Recorded sales (${sales.soldMl} ML) exceed the ${netConsumedMl} ML poured this cycle after wastage — re-check the serve counts`,
        });
      // Net consumption that isn't accounted for by recorded sales
      varianceMl = netConsumedMl - sales.soldMl;
    }

    keg.currentWeightG  = weight;
    keg.remainingMl     = remainingMl;
    keg.totalConsumedMl = (keg.totalConsumedMl || 0) + consumedMl;
    keg.totalWastageMl  = (keg.totalWastageMl  || 0) + waste;
    keg.totalGlasses    = (keg.totalGlasses    || 0) + sales.glassesSold;
    keg.totalPitchers   = (keg.totalPitchers   || 0) + sales.pitchersSold;
    keg.totalTowers     = (keg.totalTowers     || 0) + sales.towersSold;
    keg.totalSoldMl     = (keg.totalSoldMl     || 0) + sales.soldMl;
    keg.totalSalesValue = (keg.totalSalesValue || 0) + sales.salesValue;
    keg.lastInventoryAt = new Date();
    // Only move the keg if the count was taken at a bar it is actually assigned to.
    // Counting from the Stock Room must never pull an active keg back off its bar.
    if (locationId) {
      const assignedHere = keg.assignments?.some(a => String(a.barId) === String(locationId));
      if (assignedHere || !keg.assignments?.length) {
        keg.locationId = locationId;
      }
    }
    if (keg.status === 'stockroom' && consumedMl > 0) keg.status = 'active';
    await keg.save();

    const kegLog = await logKeg(keg, 'inventory', {
      weightG: weight, openingMl, remainingMl, consumedMl,
      wastageMl: waste, netConsumedMl, wastageReason: waste ? (wastageReason || 'Other') : undefined,
      glassesSold: sales.glassesSold, pitchersSold: sales.pitchersSold, towersSold: sales.towersSold,
      soldMl: sales.soldMl, salesValue: sales.salesValue, varianceMl,
      totalSell: sales.salesValue,
      ...(pos.posConnected ? { posMode: true, ncMl: pos.ncMl, posLines: pos.lines, posWindowFrom: pos.since } : {}),
    }).catch(() => null);
    // Each bill is used by one keg count only
    if (pos.posConnected && kegLog && pos.sales.length) {
      await PosSale.updateMany({ _id: { $in: pos.sales.map(x => x._id) } }, { $set: { kegLogId: kegLog._id } });
    }

    if (waste > 0) {
      await KegWastage.create({
        userId: req.auth.userId, kegId: keg._id, kegTag: keg.kegTag, beerName: keg.beerName,
        outletId: keg.outletId, locationId: keg.locationId, locationName: keg.locationName,
        wasteMl: waste, reason: wastageReason || 'Other',
      });
    }

    await addHistory(req.auth.userId, 'KEG_INVENTORY', {
      outletId: keg.outletId, outletName: keg.outletName, locationName: keg.locationName,
      productName: `${keg.beerName} (${keg.kegTag})`,
      consumedMl, totalSell: sales.salesValue, quantity: remainingMl,
    });

    res.json({
      keg,
      cycle: { openingMl, remainingMl, consumedMl, wastageMl: waste, netConsumedMl, ...sales, varianceMl,
               posMode: Boolean(pos.posConnected), ncMl: pos.ncMl || 0, posLines: pos.lines || 0 },
      isEmpty: remainingMl <= 0,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Keg ↔ POS ────────────────────────────────────────────────────────────────
// Bills for this keg's beer at the bar(s) the keg feeds, received since the
// keg's previous count and not yet used by any keg count. If no mapping for the
// beer exists at those bars, the keg is not POS-driven and the manual flow stays.
async function kegPosWindow(keg) {
  const bars = [...new Set([...(keg.assignments || []).map(a => String(a.barId)), keg.locationId && String(keg.locationId)].filter(Boolean))];
  if (!bars.length) return { posConnected: false };
  const cfgs = await PosConfig.find({ userId: keg.userId, siRooOutletId: keg.outletId, active: true }).select('_id');
  if (!cfgs.length) return { posConnected: false };
  const mappings = await MenuMapping.find({
    posConfigId: { $in: cfgs.map(c => c._id) }, targetType: 'keg',
    // a mapping for this beer, or one left as "any active keg at that bar"
    kegBeerId: keg.draftBeerId ? { $in: [keg.draftBeerId, null] } : null,
    locationId: { $in: bars }, active: { $ne: false },
  });
  if (!mappings.length) return { posConnected: false };

  const lastAssign = (keg.assignments || []).map(a => a.assignedAt).filter(Boolean).sort((a, b) => a - b)[0];
  const since = keg.lastInventoryAt || lastAssign || keg.connectedAt || keg.createdAt;
  const sales = await PosSale.find({
    userId: keg.userId, reversed: { $ne: true }, kegLogId: null,
    $or: mappings.map(m => ({ posConfigId: m.posConfigId, kind: m.kind, posItemId: m.posItemId, locationId: String(m.locationId) })),
    createdAt: { $gt: since, $lte: new Date() },
  });
  return { posConnected: true, since, sales, ...sumPosLines(sales) };
}

// Totals for a set of POS lines, NC kept apart
function sumPosLines(sales) {
  let soldMl = 0, soldQty = 0, value = 0, ncMl = 0, ncQty = 0;
  for (const x of sales) {
    const ml = saleMl(x);
    if (x.isNc) { ncMl += ml; ncQty += Number(x.quantity || 0); }
    else { soldMl += ml; soldQty += Number(x.quantity || 0); value += Number(x.lineTotal || 0); }
  }
  return { soldMl: Math.round(soldMl), soldQty, salesValue: Math.round(value), ncMl: Math.round(ncMl), ncQty, lines: sales.length };
}

// What the keg count screen needs before the count: is the POS driving this
// keg, and how much has it billed since the last count.
app.get('/api/kegs/:id/pos-preview', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const keg = await Keg.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!keg) return res.status(404).json({ error: 'Keg not found' });
    const w = await kegPosWindow(keg);
    if (!w.posConnected) return res.json({ posConnected: false });
    const { sales, ...rest } = w;
    res.json(rest);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Standalone wastage entry ──
app.post('/api/kegs/:id/wastage', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const { wasteMl, reason } = req.body;
    const keg = await Keg.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!keg) return res.status(404).json({ error: 'Keg not found' });
    if (keg.status === 'closed') return res.status(400).json({ error: 'This keg is closed' });

    const waste = Number(wasteMl || 0);
    if (waste <= 0) return res.status(400).json({ error: 'Enter a wastage quantity in ML' });
    if (waste > (keg.remainingMl || 0)) return res.status(400).json({ error: `Wastage cannot exceed the ${keg.remainingMl} ML remaining` });

    keg.remainingMl    = Math.max(0, (keg.remainingMl || 0) - waste);
    keg.totalWastageMl = (keg.totalWastageMl || 0) + waste;
    keg.totalConsumedMl = (keg.totalConsumedMl || 0) + waste;
    await keg.save();

    await KegWastage.create({
      userId: req.auth.userId, kegId: keg._id, kegTag: keg.kegTag, beerName: keg.beerName,
      outletId: keg.outletId, locationId: keg.locationId, locationName: keg.locationName,
      wasteMl: waste, reason: reason || 'Other',
    });
    await logKeg(keg, 'wastage', {
      openingMl: keg.remainingMl + waste, remainingMl: keg.remainingMl,
      consumedMl: waste, wastageMl: waste, netConsumedMl: 0,
      wastageReason: reason || 'Other',
    });
    await addHistory(req.auth.userId, 'KEG_WASTAGE', {
      outletId: keg.outletId, outletName: keg.outletName, locationName: keg.locationName,
      productName: `${keg.beerName} (${keg.kegTag})`, quantity: waste,
    });

    res.json(keg);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Declare keg empty — final wastage is mandatory before closing ──
app.post('/api/kegs/:id/declare-empty', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const { finalWastageMl, reason } = req.body;
    const keg = await Keg.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!keg) return res.status(404).json({ error: 'Keg not found' });
    if (keg.status === 'closed') return res.status(400).json({ error: 'This keg is already closed' });

    if (finalWastageMl === undefined || finalWastageMl === null || finalWastageMl === '')
      return res.status(400).json({ error: 'Final wastage quantity is required before the keg can be closed', requiresWastage: true });

    const waste = Number(finalWastageMl);
    if (isNaN(waste) || waste < 0) return res.status(400).json({ error: 'Enter a valid final wastage quantity (0 if none)' });

    const openingMl = keg.remainingMl || 0;
    if (waste > openingMl) return res.status(400).json({ error: `Final wastage cannot exceed the ${openingMl} ML remaining` });

    // Everything left in the keg at closure is accounted for: waste + residual pour-out
    keg.totalWastageMl  = (keg.totalWastageMl  || 0) + waste;
    keg.totalConsumedMl = (keg.totalConsumedMl || 0) + openingMl;
    keg.remainingMl     = 0;
    keg.currentWeightG  = keg.tareWeightG;
    keg.status          = 'closed';
    keg.closedAt        = new Date();
    await keg.save();

    if (waste > 0) {
      await KegWastage.create({
        userId: req.auth.userId, kegId: keg._id, kegTag: keg.kegTag, beerName: keg.beerName,
        outletId: keg.outletId, locationId: keg.locationId, locationName: keg.locationName,
        wasteMl: waste, reason: reason || 'Final wastage on keg closure', isFinal: true,
      });
    }
    await logKeg(keg, 'closing', {
      weightG: keg.tareWeightG, openingMl, remainingMl: 0,
      consumedMl: openingMl, wastageMl: waste, netConsumedMl: Math.max(0, openingMl - waste),
      wastageReason: reason || 'Final wastage on keg closure',
      totalSell: kegSellValue(keg, Math.max(0, openingMl - waste)),
      note: 'Keg declared empty and closed',
    });
    await addHistory(req.auth.userId, 'KEG_CLOSED', {
      outletId: keg.outletId, outletName: keg.outletName, locationName: keg.locationName,
      productName: `${keg.beerName} (${keg.kegTag})`,
      consumedMl: keg.totalConsumedMl, quantity: waste,
    });

    res.json(keg);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Full lifecycle of a single keg ──
app.get('/api/kegs/:id/history', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const keg = await Keg.findOne({ _id: req.params.id, userId: req.auth.userId });
    if (!keg) return res.status(404).json({ error: 'Keg not found' });
    const [logs, wastage] = await Promise.all([
      KegLog.find({ kegId: keg._id }).sort({ at: -1 }),
      KegWastage.find({ kegId: keg._id }).sort({ at: -1 }),
    ]);
    res.json({ keg, logs, wastage });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── All logs / wastage for a location (list views) ──
app.get('/api/kegs-logs', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const { outletId, locationId, type } = req.query;
    const filter = { userId: req.auth.userId };
    if (outletId)   filter.outletId   = outletId;
    if (locationId) filter.locationId = locationId;
    if (type)       filter.type       = type;
    res.json(await KegLog.find(filter).sort({ at: -1 }).limit(500));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/kegs-wastage', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const { outletId, locationId } = req.query;
    const filter = { userId: req.auth.userId };
    if (outletId)   filter.outletId   = outletId;
    if (locationId) filter.locationId = locationId;
    res.json(await KegWastage.find(filter).sort({ at: -1 }).limit(500));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// POS ROUTES
//
// The POS module is user-scoped data (connections, mappings, sales) but it is
// administered by SIROO staff. Every handler below is written once against an
// explicit userId, then exposed twice:
//   /api/pos/*        — the operator's own token supplies the userId
//   /api/admin/pos/*  — an admin token passes ?userId= / body.userId
// ══════════════════════════════════════════════════════════════════════════════

function posErr(status, message) { const e = new Error(message); e.status = status; return e; }

const newWebhookKey = () => crypto.randomBytes(24).toString('hex');
function webhookUrlFor(req, cfg) {
  const base = process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get('host')}`;
  // The key makes the URL unguessable, so nobody else can push fake bills
  return `${base}/api/pos/webhook/${cfg._id}${cfg.webhookKey ? `?key=${cfg.webhookKey}` : ''}`;
}
// A POS push is accepted when it carries the URL key or the configured token
function webhookAuthorised(req, cfg, body) {
  const keyOk   = cfg.webhookKey && req.query?.key && safeEqual(String(req.query.key), cfg.webhookKey);
  const tokenOk = cfg.staticToken && safeEqual(String(readPayloadToken(body) ?? ''), String(cfg.staticToken));
  if (!cfg.webhookKey && !cfg.staticToken) return true;   // old connection, nothing configured yet
  return Boolean(keyOk || tokenOk);
}

// Wraps a shared handler so it can be mounted on either route tree.
// resolveUser tells us where the userId comes from for that tree.
function posRoute(handler, resolveUser) {
  return async (req, res) => {
    try {
      const userId = await resolveUser(req);
      res.json(await handler(userId, req));
    } catch (e) {
      res.status(e.status || 500).json({ error: e.message });
    }
  };
}
const fromToken = req => req.auth.userId;
const fromAdmin = async req => {
  const userId = req.query.userId || req.body?.userId;
  if (!userId) throw posErr(400, 'Select a customer first');
  const u = await User.findById(userId).catch(() => null);
  if (!u) throw posErr(404, 'Customer not found');
  return userId;
};

// ── Shared handlers ──────────────────────────────────────────────────────────

const posSupported = () => ([
  {
    id: 'petpooja', name: 'Petpooja', mode: 'webhook',
    fields: ['restID', 'staticToken'],
    help: 'Petpooja pushes each bill to the webhook URL on SAVE AND PRINT. There is no menu or orders API to pull from — items appear in the mapping inbox as bills arrive.',
  },
  { id: 'custom', name: 'Custom POS', mode: 'webhook', fields: ['restID', 'staticToken'], help: 'Any POS that can POST the same JSON shape.' },
]);

// Everything the mapping form needs for one customer, in a single call
async function posContext(userId) {
  const [outlets, products, recipes, beers] = await Promise.all([
    Outlet.find({ userId }).sort({ name: 1 }),
    UserProduct.find({ userId, active: { $ne: false } }).sort({ name: 1 }),
    PbRecipe.find({ userId }).sort({ name: 1 }),
    DraftBeer.find({ userId, active: { $ne: false } }).sort({ name: 1 }),
  ]);
  return {
    outlets: outlets.map(o => ({
      _id: o._id, name: o.name,
      bars: (o.bars || []).map(b => ({ _id: b._id, name: b.name, type: b.type })),
    })),
    products: products.map(p => ({ _id: p._id, name: p.name, category: p.category, bottleSizeMl: p.bottleSizeMl })),
    recipes:  recipes.map(r => ({ _id: r._id, name: r.name, outletId: r.outletId, yieldMl: r.yieldMl })),
    beers:    beers.map(b => ({ _id: b._id, name: b.name })),
  };
}

async function posListConfigs(userId, req) {
  const cfgs = await PosConfig.find({ userId }).sort({ createdAt: -1 });
  const outlets = await Outlet.find({ userId });
  const nameOf = id => outlets.find(o => String(o._id) === String(id))?.name || '';
  return cfgs.map(c => ({ ...c.toObject(), outletName: nameOf(c.siRooOutletId), webhookUrl: webhookUrlFor(req, c) }));
}

async function posCreateConfig(userId, req) {
  const { siRooOutletId, posName = 'petpooja', label, restID, staticToken, autoDeduct } = req.body;
  if (!siRooOutletId) throw posErr(400, 'Select the outlet this POS belongs to');
  const outlet = await Outlet.findOne({ _id: siRooOutletId, userId });
  if (!outlet) throw posErr(400, 'That outlet does not belong to this customer');
  if (restID) {
    const dup = await PosConfig.findOne({ userId, restID: String(restID).trim() });
    if (dup) throw posErr(409, `A connection for restaurant "${restID}" already exists`);
  }
  const cfg = await PosConfig.create({
    userId, siRooOutletId, posName: String(posName).toLowerCase(),
    label: label || outlet.name, syncMode: 'webhook',
    restID: restID ? String(restID).trim() : undefined,
    staticToken: staticToken || undefined,
    webhookKey: newWebhookKey(),
    autoDeduct: autoDeduct !== false,
  });
  return { ...cfg.toObject(), outletName: outlet.name, webhookUrl: webhookUrlFor(req, cfg) };
}

async function posUpdateConfig(userId, req) {
  const cfg = await PosConfig.findOne({ _id: req.params.id, userId });
  if (!cfg) throw posErr(404, 'Connection not found');
  const { label, restID, staticToken, autoDeduct, active, siRooOutletId } = req.body;
  if (label !== undefined)       cfg.label       = label;
  if (restID !== undefined)      cfg.restID      = String(restID || '').trim() || undefined;
  if (staticToken !== undefined) cfg.staticToken = staticToken || undefined;
  if (autoDeduct !== undefined)  cfg.autoDeduct  = Boolean(autoDeduct);
  if (active !== undefined)      cfg.active      = Boolean(active);
  if (siRooOutletId) {
    const o = await Outlet.findOne({ _id: siRooOutletId, userId });
    if (!o) throw posErr(400, 'That outlet does not belong to this customer');
    cfg.siRooOutletId = siRooOutletId;
  }
  await cfg.save();
  return { ...cfg.toObject(), webhookUrl: webhookUrlFor(req, cfg) };
}

async function posDeleteConfig(userId, req) {
  const cfg = await PosConfig.findOne({ _id: req.params.id, userId });
  if (!cfg) throw posErr(404, 'Connection not found');
  await Promise.all([
    PosConfig.deleteOne({ _id: cfg._id }),
    MenuMapping.deleteMany({ posConfigId: cfg._id }),
    PosUnmapped.deleteMany({ posConfigId: cfg._id }),
  ]);
  return { ok: true };
}

async function posListUnmapped(userId, req) {
  const { posConfigId, includeIgnored } = req.query;
  const filter = { userId };
  if (posConfigId) filter.posConfigId = posConfigId;
  if (includeIgnored !== 'true') filter.ignored = { $ne: true };
  const mapped = await MenuMapping.find(posConfigId ? { posConfigId } : { userId });
  const seen = new Set(mapped.map(m => `${m.kind}:${m.posItemId}`));
  const rows = await PosUnmapped.find(filter).sort({ timesSeen: -1, lastSeenAt: -1 }).limit(500);
  return rows.filter(r => !seen.has(`${r.kind}:${r.posItemId}`));
}

async function posIgnoreUnmapped(userId, req) {
  const row = await PosUnmapped.findOneAndUpdate(
    { _id: req.params.id, userId }, { ignored: req.body?.ignored !== false }, { new: true });
  if (!row) throw posErr(404, 'Item not found');
  return row;
}

async function posListMappings(userId, req) {
  const filter = { userId };
  if (req.query.posConfigId) filter.posConfigId = req.query.posConfigId;
  return MenuMapping.find(filter).sort({ posItemName: 1 });
}

async function posSaveMapping(userId, req) {
  const { posConfigId, kind = 'item', posItemId, posItemName, posCategory,
          locationId, targetType = 'bottle', bottleId, pbRecipeId, kegBeerId,
          mlPerServe, notes } = req.body;

  if (!posConfigId || !posItemId) throw posErr(400, 'POS connection and item are required');
  if (!locationId)                throw posErr(400, 'Choose the bar this item is poured at');
  if (!Number(mlPerServe) || Number(mlPerServe) <= 0) throw posErr(400, 'Enter how many ML one serve pours');

  const cfg = await PosConfig.findOne({ _id: posConfigId, userId });
  if (!cfg) throw posErr(400, 'POS connection not found');

  const outlet = await Outlet.findById(cfg.siRooOutletId);
  const bar    = outlet?.bars?.find(b => String(b._id) === String(locationId));
  if (!bar) throw posErr(400, 'That bar is not part of this connection\'s outlet');

  if (targetType === 'bottle'   && !bottleId)   throw posErr(400, 'Select the bottle this pours from');
  if (targetType === 'prebatch' && !pbRecipeId) throw posErr(400, 'Select the pre-batch recipe this pours from');

  return MenuMapping.findOneAndUpdate(
    { posConfigId, kind, posItemId: String(posItemId) },
    {
      userId, posConfigId, kind, posItemId: String(posItemId), posItemName, posCategory,
      locationId: String(locationId), locationName: bar.name,
      targetType,
      bottleId:   targetType === 'bottle'   ? bottleId   : null,
      pbRecipeId: targetType === 'prebatch' ? pbRecipeId : null,
      kegBeerId:  targetType === 'keg'      ? (kegBeerId || null) : null,
      mlPerServe: Number(mlPerServe), notes, active: true,
    },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );
}

async function posDeleteMapping(userId, req) {
  await MenuMapping.deleteOne({ _id: req.params.id, userId });
  return { ok: true };
}

async function posListSales(userId, req) {
  const { posConfigId, from, to, mapped } = req.query;
  const filter = { userId };
  if (posConfigId)        filter.posConfigId = posConfigId;
  if (mapped === 'true')  filter.mapped = true;
  if (mapped === 'false') filter.mapped = false;
  if (req.query.nc === 'true')  filter.isNc = true;
  if (req.query.nc === 'false') filter.isNc = { $ne: true };
  if (from || to) {
    filter.soldAt = {};
    if (from) filter.soldAt.$gte = new Date(from);
    if (to)   { const d = new Date(to); d.setHours(23,59,59,999); filter.soldAt.$lte = d; }
  }
  const sales  = await PosSale.find(filter).sort({ soldAt: -1 }).limit(1000);
  const active = sales.filter(s => !s.reversed);
  return {
    sales,
    summary: {
      lines: sales.length,
      mapped:    active.filter(s => s.mapped).length,
      unmapped:  active.filter(s => !s.mapped).length,
      cancelled: sales.filter(s => s.reversed).length,
      totalMl:   active.reduce((a, s) => a + (s.totalMlDeducted || 0), 0),
      totalSell: active.reduce((a, s) => a + (s.lineTotal || 0), 0),
      ncLines:   active.filter(s => s.isNc).length,
      ncMl:      active.filter(s => s.mapped && s.isNc).reduce((a, s) => a + saleMl(s), 0),
      shortfalls:active.filter(s => (s.shortfallMl || 0) > 0).length,
    },
  };
}

// NC register — every non-chargeable line punched on the POS
async function posListNc(userId, req) {
  const { posConfigId, from, to } = req.query;
  const filter = { userId, isNc: true, reversed: { $ne: true } };
  if (posConfigId) filter.posConfigId = posConfigId;
  const allowed = req.auth ? allowedOutlets(req) : null;
  if (allowed) filter.siRooOutletId = { $in: allowed };
  if (from || to) {
    filter.soldAt = {};
    if (from) { const d = new Date(from); d.setHours(0,0,0,0); filter.soldAt.$gte = d; }
    if (to)   { const d = new Date(to);   d.setHours(23,59,59,999); filter.soldAt.$lte = d; }
  }
  const rows = await PosSale.find(filter).sort({ soldAt: -1 }).limit(2000);
  const items = rows.map(r => ({
    _id: r._id, soldAt: r.soldAt, billNo: r.invoiceId || r.posOrderId, tableNo: r.tableNo,
    biller: r.biller, item: r.posItemName, category: r.posCategory, quantity: r.quantity,
    ml: r.mapped ? saleMl(r) : null, bar: r.locationName, mapped: r.mapped,
    menuValue: Math.round(Number(r.unitPrice || 0) * Number(r.quantity || 0)),
    reason: r.ncReason,
  }));
  return {
    items,
    summary: {
      lines: items.length,
      bills: new Set(rows.map(r => r.posOrderId)).size,
      quantity: items.reduce((a, r) => a + (r.quantity || 0), 0),
      ncMl: items.reduce((a, r) => a + (r.ml || 0), 0),
      menuValue: items.reduce((a, r) => a + r.menuValue, 0),
    },
  };
}

async function posListLogs(userId, req) {
  const filter = { userId };
  if (req.query.posConfigId) filter.posConfigId = req.query.posConfigId;
  const rows = await PosWebhookLog.find(filter).sort({ at: -1 }).limit(100);
  return rows.map(r => { const o = r.toObject(); if (req.query.withPayload !== 'true') delete o.payload; return o; });
}

// Day view built from the count settlements, so it follows the count windows:
// each count compares the bills since the previous count. "date" = count date.
async function posReconcile(userId, req) {
  const { posConfigId, date } = req.body;
  const cfg = await PosConfig.findOne({ _id: posConfigId, userId });
  if (!cfg) throw posErr(404, 'POS connection not found');

  const dayStart = new Date(date); dayStart.setHours(0, 0, 0, 0);
  const dayEnd   = new Date(date); dayEnd.setHours(23, 59, 59, 999);

  const settlements = await PosSettlement.find({
    userId, outletId: cfg.siRooOutletId, reason: 'count', periodTo: { $gte: dayStart, $lte: dayEnd },
  });

  // several counts of one bottle (or the same bottle in two bars) add up
  const byBottle = new Map();
  for (const st of settlements) {
    const k = String(st.productId);
    const g = byBottle.get(k) || { name: st.productName, size: st.bottleSizeMl, phys: 0, pos: 0, nc: 0, variance: 0, counts: 0 };
    g.phys += st.physicalConsumedMl || 0; g.pos += st.posConsumedMl || 0; g.nc += st.ncMl || 0;
    g.variance += st.varianceMl || 0; g.counts += 1;
    byBottle.set(k, g);
  }

  await Reconciliation.deleteMany({ userId, posConfigId: cfg._id, date: dayStart });
  const records = [];
  for (const [bottleId, g] of byBottle) {
    const tolerance = Math.max(30, (g.size || 750) * 0.05);
    const billed = g.pos + g.nc;
    records.push(await Reconciliation.create({
      userId, siRooOutletId: cfg.siRooOutletId, posConfigId: cfg._id,
      bottleId, bottleName: g.name, date: dayStart,
      physicalConsumedMl: g.phys, posSalesML: g.pos, ncMl: g.nc, counts: g.counts,
      variance: g.variance,
      variancePct: billed > 0 ? ((g.variance / billed) * 100).toFixed(1) + '%' : null,
      status: Math.abs(g.variance) <= tolerance ? 'OK' : g.variance > 0 ? 'SHRINKAGE' : 'SURPLUS',
    }));
  }

  // Bills sitting in the mirror since the last count — waiting for the next
  // count, not missing. Shown for information only.
  const open = await PosStock.find({ userId, outletId: cfg.siRooOutletId, $or: [{ posLines: { $gt: 0 } }, { ncMl: { $gt: 0 } }] });
  const names = new Map((await UserProduct.find({ _id: { $in: open.map(m => m.productId) } }).select('name'))
    .map(p => [String(p._id), p.name]));
  return {
    ok: true, date, records,
    awaitingCount: open.map(m => ({
      bottleId: m.productId, bottleName: names.get(String(m.productId)) || 'Unknown', locationId: m.locationId,
      since: m.anchoredAt, lines: m.posLines, ml: Math.round(m.posConsumedMl || 0), ncMl: Math.round(m.ncMl || 0),
    })),
  };
}

async function posReconciliation(userId, req) {
  const { posConfigId, from, to } = req.query;
  const filter = { userId };
  if (posConfigId) filter.posConfigId = posConfigId;
  if (from || to) {
    filter.date = {};
    if (from) filter.date.$gte = new Date(from);
    if (to)   { const d = new Date(to); d.setHours(23,59,59,999); filter.date.$lte = d; }
  }
  const records = await Reconciliation.find(filter).sort({ date: -1 }).limit(500);
  return {
    records,
    summary: {
      total: records.length,
      ok:           records.filter(r => r.status === 'OK').length,
      shrinkage:    records.filter(r => r.status === 'SHRINKAGE').length,
      surplus:      records.filter(r => r.status === 'SURPLUS').length,
      unreconciled: records.filter(r => r.status === 'UNRECONCILED').length,
      totalNcMl:    records.reduce((a, r) => a + (r.ncMl || 0), 0),
      totalVarianceMl: records.reduce((a, r) => a + (r.variance || 0), 0),
    },
  };
}

// ── Webhook — public and unauthenticated, per the Global API spec ────────────
async function handlePetpoojaWebhook(req, res, cfgFromPath) {
  const body = req.body || {};
  let cfg = cfgFromPath || null;
  const restID = body?.properties?.Restaurant?.restID || '';

  try {
    if (!cfg && restID) cfg = await PosConfig.findOne({ restID, active: true });
    if (!cfg) {
      await PosWebhookLog.create({ restID, event: body.event, ok: false, message: 'No matching POS connection', payload: body }).catch(() => {});
      return res.status(404).json({ success: '0', message: 'No POS connection matches this restaurant' });
    }
    if (!webhookAuthorised(req, cfg, body)) {
      console.warn(`[security] rejected POS push for ${cfg._id} from ${req.ip}`);
      await PosWebhookLog.create({ posConfigId: cfg._id, userId: cfg.userId, restID, event: body.event, ok: false, message: 'Rejected — wrong or missing webhook key / token', payload: body }).catch(() => {});
      return res.status(401).json({ success: '0', message: 'Invalid token' });
    }
    if (body.event && body.event !== 'orderdetails') {
      await PosWebhookLog.create({ posConfigId: cfg._id, userId: cfg.userId, restID, event: body.event, ok: true, message: 'Ignored — unsupported event', payload: body }).catch(() => {});
      return res.json({ success: '1', message: 'Event ignored' });
    }

    const result = await processPetpoojaOrder(cfg, body);

    await PosWebhookLog.create({
      posConfigId: cfg._id, userId: cfg.userId, restID,
      event: body.event || 'orderdetails',
      orderId: String(body?.properties?.Order?.orderID || ''),
      orderStatus: String(body?.properties?.Order?.status || ''),
      ok: result.ok, message: result.message,
      linesTotal: result.linesTotal || 0, linesMapped: result.linesMapped || 0, mlDeducted: result.mlDeducted || 0,
      payload: body,
    }).catch(() => {});

    // Always 200 on a processed bill so Petpooja does not retry a good push
    return res.json({ success: result.ok ? '1' : '0', message: result.message });
  } catch (e) {
    await PosWebhookLog.create({ posConfigId: cfg?._id, restID, event: body?.event, ok: false, message: e.message, payload: body }).catch(() => {});
    return res.status(500).json({ success: '0', message: e.message });
  }
}

app.post('/api/pos/webhook/:configId', async (req, res) => {
  const cfg = await PosConfig.findById(req.params.configId).catch(() => null);
  return handlePetpoojaWebhook(req, res, cfg);
});
app.post('/api/pos/webhook', async (req, res) => handlePetpoojaWebhook(req, res, null));

// Reachability check — lets staff confirm the URL before handing it to Petpooja
app.get('/api/pos/webhook/:configId', async (req, res) => {
  const cfg = await PosConfig.findById(req.params.configId).catch(() => null);
  // Without the right key, don't even confirm the connection exists
  if (!cfg || (cfg.webhookKey && !(req.query?.key && safeEqual(String(req.query.key), cfg.webhookKey))))
    return res.status(404).json({ ok: false, message: 'Unknown POS connection' });
  res.json({ ok: true, message: 'Webhook endpoint is live. Petpooja should POST order details here.', posName: cfg.posName, restID: cfg.restID || null });
});

// ── Admin tree — SIROO staff acting for a customer ───────────────────────────
const A = [adminMiddleware];
app.get   ('/api/admin/pos/supported',        ...A, (_, res) => res.json(posSupported()));
app.get   ('/api/admin/pos/context',          ...A, posRoute((u) => posContext(u),   fromAdmin));
app.get   ('/api/admin/pos/configs',          ...A, posRoute(posListConfigs,         fromAdmin));
app.post  ('/api/admin/pos/configs',          ...A, posRoute(posCreateConfig,        fromAdmin));
app.put   ('/api/admin/pos/configs/:id',      ...A, posRoute(posUpdateConfig,        fromAdmin));
app.delete('/api/admin/pos/configs/:id',      ...A, posRoute(posDeleteConfig,        fromAdmin));
app.get   ('/api/admin/pos/unmapped',         ...A, posRoute(posListUnmapped,        fromAdmin));
app.put   ('/api/admin/pos/unmapped/:id/ignore', ...A, posRoute(posIgnoreUnmapped,   fromAdmin));
app.get   ('/api/admin/pos/mappings',         ...A, posRoute(posListMappings,        fromAdmin));
app.post  ('/api/admin/pos/mappings',         ...A, posRoute(posSaveMapping,         fromAdmin));
app.delete('/api/admin/pos/mappings/:id',     ...A, posRoute(posDeleteMapping,       fromAdmin));
app.get   ('/api/admin/pos/sales',            ...A, posRoute(posListSales,           fromAdmin));
app.get   ('/api/admin/pos/logs',             ...A, posRoute(posListLogs,            fromAdmin));
app.get   ('/api/admin/pos/nc',               ...A, posRoute(posListNc,              fromAdmin));
app.post  ('/api/admin/pos/reconcile',        ...A, posRoute(posReconcile,           fromAdmin));
app.get   ('/api/admin/pos/reconciliation',   ...A, posRoute(posReconciliation,      fromAdmin));

// ── Operator tree — same handlers, userId taken from their own token ─────────
const U = [authMiddleware, subscriptionCheck, requireSection('pos')];
app.get   ('/api/pos/supported',        ...U, (_, res) => res.json(posSupported()));
app.get   ('/api/pos/context',          ...U, posRoute((u) => posContext(u),   fromToken));
app.get   ('/api/pos/configs',          ...U, posRoute(posListConfigs,         fromToken));
app.post  ('/api/pos/configs',          ...U, posRoute(posCreateConfig,        fromToken));
app.put   ('/api/pos/configs/:id',      ...U, posRoute(posUpdateConfig,        fromToken));
app.delete('/api/pos/configs/:id',      ...U, posRoute(posDeleteConfig,        fromToken));
app.get   ('/api/pos/unmapped',         ...U, posRoute(posListUnmapped,        fromToken));
app.put   ('/api/pos/unmapped/:id/ignore', ...U, posRoute(posIgnoreUnmapped,   fromToken));
app.get   ('/api/pos/mappings',         ...U, posRoute(posListMappings,        fromToken));
app.post  ('/api/pos/mappings',         ...U, posRoute(posSaveMapping,         fromToken));
app.delete('/api/pos/mappings/:id',     ...U, posRoute(posDeleteMapping,       fromToken));
app.get   ('/api/pos/sales',            ...U, posRoute(posListSales,           fromToken));
app.get   ('/api/pos/logs',             ...U, posRoute(posListLogs,            fromToken));
app.get   ('/api/pos/nc',               ...U, posRoute(posListNc,              fromToken));
app.post  ('/api/pos/reconcile',        ...U, posRoute(posReconcile,           fromToken));
app.get   ('/api/pos/reconciliation',   ...U, posRoute(posReconciliation,      fromToken));

// ══════════════════════════════════════════════════════════════════════════════
// PAR STOCK ALERTS
// A par level belongs to one product at one bar, so the same bottle can carry
// a different threshold in Bar A and Bar B.
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/par-stock', authMiddleware, subscriptionCheck, requireSection('parstock','inventory'), guardOutlet, async (req, res) => {
  const { outletId, locationId } = req.query;
  const filter = { userId: req.auth.userId };
  if (outletId)   filter.outletId   = outletId;
  if (locationId) filter.locationId = locationId;
  const rows = await ParStock.find(filter);
  const products = await UserProduct.find({ userId: req.auth.userId }).select('name bottleSizeMl category');
  const byId = new Map(products.map(p => [String(p._id), p]));
  res.json(rows.map(r => {
    const p = byId.get(String(r.productId));
    return { ...r.toObject(), productName: p?.name || '', bottleSizeMl: p?.bottleSizeMl, category: p?.category };
  }));
});

app.post('/api/par-stock', authMiddleware, subscriptionCheck, requireSection('parstock','inventory'), guardOutlet, async (req, res) => {
  try {
    const { outletId, locationId, productId, minBottles } = req.body;
    if (!outletId || !locationId || !productId) return res.status(400).json({ error: 'Outlet, location and product are required' });
    const min = Number(minBottles);
    if (!Number.isFinite(min) || min < 0) return res.status(400).json({ error: 'Enter a valid minimum bottle count' });

    // Setting a new level clears any earlier dismissal
    const row = await ParStock.findOneAndUpdate(
      { userId: req.auth.userId, outletId, locationId, productId },
      { userId: req.auth.userId, outletId, locationId, productId, minBottles: min, active: true, dismissedAt: null },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    res.json(row);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/par-stock/:id', authMiddleware, subscriptionCheck, requireSection('parstock','inventory'), async (req, res) => {
  await ParStock.deleteOne({ _id: req.params.id, userId: req.auth.userId });
  res.json({ ok: true });
});

// Dismiss one alert. It re-arms on its own once stock climbs back to par,
// so ignoring it today does not silence it forever.
app.post('/api/par-stock/:id/dismiss', authMiddleware, subscriptionCheck, async (req, res) => {
  const row = await ParStock.findOneAndUpdate(
    { _id: req.params.id, userId: req.auth.userId }, { dismissedAt: new Date() }, { new: true });
  if (!row) return res.status(404).json({ error: 'Par level not found' });
  res.json({ ok: true });
});

// Dashboard feed: every par level currently breached.
app.get('/api/alerts', authMiddleware, subscriptionCheck, async (req, res) => {
  try {
    const allowed = allowedOutlets(req);
    const filter = { userId: req.auth.userId, active: true };
    if (allowed) filter.outletId = { $in: allowed };

    const pars = await ParStock.find(filter);
    if (!pars.length) return res.json({ alerts: [], count: 0 });

    const [outlets, products, stock] = await Promise.all([
      Outlet.find({ userId: req.auth.userId }),
      UserProduct.find({ userId: req.auth.userId }).select('name bottleSizeMl category'),
      Stock.find({ userId: req.auth.userId }),
    ]);
    const outletById  = new Map(outlets.map(o => [String(o._id), o]));
    const productById = new Map(products.map(p => [String(p._id), p]));
    const stockKey    = s => `${s.outletId}|${s.locationId}|${s.productId}`;
    const stockBy     = new Map(stock.map(s => [stockKey(s), s]));

    const alerts = [];
    for (const par of pars) {
      const line    = stockBy.get(`${par.outletId}|${par.locationId}|${par.productId}`);
      const current = line ? line.fullBottles : 0;

      // Re-arm: back at or above par, so clear the dismissal and stay quiet
      if (current >= par.minBottles) {
        if (par.dismissedAt) { par.dismissedAt = null; await par.save(); }
        continue;
      }
      if (par.dismissedAt) continue;

      const outlet  = outletById.get(String(par.outletId));
      const bar     = outlet?.bars?.find(b => String(b._id) === String(par.locationId));
      const product = productById.get(String(par.productId));
      alerts.push({
        _id: par._id,
        outletId: par.outletId, outletName: outlet?.name || '',
        locationId: par.locationId, locationName: bar?.name || '',
        locationType: bar?.type || '',
        productId: par.productId, productName: product?.name || 'Unknown',
        bottleSizeMl: product?.bottleSizeMl,
        minBottles: par.minBottles,
        currentBottles: current,
        shortBy: par.minBottles - current,
        severity: current === 0 ? 'out' : 'low',
      });
    }

    alerts.sort((a, b) =>
      (a.severity === 'out' ? 0 : 1) - (b.severity === 'out' ? 0 : 1) ||
      b.shortBy - a.shortBy);

    res.json({ alerts, count: alerts.length, outOfStock: alerts.filter(a => a.severity === 'out').length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// SALES REPORT
// Collapses every count of a bottle in the range into one line: opening from the
// first count, closing from the last, receipts in between as "Indent".
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/reports/sales', authMiddleware, subscriptionCheck, requireSection('salesreport','reports'), guardOutlet, async (req, res) => {
  try {
    const { outletId, locationId, productId, from, to } = req.query;
    if (!from || !to) return res.status(400).json({ error: 'Choose a date range' });

    const start = new Date(from); start.setHours(0, 0, 0, 0);
    const end   = new Date(to);   end.setHours(23, 59, 59, 999);

    const logFilter = { userId: req.auth.userId, type: { $in: ['closing','INVENTORY_CLOSING'] }, at: { $gte: start, $lte: end } };
    const allowed = allowedOutlets(req);
    if (allowed)    logFilter.outletId   = { $in: allowed };
    if (outletId)   logFilter.outletId   = outletId;
    if (locationId) logFilter.locationId = locationId;
    if (productId)  logFilter.productId  = productId;

    // Oldest first so the first row is the opening and the last is the closing
    const logs = await InventoryLog.find(logFilter).sort({ at: 1 });

    const histFilter = { userId: req.auth.userId, action: 'ADD_STOCK', at: { $gte: start, $lte: end } };
    if (allowed)    histFilter.outletId   = { $in: allowed };
    if (outletId)   histFilter.outletId   = outletId;
    if (locationId) histFilter.locationId = locationId;
    const receipts = await History.find(histFilter);

    // key on product + where it was counted, so one bottle in two bars stays separate
    const groups = new Map();
    for (const l of logs) {
      const key = `${l.productId}|${l.outletId}|${l.locationId}`;
      let g = groups.get(key);
      if (!g) {
        g = {
          productId: l.productId, productName: l.productName,
          category: l.category, bottleSizeMl: l.bottleSizeMl, cost: null,
          outletId: l.outletId, outletName: l.outletName,
          locationId: l.locationId, locationName: l.locationName,
          openingFullBottles: l.openingFullBottles ?? 0,
          openingOpenMl:      l.openingOpenMl ?? 0,
          openingAt:          l.at,
          closingFullBottles: 0, closingOpenMl: 0, closingAt: null,
          consumedMl: 0, totalSell: 0, entries: 0, indentBottles: 0,
        };
        groups.set(key, g);
      }
      g.consumedMl += Number(l.consumedMl || 0);
      g.totalSell  += Number(l.totalSell || 0);
      g.entries    += 1;
      g.closingFullBottles = l.closingFullBottles ?? 0;
      g.closingOpenMl      = l.closingOpenMl ?? 0;
      g.closingAt          = l.at;
    }

    // Every bottle that has a stock line at the chosen bar/outlet is listed,
    // even if it wasn't counted in the range (or holds zero stock).
    const stockFilter = { userId: req.auth.userId };
    if (allowed)    stockFilter.outletId   = { $in: allowed };
    if (outletId)   stockFilter.outletId   = outletId;
    if (locationId) stockFilter.locationId = String(locationId);
    if (productId)  stockFilter.productId  = productId;
    const lines = await Stock.find(stockFilter);
    const missing = lines.filter(l => !groups.has(`${l.productId}|${l.outletId}|${l.locationId}`));
    if (missing.length) {
      const [mProds, mOutlets] = await Promise.all([
        UserProduct.find({ _id: { $in: [...new Set(missing.map(l => String(l.productId)))] } }).select('name category bottleSizeMl'),
        Outlet.find({ _id: { $in: [...new Set(missing.map(l => String(l.outletId)))] } }),
      ]);
      const pById = new Map(mProds.map(p => [String(p._id), p]));
      const oById = new Map(mOutlets.map(o => [String(o._id), o]));
      for (const l of missing) {
        const p = pById.get(String(l.productId));
        if (!p) continue;                                   // product was deleted
        const o = oById.get(String(l.outletId));
        const bar = o?.bars?.find(b => String(b._id) === String(l.locationId));
        groups.set(`${l.productId}|${l.outletId}|${l.locationId}`, {
          productId: l.productId, productName: p.name,
          category: p.category, bottleSizeMl: p.bottleSizeMl, cost: null,
          outletId: l.outletId, outletName: o?.name || '',
          locationId: l.locationId, locationName: bar?.name || '',
          // not counted in the range — opening and closing are the current level
          openingFullBottles: l.fullBottles || 0, openingOpenMl: Math.round(l.openMl || 0), openingAt: null,
          closingFullBottles: l.fullBottles || 0, closingOpenMl: Math.round(l.openMl || 0), closingAt: null,
          consumedMl: 0, totalSell: 0, entries: 0, indentBottles: 0, notCounted: true,
        });
      }
    }

    // Indent — bottles received into that location during the window.
    // Matched on productId, falling back to name for rows written before
    // productId was persisted on history.
    for (const h of receipts) {
      const qty = Number(h.qty || h.quantity || 0);
      if (!qty) continue;
      for (const [key, g] of groups) {
        const sameSpot = String(g.outletId) === String(h.outletId) && String(g.locationId) === String(h.locationId);
        if (!sameSpot) continue;
        const sameProduct = h.productId
          ? String(g.productId) === String(h.productId)
          : (h.productName && g.productName === h.productName);
        if (sameProduct) { g.indentBottles += qty; break; }
      }
    }

    // Cost is not stored on the log, so resolve it from the product
    const prodIds = [...new Set([...groups.values()].map(g => String(g.productId)))];
    const prods = await UserProduct.find({ _id: { $in: prodIds } }).select('cost category');
    const costById = new Map(prods.map(p => [String(p._id), p]));
    for (const g of groups.values()) {
      const p = costById.get(String(g.productId));
      if (p) { g.cost = p.cost; if (!g.category) g.category = p.category; }
    }

    // POS side = the settlements banked by the counts in this range. Each one
    // covers the bills from the previous count up to that count, so a night that
    // runs past midnight is compared as one piece and every bill is used once.
    // Keyed the same way as the counts (product + outlet + bar).
    const stFilter = { userId: req.auth.userId, reason: 'count', periodTo: { $gte: start, $lte: end } };
    if (allowed)    stFilter.outletId   = { $in: allowed };
    if (outletId)   stFilter.outletId   = outletId;
    if (locationId) stFilter.locationId = String(locationId);
    if (productId)  stFilter.productId  = productId;
    const settlements = await PosSettlement.find(stFilter);

    const posByKey = new Map();
    for (const st of settlements) {
      const key = `${st.productId}|${st.outletId}|${st.locationId}`;
      const g = posByKey.get(key) || { ml: 0, qty: 0, value: 0, lines: 0, ncMl: 0, ncQty: 0, varianceMl: 0, varianceValue: 0, counts: 0 };
      g.ml            += st.posConsumedMl || 0;
      g.qty           += st.posQty || 0;
      g.value         += st.posSalesValue || 0;
      g.lines         += st.posLines || 0;
      g.ncMl          += st.ncMl || 0;
      g.ncQty         += st.ncQty || 0;
      g.varianceMl    += st.varianceMl || 0;
      g.varianceValue += st.varianceValue || 0;
      g.counts        += 1;
      posByKey.set(key, g);
    }

    const size = g => Math.max(1, Number(g.bottleSizeMl || 750));
    const rows = [...groups.values()].map(g => {
      const openingTotalMl = g.openingFullBottles * size(g) + g.openingOpenMl;
      const closingTotalMl = g.closingFullBottles * size(g) + g.closingOpenMl;
      const pos   = posByKey.get(`${g.productId}|${g.outletId}|${g.locationId}`)
                 || { ml: 0, qty: 0, value: 0, lines: 0, ncMl: 0, ncQty: 0, varianceMl: 0, varianceValue: 0, counts: 0 };
      const posMl = Math.round(pos.ml);
      // positive = more left the bottle than the POS billed (sold + NC)
      const varianceMl = Math.round(pos.varianceMl);
      const perMl      = Number(g.cost || 0) / size(g);
      const billedMl   = posMl + pos.ncMl;

      return {
        ...g,
        openingTotalMl, closingTotalMl,
        indentMl: g.indentBottles * size(g),
        consumedBottles: Math.round((g.consumedMl / size(g)) * 100) / 100,
        posConsumedMl: posMl,
        posQty: pos.qty,
        posSalesValue: Math.round(pos.value),
        posLines: pos.lines,
        ncMl: Math.round(pos.ncMl),
        ncQty: pos.ncQty,
        ncCostValue: Math.round(pos.ncMl * perMl),
        settlements: pos.counts,   // counts in range that were compared with the POS
        varianceMl,
        variancePct: billedMl > 0 ? Math.round((varianceMl / billedMl) * 1000) / 10 : null,
        varianceValue: Math.round(pos.varianceValue),
        // opening + received - closing, as a cross-check against the summed counts
        derivedConsumedMl: Math.max(0, openingTotalMl + g.indentBottles * size(g) - closingTotalMl),
      };
    }).sort((a, b) => (a.outletName || '').localeCompare(b.outletName || '')
                   || (a.locationName || '').localeCompare(b.locationName || '')
                   || (a.productName || '').localeCompare(b.productName || ''));

    res.json({
      from, to, rows,
      summary: {
        products: rows.length,
        entries:       rows.reduce((a, r) => a + r.entries, 0),
        totalConsumedMl: rows.reduce((a, r) => a + r.consumedMl, 0),
        totalIndent:   rows.reduce((a, r) => a + r.indentBottles, 0),
        totalSell:     rows.reduce((a, r) => a + r.totalSell, 0),
        totalPosMl:    rows.reduce((a, r) => a + r.posConsumedMl, 0),
        totalPosSales: rows.reduce((a, r) => a + r.posSalesValue, 0),
        totalNcMl:     rows.reduce((a, r) => a + r.ncMl, 0),
        totalNcQty:    rows.reduce((a, r) => a + r.ncQty, 0),
        totalNcCostValue: rows.reduce((a, r) => a + r.ncCostValue, 0),
        totalVarianceMl:    rows.reduce((a, r) => a + r.varianceMl, 0),
        totalVarianceValue: rows.reduce((a, r) => a + r.varianceValue, 0),
        posLinked:     rows.filter(r => r.posLines > 0).length,
      },
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// POS SALES REPORT — what the till says, on its own terms
// Revenue here is the billed amount, not cost x consumption.
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/reports/pos-sales', authMiddleware, subscriptionCheck, requireSection('pos','reports'), guardOutlet, async (req, res) => {
  try {
    const { outletId, locationId, from, to, groupBy = 'product' } = req.query;
    if (!from || !to) return res.status(400).json({ error: 'Choose a date range' });

    const start = new Date(from); start.setHours(0, 0, 0, 0);
    const end   = new Date(to);   end.setHours(23, 59, 59, 999);

    const filter = { userId: req.auth.userId, soldAt: { $gte: start, $lte: end } };
    const allowed = allowedOutlets(req);
    if (allowed)    filter.siRooOutletId = { $in: allowed };
    if (outletId)   filter.siRooOutletId = outletId;
    if (locationId) filter.locationId    = String(locationId);

    const sales   = await PosSale.find(filter).sort({ soldAt: -1 });
    const live    = sales.filter(s => !s.reversed);
    const outlets = await Outlet.find({ userId: req.auth.userId });
    const outletName = id => outlets.find(o => String(o._id) === String(id))?.name || '';

    const groups = new Map();
    for (const s of live) {
      const key = groupBy === 'item'
        ? `${s.kind}|${s.posItemId}|${s.locationId}`
        : `${s.bottleId || 'unmapped'}|${s.locationId}`;
      const g = groups.get(key) || {
        posItemId: s.posItemId, posItemName: s.posItemName, kind: s.kind,
        category: s.posCategory || '',
        bottleId: s.bottleId, productName: null,
        outletId: s.siRooOutletId, outletName: outletName(s.siRooOutletId),
        locationId: s.locationId, locationName: s.locationName || '',
        qty: 0, ml: 0, value: 0, lines: 0, mapped: s.mapped,
      };
      g.qty   += s.quantity || 0;
      g.ml    += (s.quantity || 0) * (s.mlPerServe || 0);
      g.value += s.lineTotal || 0;
      g.lines += 1;
      groups.set(key, g);
    }

    // Name the SIROO bottle behind each mapped line
    const ids = [...new Set([...groups.values()].map(g => g.bottleId).filter(Boolean).map(String))];
    const prods = await UserProduct.find({ _id: { $in: ids } }).select('name category bottleSizeMl cost');
    const prodById = new Map(prods.map(p => [String(p._id), p]));
    for (const g of groups.values()) {
      const p = prodById.get(String(g.bottleId));
      if (p) {
        g.productName  = p.name;
        g.bottleSizeMl = p.bottleSizeMl;
        if (!g.category) g.category = p.category;
        g.costOfSales  = Math.round(g.ml * (Number(p.cost || 0) / Math.max(1, p.bottleSizeMl || 750)));
      }
      g.ml = Math.round(g.ml);
      g.value = Math.round(g.value);
    }

    const rows = [...groups.values()].sort((a, b) => b.value - a.value);

    // A quick read on how the bills were settled
    const byPayment = {};
    for (const s of live) byPayment[s.paymentType || 'Unknown'] = (byPayment[s.paymentType || 'Unknown'] || 0) + (s.lineTotal || 0);
    const bySource = {};
    for (const s of live) bySource[s.orderFrom || 'POS'] = (bySource[s.orderFrom || 'POS'] || 0) + (s.lineTotal || 0);

    res.json({
      from, to, groupBy, rows,
      byPayment, bySource,
      summary: {
        orders:    new Set(live.map(s => s.posOrderId)).size,
        lines:     live.length,
        cancelled: sales.filter(s => s.reversed).length,
        unmapped:  live.filter(s => !s.mapped).length,
        totalQty:  live.reduce((a, s) => a + (s.quantity || 0), 0),
        totalMl:   Math.round(rows.reduce((a, r) => a + r.ml, 0)),
        totalValue:Math.round(rows.reduce((a, r) => a + r.value, 0)),
        costOfSales: rows.reduce((a, r) => a + (r.costOfSales || 0), 0),
      },
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// EXCISE REGISTER
// The standard opening / receipts / total / consumed / closing shape that state
// excise returns are built from. Column names vary by state, so this is a
// general register rather than any one state's prescribed form.
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/reports/excise', authMiddleware, subscriptionCheck, requireSection('excise','reports'), guardOutlet, async (req, res) => {
  try {
    const { outletId, from, to, groupBy = 'brand' } = req.query;
    if (!from || !to) return res.status(400).json({ error: 'Choose a date range' });

    const start = new Date(from); start.setHours(0, 0, 0, 0);
    const end   = new Date(to);   end.setHours(23, 59, 59, 999);

    const allowed = allowedOutlets(req);
    const base = { userId: req.auth.userId };
    if (allowed)  base.outletId = { $in: allowed };
    if (outletId) base.outletId = outletId;

    const [logs, receipts, outlets] = await Promise.all([
      InventoryLog.find({ ...base, type: { $in: ['closing','INVENTORY_CLOSING'] }, at: { $gte: start, $lte: end } }).sort({ at: 1 }),
      History.find({ ...base, action: 'ADD_STOCK', at: { $gte: start, $lte: end } }),
      Outlet.find({ userId: req.auth.userId }),
    ]);

    // Roll everything up to the whole premises — excise returns are per licence,
    // not per bar, so bar-level splits are summed away here.
    const byProduct = new Map();
    for (const l of logs) {
      const key = String(l.productId);
      let g = byProduct.get(key);
      if (!g) {
        g = {
          productId: l.productId, brand: l.productName, category: l.category || 'Uncategorised',
          bottleSizeMl: l.bottleSizeMl || 750,
          openingBottles: 0, openingMl: 0, closingBottles: 0, closingMl: 0,
          receiptBottles: 0, consumedMl: 0,
          _seenSpots: new Set(), _lastBySpot: new Map(),
        };
        byProduct.set(key, g);
      }
      const spot = `${l.outletId}|${l.locationId}`;
      if (!g._seenSpots.has(spot)) {
        g._seenSpots.add(spot);
        g.openingBottles += l.openingFullBottles ?? 0;
        g.openingMl      += l.openingOpenMl ?? 0;
      }
      g._lastBySpot.set(spot, l);
      g.consumedMl += Number(l.consumedMl || 0);
    }
    for (const g of byProduct.values()) {
      for (const l of g._lastBySpot.values()) {
        g.closingBottles += l.closingFullBottles ?? 0;
        g.closingMl      += l.closingOpenMl ?? 0;
      }
      delete g._seenSpots; delete g._lastBySpot;
    }
    for (const h of receipts) {
      const qty = Number(h.qty || h.quantity || 0);
      if (!qty) continue;
      const g = h.productId ? byProduct.get(String(h.productId))
                            : [...byProduct.values()].find(x => x.brand === h.productName);
      if (g) g.receiptBottles += qty;
    }

    const rows = [...byProduct.values()].map(g => {
      const size = Math.max(1, g.bottleSizeMl);
      const openingTotalMl = g.openingBottles * size + g.openingMl;
      const receiptMl      = g.receiptBottles * size;
      const closingTotalMl = g.closingBottles * size + g.closingMl;
      return {
        brand: g.brand, category: g.category, bottleSizeMl: size,
        openingBottles: g.openingBottles, openingMl: Math.round(g.openingMl),
        openingTotalMl: Math.round(openingTotalMl),
        receiptBottles: g.receiptBottles, receiptMl,
        totalAvailableMl: Math.round(openingTotalMl + receiptMl),
        totalAvailableBottles: Math.round(((openingTotalMl + receiptMl) / size) * 100) / 100,
        consumedMl: Math.round(g.consumedMl),
        consumedBottles: Math.round((g.consumedMl / size) * 100) / 100,
        closingBottles: g.closingBottles, closingMl: Math.round(g.closingMl),
        closingTotalMl: Math.round(closingTotalMl),
        // Opening + receipts - consumed should equal closing; anything else is a discrepancy
        balanceCheckMl: Math.round(openingTotalMl + receiptMl - g.consumedMl - closingTotalMl),
      };
    });

    if (groupBy === 'category') {
      const byCat = new Map();
      for (const r of rows) {
        const k = r.category;
        const g = byCat.get(k) || { category: k, brands: 0, openingTotalMl: 0, receiptMl: 0, consumedMl: 0, closingTotalMl: 0 };
        g.brands += 1; g.openingTotalMl += r.openingTotalMl; g.receiptMl += r.receiptMl;
        g.consumedMl += r.consumedMl; g.closingTotalMl += r.closingTotalMl;
        byCat.set(k, g);
      }
      return res.json({ from, to, groupBy, rows: [...byCat.values()].sort((a, b) => a.category.localeCompare(b.category)) });
    }

    rows.sort((a, b) => (a.category || '').localeCompare(b.category || '') || (a.brand || '').localeCompare(b.brand || ''));

    const premises = outletId ? outlets.find(o => String(o._id) === String(outletId)) : null;
    res.json({
      from, to, groupBy,
      premises: premises ? { name: premises.name, address: premises.address || '', licenceNo: premises.licenceNo || '' }
                         : { name: 'All outlets', address: '', licenceNo: '' },
      rows,
      summary: {
        brands: rows.length,
        openingTotalMl: rows.reduce((a, r) => a + r.openingTotalMl, 0),
        receiptMl:      rows.reduce((a, r) => a + r.receiptMl, 0),
        consumedMl:     rows.reduce((a, r) => a + r.consumedMl, 0),
        closingTotalMl: rows.reduce((a, r) => a + r.closingTotalMl, 0),
        discrepancies:  rows.filter(r => Math.abs(r.balanceCheckMl) > 50).length,
      },
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// MAHARASHTRA EXCISE — SCM PORTAL EXPORTS
//
// The portal is upload-driven. Two files matter:
//   Opening stock : Local Item Code | Brand Name | Size | Qty(Case) | Qty(Loose Bottle)
//   Daily sales   : Sale Date | Local Item Code | Brand Name | Size | Qty(Case) | Qty(Loose Bottle)
// The portal then generates Form F.L.R. 1A/2A/3A (Rule 15) from what we upload.
//
// Quantities are Case + Loose Bottle, never millilitres, so each product needs a
// Local Item Code and a bottles-per-case figure before it can be reported.
// ══════════════════════════════════════════════════════════════════════════════

// Portal expects DD/MM/YYYY
function scmDate(d) {
  const x = new Date(d);
  return `${String(x.getDate()).padStart(2,'0')}/${String(x.getMonth()+1).padStart(2,'0')}/${x.getFullYear()}`;
}

// Whole cases plus the remainder as loose bottles.
function toCases(bottles, perCase) {
  const n = Math.max(0, Math.round(Number(bottles) || 0));
  const p = Number(perCase) || 0;
  if (p <= 1) return { cases: 0, loose: n };
  return { cases: Math.floor(n / p), loose: n % p };
}

function sendXlsx(res, filename, rows) {
  const buf = buildXlsx(rows);
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Length', buf.length);
  res.end(buf);
}

// ── Catalogue lookup, so staff can find the portal's code for a brand ────────
app.get('/api/scm/items', authMiddleware, subscriptionCheck, async (req, res) => {
  const { q, itemType, limit = 40 } = req.query;
  const filter = {};
  if (itemType) filter.itemType = itemType;
  if (q && String(q).trim()) {
    const rx = new RegExp(String(q).trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
    filter.$or = [{ itemName: rx }, { localItemCode: rx }];
  }
  res.json(await ScmItem.find(filter).sort({ itemName: 1, bottleSizeMl: 1 }).limit(Math.min(200, Number(limit) || 40)));
});

app.get('/api/scm/item-types', authMiddleware, subscriptionCheck, async (_, res) => {
  res.json(await ScmItem.distinct('itemType'));
});

// Which products still cannot be reported
app.get('/api/scm/mapping-status', authMiddleware, subscriptionCheck, requireSection('excise','reports','products'), async (req, res) => {
  const products = await UserProduct.find({ userId: req.auth.userId, active: { $ne: false } })
    .select('name category bottleSizeMl scmItemCode scmBrandName scmSize bottlesPerCase');
  const mapped   = products.filter(p => p.scmItemCode);
  const unmapped = products.filter(p => !p.scmItemCode);
  const noCase   = mapped.filter(p => !p.bottlesPerCase || p.bottlesPerCase < 1);
  res.json({
    products, mapped: mapped.length, unmapped: unmapped.length,
    missingCaseSize: noCase.length,
    ready: unmapped.length === 0 && noCase.length === 0,
    unmappedList: unmapped.map(p => ({ _id: p._id, name: p.name, bottleSizeMl: p.bottleSizeMl })),
    missingCaseList: noCase.map(p => ({ _id: p._id, name: p.name, scmItemCode: p.scmItemCode })),
  });
});

// Link a product to a portal item
app.post('/api/scm/map', authMiddleware, subscriptionCheck, requireSection('excise','reports','products'), async (req, res) => {
  try {
    const { productId, localItemCode, bottlesPerCase } = req.body;
    const product = await UserProduct.findOne({ _id: productId, userId: req.auth.userId });
    if (!product) return res.status(404).json({ error: 'Product not found' });

    if (localItemCode === null || localItemCode === '') {
      product.scmItemCode = undefined; product.scmBrandName = undefined; product.scmSize = undefined;
      await product.save();
      return res.json(product);
    }

    const item = await ScmItem.findOne({ localItemCode: String(localItemCode).trim() });
    if (!item) return res.status(400).json({ error: 'That Local Item Code is not in the excise catalogue' });

    product.scmItemCode  = item.localItemCode;
    product.scmBrandName = item.itemName;
    product.scmSize      = item.uom;
    const per = Number(bottlesPerCase) || item.bottlesPerCase || 0;
    if (per > 0) product.bottlesPerCase = per;
    await product.save();
    res.json(product);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Shared figure builder for both exports ───────────────────────────────────
// Sales are taken from closing counts, converted from millilitres to whole
// bottles, because the portal only accepts case/bottle counts.
async function scmSalesRows(userId, { outletId, from, to, allowed }) {
  const start = new Date(from); start.setHours(0, 0, 0, 0);
  const end   = new Date(to);   end.setHours(23, 59, 59, 999);

  const filter = { userId, type: { $in: ['closing','INVENTORY_CLOSING'] }, at: { $gte: start, $lte: end } };
  if (allowed)  filter.outletId = { $in: allowed };
  if (outletId) filter.outletId = outletId;

  const logs = await InventoryLog.find(filter);
  const products = await UserProduct.find({ userId }).select('name scmItemCode scmBrandName scmSize bottlesPerCase bottleSizeMl');
  const byId = new Map(products.map(p => [String(p._id), p]));

  // Sum consumption per product per calendar day
  const perDay = new Map();
  for (const l of logs) {
    const p = byId.get(String(l.productId));
    if (!p || !p.scmItemCode) continue;
    const day = scmDate(l.at);
    const key = `${day}|${p.scmItemCode}`;
    const g = perDay.get(key) || { day, product: p, ml: 0 };
    g.ml += Number(l.consumedMl || 0);
    perDay.set(key, g);
  }

  const rows = [], skipped = [];
  for (const g of [...perDay.values()].sort((a, b) => a.day.localeCompare(b.day) || a.product.name.localeCompare(b.product.name))) {
    const size = Math.max(1, Number(g.product.bottleSizeMl || 750));
    const bottles = Math.round(g.ml / size);
    if (bottles <= 0) continue;
    const per = Number(g.product.bottlesPerCase) || 0;
    if (per < 1) { skipped.push(g.product.name); continue; }
    const { cases, loose } = toCases(bottles, per);
    rows.push([g.day, g.product.scmItemCode, g.product.scmBrandName, g.product.scmSize, cases, loose]);
  }
  return { rows, skipped: [...new Set(skipped)] };
}

// ── Daily sales upload file ──────────────────────────────────────────────────
app.get('/api/reports/excise/scm-sales.xlsx', authMiddleware, subscriptionCheck, requireSection('excise','reports'), guardOutlet, async (req, res) => {
  try {
    const { outletId, from, to } = req.query;
    if (!from || !to) return res.status(400).json({ error: 'Choose a date range' });
    const { rows } = await scmSalesRows(req.auth.userId, { outletId, from, to, allowed: allowedOutlets(req) });
    sendXlsx(res, `SCM_Sales_${from}_to_${to}.xlsx`,
      [['Sale Date','Local Item Code','Brand Name','Size','Quantity(Case)','Quantity(Loose Bottle)'], ...rows]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Opening stock upload file ────────────────────────────────────────────────
// Snapshot of what is physically on hand right now, across every location.
app.get('/api/reports/excise/scm-opening.xlsx', authMiddleware, subscriptionCheck, requireSection('excise','reports'), guardOutlet, async (req, res) => {
  try {
    const { outletId } = req.query;
    const filter = { userId: req.auth.userId };
    const allowed = allowedOutlets(req);
    if (allowed)  filter.outletId = { $in: allowed };
    if (outletId) filter.outletId = outletId;

    const lines = await Stock.find(filter);
    const products = await UserProduct.find({ userId: req.auth.userId })
      .select('name scmItemCode scmBrandName scmSize bottlesPerCase bottleSizeMl');
    const byId = new Map(products.map(p => [String(p._id), p]));

    // The portal reports per licence, so bar and stock room are summed together
    const totals = new Map();
    for (const l of lines) {
      const p = byId.get(String(l.productId));
      if (!p || !p.scmItemCode) continue;
      const g = totals.get(p.scmItemCode) || { product: p, bottles: 0 };
      const size = Math.max(1, Number(p.bottleSizeMl || 750));
      g.bottles += l.fullBottles + (l.openMl > 0 ? l.openMl / size : 0);
      totals.set(p.scmItemCode, g);
    }

    const rows = [];
    for (const g of [...totals.values()].sort((a, b) => a.product.scmBrandName.localeCompare(b.product.scmBrandName))) {
      const per = Number(g.product.bottlesPerCase) || 0;
      if (per < 1) continue;
      const { cases, loose } = toCases(Math.round(g.bottles), per);
      if (cases === 0 && loose === 0) continue;
      rows.push([g.product.scmItemCode, g.product.scmBrandName, g.product.scmSize, cases, loose]);
    }

    sendXlsx(res, `SCM_Opening_${new Date().toISOString().slice(0,10)}.xlsx`,
      [['Local Item Code','Brand Name','Size','Quantity(Case)','Quantity(Loose Bottle)'], ...rows]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── On-screen preview, so the numbers can be checked before uploading ────────
app.get('/api/reports/excise/scm-preview', authMiddleware, subscriptionCheck, requireSection('excise','reports'), guardOutlet, async (req, res) => {
  try {
    const { outletId, from, to } = req.query;
    if (!from || !to) return res.status(400).json({ error: 'Choose a date range' });
    const { rows, skipped } = await scmSalesRows(req.auth.userId, { outletId, from, to, allowed: allowedOutlets(req) });

    const status = await UserProduct.find({ userId: req.auth.userId, active: { $ne: false } })
      .select('name scmItemCode bottlesPerCase');
    const unmapped = status.filter(p => !p.scmItemCode).map(p => p.name);
    const noCase   = status.filter(p => p.scmItemCode && !(p.bottlesPerCase > 0)).map(p => p.name);

    res.json({
      from, to,
      header: ['Sale Date','Local Item Code','Brand Name','Size','Quantity(Case)','Quantity(Loose Bottle)'],
      rows: rows.map(r => ({ saleDate:r[0], localItemCode:r[1], brandName:r[2], size:r[3], cases:r[4], loose:r[5] })),
      blockers: { unmapped, missingCaseSize: noCase, skippedInExport: skipped },
      ready: unmapped.length === 0 && noCase.length === 0,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Catalogue seeding, from lib/scm-items.json ───────────────────────────────
async function seedScmItems() {
  try {
    const n = await ScmItem.estimatedDocumentCount();
    if (n > 0) { console.log(`SCM catalogue: ${n} items already loaded`); return; }
    const { readFileSync } = await import('fs');
    const { fileURLToPath } = await import('url');
    const { dirname, join } = await import('path');
    const here = dirname(fileURLToPath(import.meta.url));
    const items = JSON.parse(readFileSync(join(here, 'lib', 'scm-items.json'), 'utf8'));
    await ScmItem.insertMany(items, { ordered: false }).catch(() => {});
    console.log(`SCM catalogue seeded: ${await ScmItem.estimatedDocumentCount()} items`);
  } catch (e) {
    console.warn('SCM catalogue not seeded:', e.message);
  }
}

// ── Admin: sub-user management on behalf of a customer ───────────────────────
// Creation moved here — the brand owner can view their staff but not change them.
app.get('/api/admin/sections', adminMiddleware, (_, res) => res.json(SECTIONS));

app.get('/api/admin/sub-users', adminMiddleware, async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return res.status(400).json({ error: 'Select a customer first' });
    res.json(await SubUser.find({ userId }).select('-passwordHash').sort({ createdAt: -1 }));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/sub-users', adminMiddleware, async (req, res) => {
  try {
    const { userId, username, password, name, phone, email, designation,
            outletAccess = [], barAccess = [], sections = [], financialAccess } = req.body;

    if (!userId) return res.status(400).json({ error: 'Select a customer first' });
    const owner = await User.findById(userId);
    if (!owner)  return res.status(404).json({ error: 'Customer not found' });

    if (!username || !String(username).trim()) return res.status(400).json({ error: 'Login ID is required' });
    if (!password || String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    if (!name || !String(name).trim())         return res.status(400).json({ error: 'Name is required' });

    const uname = String(username).trim();
    if (await SubUser.findOne({ username: exactCi(uname) }))
      return res.status(409).json({ error: `Login ID "${uname}" is already taken` });
    if (await User.findOne({ email: uname.toLowerCase() }))
      return res.status(409).json({ error: 'That login ID collides with an owner account' });

    const owned = await Outlet.find({ userId }).select('_id');
    const ownedIds = owned.map(o => String(o._id));

    const sub = await SubUser.create({
      userId, username: uname,
      passwordHash: await bcrypt.hash(String(password), 12),
      name: String(name).trim(), phone, email, designation,
      outletAccess: (outletAccess || []).map(String).filter(id => ownedIds.includes(id)),
      barAccess,
      sections: (sections || []).filter(s => SECTION_KEYS.includes(s)),
      financialAccess: Boolean(financialAccess),
      status: 'Active', lastActive: 'New',
    });
    const out = sub.toObject(); delete out.passwordHash;
    res.json(out);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/sub-users/:id', adminMiddleware, async (req, res) => {
  try {
    const sub = await SubUser.findById(req.params.id);
    if (!sub) return res.status(404).json({ error: 'Sub-user not found' });

    const { username, password, name, phone, email, designation,
            outletAccess, barAccess, sections, financialAccess, status } = req.body;

    if (username && String(username).trim() !== sub.username) {
      const uname = String(username).trim();
      if (await SubUser.findOne({ username: exactCi(uname), _id: { $ne: sub._id } }))
        return res.status(409).json({ error: `Login ID "${uname}" is already taken` });
      sub.username = uname;
    }
    if (password) {
      if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
      sub.passwordHash = await bcrypt.hash(String(password), 12);
      sub.tokensValidAfter = new Date();          // signs this staff member out everywhere
    }
    if (name !== undefined)            sub.name = name;
    if (phone !== undefined)           sub.phone = phone;
    if (email !== undefined)           sub.email = email;
    if (designation !== undefined)     sub.designation = designation;
    if (barAccess !== undefined)       sub.barAccess = barAccess;
    if (status !== undefined)          sub.status = status;
    if (financialAccess !== undefined) sub.financialAccess = Boolean(financialAccess);
    if (sections !== undefined)        sub.sections = (sections || []).filter(s => SECTION_KEYS.includes(s));
    if (outletAccess !== undefined) {
      const owned = await Outlet.find({ userId: sub.userId }).select('_id');
      const ownedIds = owned.map(o => String(o._id));
      sub.outletAccess = (outletAccess || []).map(String).filter(id => ownedIds.includes(id));
    }
    await sub.save();
    const out = sub.toObject(); delete out.passwordHash;
    res.json(out);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/sub-users/:id', adminMiddleware, async (req, res) => {
  await SubUser.deleteOne({ _id: req.params.id });
  res.json({ ok: true });
});

app.get('/api/admin/customer-outlets', adminMiddleware, async (req, res) => {
  const { userId } = req.query;
  if (!userId) return res.status(400).json({ error: 'Select a customer first' });
  const outlets = await Outlet.find({ userId }).sort({ name: 1 });
  res.json(outlets.map(o => ({ _id: o._id, name: o.name })));
});

// ══════════════════════════════════════════════════════════════════════════════
// POS MIRROR — read-only ledger the operator can browse per bar
// ══════════════════════════════════════════════════════════════════════════════

// Is there anything to show? Drives whether the dashboard card appears.
app.get('/api/pos-stock/status', authMiddleware, subscriptionCheck, async (req, res) => {
  const cfgs = await PosConfig.find({ userId: req.auth.userId, active: true }).select('siRooOutletId label lastEventAt');
  res.json({
    connected: cfgs.length > 0,
    outletIds: cfgs.map(c => String(c.siRooOutletId)),
    connections: cfgs.map(c => ({ label: c.label, lastEventAt: c.lastEventAt })),
  });
});

// The mirror for one bar, alongside what the scale currently says.
app.get('/api/pos-stock', authMiddleware, subscriptionCheck, requireSection('pos','inventory'), guardOutlet, async (req, res) => {
  try {
    const { outletId, locationId } = req.query;
    if (!outletId || !locationId) return res.status(400).json({ error: 'Choose an outlet and a bar' });

    const [mirror, real, products, outlet] = await Promise.all([
      PosStock.find({ userId: req.auth.userId, outletId, locationId }),
      Stock.find({ userId: req.auth.userId, outletId, locationId }),
      UserProduct.find({ userId: req.auth.userId }).select('name category bottleSizeMl cost trackingMode'),
      Outlet.findById(outletId),
    ]);
    const prodById = new Map(products.map(p => [String(p._id), p]));
    const realById = new Map(real.map(s => [String(s.productId), s]));

    const rows = mirror.map(m => {
      const p    = prodById.get(String(m.productId));
      const size = Math.max(1, Number(p?.bottleSizeMl || 750));
      const r    = realById.get(String(m.productId));

      const posTotalMl  = m.fullBottles * size + m.openMl;
      const realTotalMl = r ? r.fullBottles * size + r.openMl : 0;
      const gapMl       = realTotalMl - posTotalMl;   // negative = less on the shelf than POS expects
      const perMl       = Number(p?.cost || 0) / size;

      return {
        _id: m._id, productId: m.productId,
        productName: p?.name || 'Unknown', category: p?.category || '',
        bottleSizeMl: size, trackingMode: p?.trackingMode || 'physical',
        posFullBottles: m.fullBottles, posOpenMl: Math.round(m.openMl), posTotalMl,
        realFullBottles: r?.fullBottles ?? 0, realOpenMl: Math.round(r?.openMl ?? 0), realTotalMl,
        gapMl, gapValue: Math.round(gapMl * perMl),
        posConsumedMl: Math.round(m.posConsumedMl || 0),
        posSalesValue: Math.round(m.posSalesValue || 0),
        posLines: m.posLines || 0,
        ncMl: Math.round(m.ncMl || 0),
        ncQty: m.ncQty || 0,
        anchoredAt: m.anchoredAt, lastSaleAt: m.lastSaleAt,
      };
    }).sort((a, b) => a.productName.localeCompare(b.productName));

    const bar = outlet?.bars?.find(b => String(b._id) === String(locationId));
    res.json({
      outletName: outlet?.name || '', locationName: bar?.name || '',
      anchoredAt: rows[0]?.anchoredAt || null,
      rows,
      summary: {
        products: rows.length,
        posConsumedMl: rows.reduce((a, r) => a + r.posConsumedMl, 0),
        posSalesValue: rows.reduce((a, r) => a + r.posSalesValue, 0),
        posLines:      rows.reduce((a, r) => a + r.posLines, 0),
        ncMl:          rows.reduce((a, r) => a + r.ncMl, 0),
        shortOnShelf:  rows.filter(r => r.gapMl < 0).length,
        negativeMirror:rows.filter(r => r.posTotalMl < 0).length,
      },
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Orders that hit this bar, newest first.
app.get('/api/pos-stock/orders', authMiddleware, subscriptionCheck, requireSection('pos','inventory'), guardOutlet, async (req, res) => {
  try {
    const { outletId, locationId, from, to, limit = 200 } = req.query;
    const filter = { userId: req.auth.userId, mapped: true };
    if (outletId)   filter.siRooOutletId = outletId;
    if (locationId) filter.locationId    = String(locationId);
    if (from || to) {
      filter.soldAt = {};
      if (from) filter.soldAt.$gte = new Date(from);
      if (to)   { const d = new Date(to); d.setHours(23,59,59,999); filter.soldAt.$lte = d; }
    }
    const sales = await PosSale.find(filter).sort({ soldAt: -1 }).limit(Math.min(500, Number(limit) || 200));
    const live  = sales.filter(s => !s.reversed);
    res.json({
      sales,
      summary: {
        lines: sales.length,
        cancelled: sales.filter(s => s.reversed).length,
        totalMl:    live.reduce((a, s) => a + (s.quantity || 0) * (s.mlPerServe || 0), 0),
        totalValue: live.reduce((a, s) => a + (s.lineTotal || 0), 0),
      },
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Settle without waiting for a count — mirror is forced to the current shelf level.
app.post('/api/pos-stock/settle', authMiddleware, subscriptionCheck, requireSection('pos','inventory'), guardOutlet, async (req, res) => {
  try {
    const { outletId, locationId, productId } = req.body;
    if (!outletId || !locationId) return res.status(400).json({ error: 'Choose an outlet and a bar' });

    const filter = { userId: req.auth.userId, outletId, locationId };
    if (productId) filter.productId = productId;
    const mirrors = await PosStock.find(filter);

    const settled = [];
    for (const m of mirrors) {
      const real = await Stock.findOne({ userId: req.auth.userId, outletId, locationId, productId: m.productId });
      const p    = await UserProduct.findById(m.productId).catch(() => null);
      const size = Math.max(1, Number(p?.bottleSizeMl || 750));

      // Settling by hand has no fresh count behind it, so the physical figure is
      // taken as whatever the shelf currently reads.
      const mirrorMl = m.fullBottles * size + m.openMl;
      const realMl   = real ? real.fullBottles * size + real.openMl : 0;

      const s = await settleMirror({
        userId: req.auth.userId, outletId, locationId, productId: m.productId,
        actualFullBottles: real?.fullBottles ?? 0,
        actualOpenMl: real?.openMl ?? 0,
        physicalConsumedMl: Math.max(0, Number(m.posConsumedMl || 0) + Number(m.ncMl || 0) + (mirrorMl - realMl)),
        reason: 'manual',
      });
      if (s) settled.push(s);
    }
    res.json({ ok: true, settled: settled.length, settlements: settled });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Past settlements — the variance history for a bar.
app.get('/api/pos-stock/settlements', authMiddleware, subscriptionCheck, requireSection('pos','inventory','reports'), guardOutlet, async (req, res) => {
  const { outletId, locationId, from, to } = req.query;
  const filter = { userId: req.auth.userId };
  if (outletId)   filter.outletId   = outletId;
  if (locationId) filter.locationId = String(locationId);
  if (from || to) {
    filter.periodTo = {};
    if (from) filter.periodTo.$gte = new Date(from);
    if (to)   { const d = new Date(to); d.setHours(23,59,59,999); filter.periodTo.$lte = d; }
  }
  const records = await PosSettlement.find(filter).sort({ periodTo: -1 }).limit(500);
  res.json({
    records,
    summary: {
      count: records.length,
      totalVarianceMl:    records.reduce((a, r) => a + (r.varianceMl || 0), 0),
      totalVarianceValue: records.reduce((a, r) => a + (r.varianceValue || 0), 0),
      totalPosSales:      records.reduce((a, r) => a + (r.posSalesValue || 0), 0),
      totalNcMl:          records.reduce((a, r) => a + (r.ncMl || 0), 0),
      excess: records.filter(r => (r.varianceMl || 0) > 0).length,
      short:  records.filter(r => (r.varianceMl || 0) < 0).length,
    },
  });
});

// Flip a product between physical counting and POS-driven stock.
app.put('/api/products/:id/tracking-mode', authMiddleware, subscriptionCheck, requireSection('products','pos'), async (req, res) => {
  try {
    const { trackingMode } = req.body;
    if (!['physical','pos'].includes(trackingMode)) return res.status(400).json({ error: 'Invalid tracking mode' });
    const p = await UserProduct.findOneAndUpdate(
      { _id: req.params.id, userId: req.auth.userId }, { trackingMode }, { new: true });
    if (!p) return res.status(404).json({ error: 'Product not found' });
    res.json(p);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── Fallbacks ───────────────────────────────────────────────────────────────
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => {
  if (err?.type === 'entity.parse.failed') return res.status(400).json({ error: 'Malformed JSON' });
  if (err?.type === 'entity.too.large')    return res.status(413).json({ error: 'Request is too large' });
  console.error('[error]', err);
  res.status(err?.status || 500).json({ error: IS_PROD ? 'Something went wrong' : (err?.message || 'Server error') });
});

// ─── Start ───────────────────────────────────────────────────────────────────
mongoose.set('autoIndex', false);
mongoose.connect(MONGO_URI)
  .then(async () => {
    console.log('MongoDB connected:', MONGO_URI_SAFE);
    const collectionsToClear = ['userproducts', 'masterbottles', 'outlets', 'stocks', 'users', 'subusers', 'historys', 'inventorylogs'];
    for (const col of collectionsToClear) {
      try {
        const indexes = await mongoose.connection.collection(col).indexes();
        for (const idx of indexes) {
          if (idx.name === '_id_') continue;
          try {
            await mongoose.connection.collection(col).dropIndex(idx.name);
            console.log('Dropped stale index:', idx.name, 'on', col);
          } catch (e) {}
        }
      } catch (e) {}
    }
    try { await mongoose.connection.collection('stocks').createIndex({ userId: 1, outletId: 1, locationId: 1, productId: 1 }, { unique: true, name: 'stock_unique' }); } catch(e) {}
    try { await mongoose.connection.collection('masterbottles').createIndex({ barcode: 1 }, { unique: true, name: 'barcode_unique' }); } catch(e) {}
    try { await mongoose.connection.collection('users').createIndex({ email: 1 }, { unique: true, name: 'email_unique' }); } catch(e) {}
    try { await mongoose.connection.collection('kegs').createIndex({ userId: 1, outletId: 1, kegTag: 1 }, { unique: true, name: 'keg_tag_unique' }); } catch(e) {}
    try { await mongoose.connection.collection('draftbeers').createIndex({ userId: 1, name: 1 }, { unique: true, name: 'draftbeer_unique' }); } catch(e) {}
    try { await mongoose.connection.collection('menumappings').createIndex({ posConfigId: 1, kind: 1, posItemId: 1 }, { unique: true, name: 'pos_mapping_unique' }); } catch(e) {}
    try { await mongoose.connection.collection('posunmappeds').createIndex({ posConfigId: 1, kind: 1, posItemId: 1 }, { unique: true, name: 'pos_unmapped_unique' }); } catch(e) {}
    try { await mongoose.connection.collection('possales').createIndex({ posConfigId: 1, posOrderId: 1, kind: 1, posItemId: 1, lineIndex: 1 }, { unique: true, name: 'pos_sale_unique' }); } catch(e) {}
    // Lookup indexes for reports and count-time POS comparison (autoIndex is off)
    const ensure = (col, keys, name) => mongoose.connection.collection(col).createIndex(keys, { name }).catch(() => {});
    await ensure('inventorylogs',  { userId: 1, outletId: 1, locationId: 1, productId: 1, type: 1, at: -1 }, 'inv_lookup');
    await ensure('inventorylogs',  { userId: 1, at: -1 }, 'inv_by_date');
    await ensure('possales',       { userId: 1, soldAt: -1 }, 'pos_sale_by_date');
    await ensure('possales',       { posConfigId: 1, posOrderId: 1 }, 'pos_sale_by_order');
    await ensure('possettlements', { userId: 1, reason: 1, periodTo: -1 }, 'settle_by_date');
    await ensure('possettlements', { userId: 1, productId: 1, locationId: 1, periodTo: -1 }, 'settle_lookup');
    await ensure('posstocks',      { userId: 1, outletId: 1, locationId: 1, productId: 1 }, 'mirror_lookup');
    await ensure('pbcountlogs',    { userId: 1, recipeId: 1, locationId: 1, at: -1 }, 'pb_count_lookup');
    await ensure('keglogs',        { userId: 1, kegId: 1, at: -1 }, 'keg_log_lookup');
    // POS connections made before webhook keys existed get one now. Their
    // webhook URL (shown in the admin panel) changes — give Petpooja the new one.
    for (const c of await PosConfig.find({ $or: [{ webhookKey: { $exists: false } }, { webhookKey: null }, { webhookKey: '' }] })) {
      await PosConfig.updateOne({ _id: c._id, $or: [{ webhookKey: { $exists: false } }, { webhookKey: null }, { webhookKey: '' }] },
                                { $set: { webhookKey: newWebhookKey() } });
      console.log('[security] webhook key added to POS connection', String(c._id));
    }
    await loadPosAdapters();
    await seedPbIngredients();
    await seedScmItems();
    await seedSpiritCategories();
    await seedMasterBottles();
    app.listen(PORT, () => console.log(`SIROO backend running on port ${PORT}${IS_PROD ? ' (production)' : ''}`));
  })
  .catch(err => {
    console.error('MongoDB connection failed:', err.message);
    console.log('Starting without MongoDB (in-memory fallback not available — please start MongoDB)');
    process.exit(1);
  });
