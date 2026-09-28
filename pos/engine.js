// ── SIROO POS Integration Engine ─────────────────────────────────────────────
// Central sync engine. Supports any POS via adapters.
// Usage: import { syncOutlet, runReconciliation } from './pos/engine.js'

import { normalizeSale } from './normalizer.js';

// Adapter registry — add new POS here, nothing else changes
const ADAPTERS = {};

export async function loadAdapters() {
  const { testConnection: ppTest, fetchMenuItems: ppMenu, fetchSales: ppSales } = await import('./adapters/petpooja.js');
  ADAPTERS['petpooja'] = { testConnection: ppTest, fetchMenuItems: ppMenu, fetchSales: ppSales };
  const { testConnection: cTest, fetchMenuItems: cMenu, fetchSales: cSales } = await import('./adapters/custom.js');
  ADAPTERS['custom'] = { testConnection: cTest, fetchMenuItems: cMenu, fetchSales: cSales };
  console.log('[POS Engine] Adapters loaded:', Object.keys(ADAPTERS).join(', '));
}

export function getAdapter(posName) {
  const adapter = ADAPTERS[posName?.toLowerCase()];
  if (!adapter) throw new Error(`No adapter found for POS: "${posName}". Available: ${Object.keys(ADAPTERS).join(', ')}`);
  return adapter;
}

export async function testPosConnection(posConfig) {
  const adapter = getAdapter(posConfig.posName);
  return adapter.testConnection(posConfig.credentials);
}

export async function fetchPosMenuItems(posConfig) {
  const adapter = getAdapter(posConfig.posName);
  return adapter.fetchMenuItems(posConfig.credentials);
}

// ── Main sync: fetch sales → normalize → deduplicate → return ────────────────
export async function syncOutlet(posConfig, mappings, from, to) {
  const adapter  = getAdapter(posConfig.posName);
  const rawSales = await adapter.fetchSales(posConfig.credentials, from, to);

  // Build mapping lookup: posItemId → mapping
  const mapLookup = {};
  for (const m of mappings) mapLookup[String(m.posItemId)] = m;

  const normalized = rawSales.map(raw =>
    normalizeSale(raw, mapLookup[String(raw.posItemId)], posConfig._id, posConfig.siRooOutletId)
  );

  const unmapped = normalized.filter(s => !s.mapped).map(s => s.posItemName);
  const uniqueUnmapped = [...new Set(unmapped)];

  return { sales: normalized, unmappedItems: uniqueUnmapped };
}

// ── Reconciliation: compare POS sales ML vs physical closing ML ──────────────
export function reconcile({ openingStock, closingStock, posSalesML, bottleSizeMl }) {
  const physicalConsumedMl = openingStock - closingStock;
  const variance           = physicalConsumedMl - posSalesML;
  const variancePct        = posSalesML > 0 ? ((variance / posSalesML) * 100).toFixed(1) : null;

  return {
    openingStock,
    closingStock,
    physicalConsumedMl,
    posSalesML,
    variance,           // positive = more consumed than sold (shrinkage/wastage)
    variancePct,
    status: Math.abs(variance) <= bottleSizeMl * 0.05
      ? 'OK'            // within 5% of a bottle — acceptable
      : variance > 0
        ? 'SHRINKAGE'   // consumed more than sold
        : 'SURPLUS',    // sold more than consumed (POS over-recorded or stock error)
  };
}
