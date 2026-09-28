// ── Custom / Generic Adapter Template ────────────────────────────────────────
// Copy this file and rename it for any new POS system.
// Implement the 3 functions below and register in engine.js ADAPTERS map.

export async function testConnection(config) {
  // TODO: call your POS API health/auth endpoint
  return { ok: false, message: 'Custom adapter not implemented yet' };
}

export async function fetchMenuItems(config) {
  // TODO: return array of { posItemId, name, price }
  return [];
}

export async function fetchSales(config, from, to) {
  // TODO: return array of { posOrderId, posItemId, posItemName, quantity, unitPrice, soldAt }
  return [];
}
