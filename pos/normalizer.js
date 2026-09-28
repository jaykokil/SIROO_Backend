// ── POS Normalizer ────────────────────────────────────────────────────────────
// Converts raw POS sale + a MenuMapping into a standard SIROO PosSale document.

export function normalizeSale(rawSale, mapping, posConfigId, siRooOutletId) {
  return {
    posConfigId,
    siRooOutletId,
    posOrderId:     rawSale.posOrderId,
    posItemId:      rawSale.posItemId,
    posItemName:    rawSale.posItemName,
    quantity:       Number(rawSale.quantity || 1),
    unitPrice:      Number(rawSale.unitPrice || 0),
    soldAt:         new Date(rawSale.soldAt),
    // from mapping
    bottleId:       mapping?.bottleId   || null,
    mlPerServe:     mapping?.mlPerServe || 0,
    totalMlDeducted:Number(rawSale.quantity || 1) * Number(mapping?.mlPerServe || 0),
    mapped:         !!mapping?.bottleId,
  };
}
