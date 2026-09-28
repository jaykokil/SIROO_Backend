// ── Petpooja Adapter ──────────────────────────────────────────────────────────
// Implements the standard SIROO POS adapter interface:
//   testConnection(config) → { ok, message }
//   fetchMenuItems(config)  → [ { posItemId, name, price } ]
//   fetchSales(config, from, to) → [ NormalizedSale ]

export async function testConnection(config) {
  try {
    const res = await fetch(`${config.serverUrl}/api/v1/get_menu`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ app_key: config.appKey, app_secret: config.appSecret, access_token: config.accessToken, outlet_id: config.outletId }),
    });
    const data = await res.json();
    if (data.success === '1' || data.status === 1) return { ok: true, message: 'Connected to Petpooja' };
    return { ok: false, message: data.message || 'Auth failed' };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

export async function fetchMenuItems(config) {
  const res = await fetch(`${config.serverUrl}/api/v1/get_menu`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ app_key: config.appKey, app_secret: config.appSecret, access_token: config.accessToken, outlet_id: config.outletId }),
  });
  const data = await res.json();
  const items = [];
  for (const cat of data.categories || []) {
    for (const item of cat.items || []) {
      items.push({ posItemId: String(item.itemid || item.item_id), name: item.itemname || item.item_name, price: Number(item.price || 0) });
    }
  }
  return items;
}

export async function fetchSales(config, from, to) {
  const res = await fetch(`${config.serverUrl}/api/v1/get_orders`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ app_key: config.appKey, app_secret: config.appSecret, access_token: config.accessToken, outlet_id: config.outletId, sdate: from, edate: to }),
  });
  const data = await res.json();
  const sales = [];
  for (const order of data.orders || []) {
    for (const item of order.items || []) {
      sales.push({
        posOrderId:  String(order.orderid || order.order_id),
        posItemId:   String(item.itemid || item.item_id),
        posItemName: item.itemname || item.item_name || '',
        quantity:    Number(item.quantity || item.qty || 1),
        unitPrice:   Number(item.price || 0),
        soldAt:      order.created_on || order.order_date || new Date().toISOString(),
      });
    }
  }
  return sales;
}
