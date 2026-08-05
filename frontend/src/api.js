// All requests go through the Vite dev proxy ("/api" -> backend). In production
// you would replace BASE with the deployed API's base URL.
const BASE = '/api';

/**
 * Asks the server whether demo mode is on.
 *
 * The UI does not assume: when demo mode is off the server genuinely does not
 * expose the comparison endpoint or any layer detail, so the front-end reads the
 * real state instead of keeping its own copy that could drift out of sync.
 */
export async function getDemoStatus() {
  try {
    const res = await fetch(`${BASE}/demo-status`);
    if (!res.ok) return { demoMode: false };
    return await res.json();
  } catch {
    return { demoMode: false };
  }
}

/** Normal upload path: the layered filter alone. This is the product. */
export async function uploadFile(file, category) {
  const form = new FormData();
  form.append('file', file);
  form.append('category', category);

  const res = await fetch(`${BASE}/upload`, { method: 'POST', body: form });

  let body = null;
  try {
    body = await res.json();
  } catch {
    // non-JSON response (e.g. an unhandled server error)
  }
  return { ok: res.ok, status: res.status, body };
}

/**
 * Evaluation path: runs the SAME bytes through every configured scanner and
 * returns their verdicts side by side. Available only while demo mode is on —
 * otherwise the server returns 404 and this resolves with ok:false.
 */
export async function compareFile(file, category) {
  const form = new FormData();
  form.append('file', file);
  form.append('category', category);

  const res = await fetch(`${BASE}/compare`, { method: 'POST', body: form });

  let body = null;
  try {
    body = await res.json();
  } catch {
    // non-JSON response
  }
  return { ok: res.ok, status: res.status, body };
}

export async function listFiles() {
  const res = await fetch(`${BASE}/files`);
  if (!res.ok) return [];
  return res.json();
}