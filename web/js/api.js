// API client. The key lives in sessionStorage only (gone when the tab closes); Entra sign-in replaces it in Phase 4.
import { h } from './dom.js';

const KEY = 'ipam.apiKey';
const CLIENT = 'IPAM-UI/0.1';

export const auth = {
  get: () => sessionStorage.getItem(KEY),
  set: (k) => sessionStorage.setItem(KEY, k.trim()),
  clear: () => sessionStorage.removeItem(KEY),
  prefix: () => (sessionStorage.getItem(KEY) || '').split('_')[1] || '',
};

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.detail || body?.message || `HTTP ${status}`);
    this.status = status;
    this.body = body || {};
    this.code = this.body.code || `HTTP-${status}`;
  }
}

export async function api(method, path, { query, body, headers = {}, key } = {}) {
  const url = new URL(`/api/v1${path}`, location.origin);
  for (const [k, v] of Object.entries(query || {})) {
    if (v !== null && v !== undefined && v !== '') url.searchParams.set(k, v);
  }
  const res = await fetch(url, {
    method,
    headers: {
      'X-API-Key': key ?? auth.get() ?? '',
      'X-Client-Name': CLIENT,
      Accept: 'application/json',
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...headers,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const type = res.headers.get('content-type') || '';
  const data = type.includes('json') ? await res.json().catch(() => null) : await res.text();
  if (res.status === 401 && !key) {
    auth.clear();
    window.dispatchEvent(new Event('ipam:signed-out'));
  }
  if (!res.ok) throw new ApiError(res.status, typeof data === 'object' ? data : { detail: data });
  return data;
}

export const get = (path, query) => api('GET', path, { query });
export const post = (path, body, opts = {}) => api('POST', path, { body: body ?? {}, ...opts });
export const patch = (path, body) => api('PATCH', path, { body });

/** A readable panel for an API error, including the extra fields the API returns (suggested, candidates, errors...). */
export function errorPanel(err) {
  if (!(err instanceof ApiError)) return h('div', { class: 'alert alert-error' }, String(err?.message || err));
  const b = err.body;
  const skip = new Set(['type', 'title', 'status', 'code', 'detail', 'requestId', 'errors', 'report']);
  const extras = Object.entries(b).filter(([k]) => !skip.has(k));
  const list = b.errors || b.report?.errors || [];
  return h('div', { class: 'alert alert-error' },
    h('div', {}, h('strong', {}, err.code), ' — ', err.message),
    extras.length ? h('ul', { class: 'kv' }, extras.map(([k, v]) => h('li', {}, h('span', { class: 'k' }, k), ' ', typeof v === 'object' ? JSON.stringify(v) : String(v)))) : null,
    list.length ? h('ul', {}, list.slice(0, 20).map((e) =>
      h('li', {}, h('code', {}, e.code || e.type || ''), ' ', e.message || e.msg || JSON.stringify(e.loc || e)))) : null,
    b.requestId ? h('div', { class: 'muted small' }, `Request ${b.requestId}`) : null);
}
