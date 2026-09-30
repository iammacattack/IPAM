// API client. The browser session is an HttpOnly cookie the page can't read; every call sends
// X-Requested-With so the server knows a write came from this UI (CSRF guard).
// When the server asks for a fresh 2FA code (step-up) the user is prompted and the call is retried.
import { h, modal } from './dom.js';

const CLIENT = 'IPAM-UI/0.2';

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.detail || body?.message || `HTTP ${status}`);
    this.status = status;
    this.body = body || {};
    this.code = this.body.code || `HTTP-${status}`;
  }
}

async function send(method, path, { query, body, headers = {} } = {}) {
  const url = new URL(`/api/v1${path}`, location.origin);
  for (const [k, v] of Object.entries(query || {})) {
    if (v !== null && v !== undefined && v !== '') url.searchParams.set(k, v);
  }
  const res = await fetch(url, {
    method,
    credentials: 'same-origin',
    headers: {
      'X-Requested-With': 'IPAM-UI',
      'X-Client-Name': CLIENT,
      Accept: 'application/json',
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...headers,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const type = res.headers.get('content-type') || '';
  const data = type.includes('json') ? await res.json().catch(() => null) : await res.text();
  if (!res.ok) throw new ApiError(res.status, typeof data === 'object' && data ? data : { detail: data });
  return { data, res };
}

const SIGNED_OUT = new Set(['IPAM-SESSION-INVALID', 'IPAM-SESSION-EXPIRED', 'IPAM-AUTH-REQUIRED', 'IPAM-MFA-REQUIRED']);
const RESTRICTED = new Set(['IPAM-PASSWORD-CHANGE-REQUIRED']);

export async function api(method, path, opts = {}) {
  let extra = {};
  let lastError = null;
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      const { data } = await send(method, path, { ...opts, headers: { ...(opts.headers || {}), ...extra } });
      return data;
    } catch (err) {
      if (!(err instanceof ApiError)) throw err;
      if (SIGNED_OUT.has(err.code) && !opts.quiet) window.dispatchEvent(new CustomEvent('ipam:signed-out', { detail: err }));
      if (RESTRICTED.has(err.code) || (err.code === 'IPAM-MFA-ENROLMENT-REQUIRED' && !err.body.action)) {
        window.dispatchEvent(new CustomEvent('ipam:restricted', { detail: err }));
      }
      if (err.code === 'IPAM-MFA-ENROLMENT-REQUIRED' && err.body.action) {
        await enrolFirst(err);
        throw err;
      }
      if (err.code === 'IPAM-STEP-UP-REQUIRED' || (err.code === 'IPAM-STEP-UP-FAILED' && extra['X-IPAM-2FA'])) {
        const code = await askForCode(err.body.action, err.code === 'IPAM-STEP-UP-FAILED' ? err.message : null);
        if (!code) throw err;
        extra = { 'X-IPAM-2FA': code };
        lastError = err;
        continue;
      }
      throw err;
    }
  }
  throw lastError;
}

export const get = (path, query) => api('GET', path, { query });
export const post = (path, body, opts = {}) => api('POST', path, { body: body ?? {}, ...opts });
export const patch = (path, body) => api('PATCH', path, { body });

const ACTION_LABELS = {
  'templates.release': 'release a template',
  'sites.confirm': 'confirm a site allocation',
  'sites.release': 'release a site reservation',
  'users.manage': 'change users',
  'apikeys.manage': 'issue or revoke API keys',
  'mfa.replace': 'change your 2FA set-up',
};

/** Prompt for an authenticator (or backup) code. Resolves with the code, or null if cancelled. */
export function askForCode(action, problem) {
  const code = h('input', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: 14, class: 'code-input', placeholder: '123456' });
  const body = h('div', {},
    h('p', {}, `To ${ACTION_LABELS[action] || 'do this'}, enter the 6-digit code from your authenticator app.`),
    problem ? h('div', { class: 'alert alert-error compact' }, problem) : null,
    code,
    h('p', { class: 'muted small' }, 'Lost your phone? A backup code works too (e.g. 1A2B-3C4D-5E6F). One code covers the next few minutes.'));
  code.addEventListener('keydown', (e) => { if (e.key === 'Enter') body.closest('.modal')?.querySelector('.btn-primary')?.click(); });
  return modal({
    title: 'Confirm it\'s you',
    body,
    actions: [{ label: 'Cancel', value: null }, { label: 'Verify', kind: 'primary', value: () => code.value.trim() || null }],
  });
}

async function enrolFirst(err) {
  const go = await modal({
    title: 'Set up 2FA first',
    body: h('p', {}, `${err.message} It takes about a minute: you scan a QR code with an authenticator app such as Microsoft Authenticator.`),
    actions: [{ label: 'Not now', value: false }, { label: 'Set up 2FA', kind: 'primary', value: true }],
  });
  if (go) location.hash = '#/account';
}

/** A readable panel for an API error, including the extra fields the API returns (suggested, candidates, errors...). */
export function errorPanel(err) {
  if (!(err instanceof ApiError)) return h('div', { class: 'alert alert-error' }, String(err?.message || err));
  const b = err.body;
  const skip = new Set(['type', 'title', 'status', 'code', 'detail', 'requestId', 'errors', 'report', 'action', 'permission']);
  const extras = Object.entries(b).filter(([k]) => !skip.has(k));
  const list = b.errors || b.report?.errors || [];
  return h('div', { class: 'alert alert-error' },
    h('div', {}, h('strong', {}, err.code), ' — ', err.message),
    extras.length ? h('ul', { class: 'kv' }, extras.map(([k, v]) => h('li', {}, h('span', { class: 'k' }, k), ' ', typeof v === 'object' ? JSON.stringify(v) : String(v)))) : null,
    list.length ? h('ul', {}, list.slice(0, 20).map((e) =>
      h('li', {}, h('code', {}, e.code || e.type || ''), ' ', e.message || e.msg || JSON.stringify(e.loc || e)))) : null,
    b.requestId ? h('div', { class: 'muted small' }, `Request ${b.requestId}`) : null);
}
