// Shell, sign-in and hash router. Each page module exports a render function.
import { api, errorPanel } from './api.js';
import { h, mount, field, input, button, toast } from './dom.js';
import { session, can, canAny } from './session.js';
import * as dashboard from './pages/dashboard.js';
import * as templates from './pages/templates.js';
import * as builder from './pages/builder.js';
import * as sites from './pages/sites.js';
import * as lookup from './pages/lookup.js';
import * as library from './pages/library.js';
import * as audit from './pages/audit.js';
import * as account from './pages/account.js';
import * as admin from './pages/admin.js';

const root = document.getElementById('app');

const routes = [
  [/^#?\/?$/, 'dashboard', () => dashboard.render(root)],
  [/^#\/templates$/, 'templates', () => templates.renderList(root)],
  [/^#\/templates\/([^/]+)(?:\/v\/(\d+))?$/, 'templates', (m) => templates.renderDetail(root, decodeURIComponent(m[1]), m[2] ? Number(m[2]) : null)],
  [/^#\/builder\/new$/, 'templates', () => builder.render(root, null, null)],
  [/^#\/builder\/([^/]+)\/(\d+)$/, 'templates', (m) => builder.render(root, decodeURIComponent(m[1]), Number(m[2]))],
  [/^#\/sites$/, 'sites', () => sites.renderList(root)],
  [/^#\/sites\/new$/, 'sites', (m, q) => sites.renderNew(root, q)],
  [/^#\/sites\/([^/]+)$/, 'sites', (m) => sites.renderDetail(root, decodeURIComponent(m[1]))],
  [/^#\/lookup$/, 'lookup', () => lookup.render(root)],
  [/^#\/library$/, 'library', () => library.render(root)],
  [/^#\/audit$/, 'audit', () => audit.render(root)],
  [/^#\/account$/, 'account', () => account.render(root)],
  [/^#\/admin\/users$/, 'users', () => admin.renderUsers(root)],
  [/^#\/admin\/roles$/, 'roles', () => admin.renderRoles(root)],
  [/^#\/admin\/keys$/, 'keys', () => admin.renderKeys(root)],
];

const NAV = [
  { id: 'dashboard', href: '#/', label: 'Dashboard', ico: '◈', show: () => true },
  { id: 'templates', href: '#/templates', label: 'Templates', ico: '▦', show: () => can('read') },
  { id: 'sites', href: '#/sites', label: 'Sites', ico: '⌂', show: () => can('read') },
  { id: 'lookup', href: '#/lookup', label: 'Lookup', ico: '⌕', show: () => can('read') },
  { id: 'library', href: '#/library', label: 'Library', ico: '☰', show: () => can('read') },
  { label: 'Governance', show: () => canAny('audit.read', 'users.manage', 'apikeys.manage') },
  { id: 'audit', href: '#/audit', label: 'Audit log', ico: '✎', show: () => can('audit.read') },
  { id: 'users', href: '#/admin/users', label: 'Users', ico: '☺', show: () => can('users.manage') },
  { id: 'roles', href: '#/admin/roles', label: 'Roles', ico: '⚿', show: () => can('users.manage') },
  { id: 'keys', href: '#/admin/keys', label: 'API keys', ico: '⚷', show: () => can('apikeys.manage') },
];

// Pages can register a guard (e.g. unsaved builder changes).
let leaveGuard = null;
export function setLeaveGuard(fn) { leaveGuard = fn; }

// --------------------------------------------------------------------------- theme

const THEME_KEY = 'ipam-color-mode';
function applyTheme(mode) {
  document.body.classList.toggle('light', mode === 'light');
  document.getElementById('theme-toggle').textContent = mode === 'light' ? '☾ Dark' : '☀ Light';
}
applyTheme(localStorage.getItem(THEME_KEY) || 'dark');
document.getElementById('theme-toggle').addEventListener('click', () => {
  const next = document.body.classList.contains('light') ? 'dark' : 'light';
  localStorage.setItem(THEME_KEY, next);
  applyTheme(next);
});

// --------------------------------------------------------------------------- shell

function renderShell() {
  const me = session.me;
  document.body.classList.toggle('signed-out', !me);
  if (!me) return;
  const nav = document.getElementById('nav');
  mount(nav, NAV.filter((n) => n.show()).map((n) => (n.href
    ? h('a', { href: n.href, dataset: { route: n.id } }, h('span', { class: 'nav-ico', 'aria-hidden': 'true' }, n.ico), n.label)
    : h('div', { class: 'nav-label' }, n.label))));
  document.getElementById('avatar').textContent = (me.fullName || me.username).split(/\s+/).map((p) => p[0]).join('').slice(0, 2).toUpperCase();
  document.getElementById('who-name').textContent = me.fullName || me.username;
  document.getElementById('who-role').textContent = `${me.roles.map((r) => r.name).join(', ') || 'no role'}${me.mfaEnrolled ? ' · 2FA on' : ''}`;
}

export async function refreshMe() {
  try {
    session.me = await api('GET', '/auth/me', { quiet: true });
  } catch {
    session.me = null;
  }
  renderShell();
  return session.me;
}

// --------------------------------------------------------------------------- routing

let lastHash = location.hash;
async function route() {
  if (leaveGuard && location.hash !== lastHash) {
    if (!(await leaveGuard())) {
      history.replaceState(null, '', lastHash || '#/');
      return;
    }
    leaveGuard = null;
  }
  lastHash = location.hash;
  if (!session.me) return renderSignIn();
  const gated = session.me.mustChangePassword || session.me.mfaEnrolRequired;
  document.body.classList.toggle('signed-out', Boolean(gated));  // no menu until the account is ready
  if (session.me.mustChangePassword) return account.renderForcedPasswordChange(root, afterGate);
  if (session.me.mfaEnrolRequired) return account.renderForcedEnrolment(root, afterGate);

  const [hash, qs] = (location.hash || '#/').split('?');
  const query = new URLSearchParams(qs || '');
  for (const [re, nav, fn] of routes) {
    const m = hash.match(re);
    if (m) {
      document.querySelectorAll('#nav a').forEach((a) => a.classList.toggle('active', a.dataset.route === nav));
      try {
        await fn(m, query);
      } catch (err) {
        mount(root, errorPanel(err));
      }
      window.scrollTo(0, 0);
      return;
    }
  }
  mount(root, h('div', { class: 'card' }, h('h2', {}, 'Not found'), h('a', { href: '#/' }, 'Go to the dashboard')));
}

async function afterGate() {
  await refreshMe();
  route();
}

// --------------------------------------------------------------------------- sign-in

function renderSignIn(message) {
  session.me = null;
  renderShell();
  const user = input({ autocomplete: 'username', placeholder: 'username', class: 'wide' });
  const pass = input({ type: 'password', autocomplete: 'current-password', class: 'wide' });
  const status = h('div');
  const submit = async () => {
    if (!user.value.trim() || !pass.value) return;
    mount(status);
    try {
      const r = await api('POST', '/auth/login', { body: { username: user.value.trim(), password: pass.value }, quiet: true });
      if (r.mfaRequired) return renderCode();
      await afterGate();
    } catch (err) {
      pass.value = '';
      mount(status, errorPanel(err));
    }
  };
  [user, pass].forEach((el) => el.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); }));
  mount(root, authCard('Sign in',
    message ? h('div', { class: 'alert compact' }, message) : null,
    field('Username', user), field('Password', pass),
    button('Sign in', submit, 'primary'),
    status,
    h('p', { class: 'muted small' }, 'First time? Sign in as ', h('code', {}, 'admin'), ' with IPAM_ADMIN_PASSWORD from .env in the repo folder. You\'ll be asked to change it and set up 2FA.')));
  user.focus();
}

function renderCode() {
  const code = h('input', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: 14, class: 'code-input', placeholder: '123456' });
  const status = h('div');
  const submit = async () => {
    if (!code.value.trim()) return;
    try {
      await api('POST', '/auth/mfa/verify', { body: { code: code.value.trim() }, quiet: true });
      await afterGate();
    } catch (err) {
      code.value = '';
      mount(status, errorPanel(err));
      if (err.code === 'IPAM-SESSION-INVALID' || err.code === 'IPAM-MFA-LOCKED') setTimeout(() => renderSignIn(err.message), 1500);
    }
  };
  code.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  mount(root, authCard('Two-step verification',
    h('p', { class: 'muted' }, 'Enter the 6-digit code from your authenticator app.'),
    code,
    button('Verify', submit, 'primary'),
    status,
    h('p', { class: 'muted small' }, 'No phone? Enter one of your backup codes instead. ', h('a', { href: '#/', onClick: (e) => { e.preventDefault(); renderSignIn(); } }, 'Start again'))));
  code.focus();
}

export function authCard(title, ...children) {
  return h('div', { class: 'auth-stage' },
    h('div', { class: 'card auth-card' },
      h('div', { class: 'brand' }, h('span', { class: 'brand-mark' }, 'IP'), h('span', {}, h('span', { class: 'brand-name' }, 'IPAM'), h('br'), h('span', { class: 'brand-sub' }, 'IP Address Management'))),
      h('h2', {}, title),
      children));
}

// --------------------------------------------------------------------------- events

document.getElementById('signout').addEventListener('click', async () => {
  try { await api('POST', '/auth/logout', { quiet: true }); } catch { /* signed out either way */ }
  leaveGuard = null;
  history.replaceState(null, '', '#/');
  renderSignIn('Signed out.');
});
window.addEventListener('ipam:signed-out', (e) => {
  if (!session.me) return;
  leaveGuard = null;
  toast(e.detail?.message || 'Signed out', 'warn');
  renderSignIn(e.detail?.message);
});
window.addEventListener('ipam:restricted', () => afterGate());
window.addEventListener('hashchange', route);

(async () => {
  await refreshMe();
  route();
})();
