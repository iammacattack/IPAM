// Hash router and sign-in. Each page module exports render(root, params).
import { api, auth, errorPanel } from './api.js';
import { h, mount, field, input, button, card } from './dom.js';
import * as dashboard from './pages/dashboard.js';
import * as templates from './pages/templates.js';
import * as builder from './pages/builder.js';
import * as sites from './pages/sites.js';
import * as lookup from './pages/lookup.js';
import * as library from './pages/library.js';
import * as audit from './pages/audit.js';

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
];

// Pages can register a guard (e.g. unsaved builder changes).
let leaveGuard = null;
export function setLeaveGuard(fn) { leaveGuard = fn; }

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
  if (!auth.get()) return renderSignIn();
  showChrome(true);
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
  mount(root, card('Not found', h('p', {}, 'No page at this address. '), h('a', { href: '#/' }, 'Go to the dashboard')));
}

function showChrome(on) {
  document.getElementById('nav').hidden = !on;
  document.getElementById('session').hidden = !on;
  document.getElementById('whoami').textContent = on ? `key ${auth.prefix()}` : '';
}

function renderSignIn(message) {
  showChrome(false);
  const key = input({ type: 'password', placeholder: 'ipam_xxxxxxxx_…', autocomplete: 'off', class: 'wide' });
  const status = h('div');
  const submit = async () => {
    const value = key.value.trim();
    if (!value) return;
    try {
      // Test the typed key before keeping it.
      await api('GET', '/templates', { query: { state: 'RELEASED' }, key: value });
      auth.set(value);
      route();
    } catch (err) {
      mount(status, errorPanel(err));
    }
  };
  key.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  mount(root,
    h('div', { class: 'signin' },
      card('Sign in',
        message ? h('div', { class: 'alert' }, message) : null,
        h('p', {}, 'Paste the development API key. It\'s the ', h('code', {}, 'IPAM_BOOTSTRAP_API_KEY'), ' line in ', h('code', {}, '.env'), ' in the repo folder.'),
        h('p', { class: 'muted small' }, 'To copy it from PowerShell: ', h('code', {}, "((Get-Content .env) -match '^IPAM_BOOTSTRAP_API_KEY=' -replace '^IPAM_BOOTSTRAP_API_KEY=','') | Set-Clipboard")),
        field('API key', key),
        button('Sign in', submit, 'primary'),
        status,
        h('p', { class: 'muted small' }, 'The key is kept in this browser tab only and is cleared when you close it. Entra ID sign-in replaces this in Phase 4.'))));
  key.focus();
}

document.getElementById('signout').addEventListener('click', () => {
  auth.clear();
  location.hash = '#/';
  renderSignIn('Signed out.');
});
window.addEventListener('ipam:signed-out', () => renderSignIn('Your key was refused or has expired. Sign in again.'));
window.addEventListener('hashchange', route);
route();
