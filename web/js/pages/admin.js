// Administration: users, roles, API keys. Every change asks for a fresh 2FA code (step-up).
import { get, post, patch, errorPanel } from '../api.js';
import { h, mount, card, chip, table, button, input, select, field, modal, confirmBox, toast, fmtTime, fromNow, copyButton } from '../dom.js';
import { session } from '../session.js';

// --------------------------------------------------------------------------- users

export async function renderUsers(root) {
  const [users, roles] = await Promise.all([get('/users'), get('/roles')]);
  const reload = () => renderUsers(root);
  mount(root,
    h('div', { class: 'page-head' }, h('h1', {}, 'Users'), h('div', { class: 'actions' }, button('Add user', () => userDialog(null, roles.roles, reload), 'primary'))),
    h('p', { class: 'page-sub' }, 'Local accounts. People sign in with a password and, once enrolled, a code from an authenticator app. Changes here ask you for a fresh code.'),
    card(null, table([
      { label: 'User', value: (u) => h('span', {}, h('strong', {}, u.username), u.username === session.me.username ? h('span', { class: 'badge' }, 'you') : null, h('div', { class: 'muted small' }, u.fullName || '')) },
      { label: 'Roles', value: (u) => h('span', { class: 'chips' }, u.roles.length ? u.roles.map((r) => chip(roleName(roles, r), 'draft')) : h('span', { class: 'muted' }, 'none')) },
      { label: 'Status', value: (u) => h('span', { class: 'chips' }, chip(u.status),
          u.lockedUntil && new Date(u.lockedUntil) > new Date() ? chip('locked') : null,
          u.mustChangePassword ? chip('must change password', 'warning') : null) },
      { label: '2FA', value: (u) => (u.mfaEnrolled ? chip('enrolled') : chip('not set up', 'warning')) },
      { label: 'Last sign-in', value: (u) => (u.lastLoginAt ? h('span', { title: fmtTime(u.lastLoginAt) }, fromNow(u.lastLoginAt)) : '—') },
      { label: '', value: (u) => h('div', { class: 'actions' },
          button('Edit', () => userDialog(u, roles.roles, reload), 'small'),
          button('Reset password', () => resetPassword(u, reload), 'small'),
          u.mfaEnrolled ? button('Reset 2FA', () => resetMfa(u, reload), 'small') : null,
          u.lockedUntil && new Date(u.lockedUntil) > new Date() ? button('Unlock', () => unlock(u, reload), 'small') : null) },
    ], users)));
}

function roleName(roles, key) {
  return roles.roles.find((r) => r.key === key)?.name || key;
}

async function userDialog(user, roles, reload) {
  const isNew = !user;
  const username = input({ value: user?.username || '', disabled: !isNew, class: 'mono', placeholder: 'e.g. jsmith' });
  const fullName = input({ value: user?.fullName || '', class: 'wide' });
  const email = input({ value: user?.email || '', class: 'wide' });
  const status = select(['active', 'disabled'], user?.status || 'active');
  const boxes = roles.map((r) => {
    const cb = h('input', { type: 'checkbox', value: r.key, checked: user ? user.roles.includes(r.key) : r.key === 'viewer' });
    return h('label', { class: 'check role-check' }, cb, h('span', {}, h('strong', {}, r.name), h('span', { class: 'muted small' }, ` — ${r.description}`)));
  });
  const out = h('div');
  let result = null;
  const ok = await modal({
    title: isNew ? 'Add user' : `Edit ${user.username}`,
    body: h('div', {},
      h('div', { class: 'form-grid' }, field('Username', username, isNew ? 'Lower case; letters, digits, . _ -' : null), field('Full name', fullName), field('Email', email), isNew ? null : field('Status', status)),
      h('h3', {}, 'Roles'), h('div', { class: 'role-list' }, boxes),
      isNew ? h('p', { class: 'muted small' }, 'A temporary password is generated and shown once. They choose their own at first sign-in.') : null,
      out),
    actions: [{ label: 'Cancel', value: false }, {
      label: isNew ? 'Add user' : 'Save', kind: 'primary', value: true,
      validate: async () => {
        const chosen = boxes.map((b) => b.querySelector('input')).filter((c) => c.checked).map((c) => c.value);
        try {
          result = isNew
            ? await post('/users', { username: username.value.trim(), fullName: fullName.value.trim() || null, email: email.value.trim() || null, roles: chosen })
            : await patch(`/users/${encodeURIComponent(user.username)}`, { fullName: fullName.value.trim(), email: email.value.trim(), roles: chosen, status: status.value });
          return true;
        } catch (err) { mount(out, errorPanel(err)); return false; }
      },
    }],
  });
  if (!ok) return;
  if (isNew) await showTemporaryPassword(result.username, result.temporaryPassword);
  else toast(`${user.username} updated`, 'success');
  reload();
}

async function resetPassword(u, reload) {
  if (!(await confirmBox(`Reset ${u.username}'s password`, 'They get a temporary password (shown to you once), must choose a new one at next sign-in, and are signed out everywhere now.', 'Reset'))) return;
  try {
    const r = await post(`/users/${encodeURIComponent(u.username)}:reset-password`, {});
    await showTemporaryPassword(u.username, r.temporaryPassword);
    reload();
  } catch (err) { if (!err.code?.startsWith('IPAM-STEP-UP')) modal({ title: 'Couldn\'t reset', body: errorPanel(err) }); }
}

async function resetMfa(u, reload) {
  if (!(await confirmBox(`Reset ${u.username}'s 2FA`, 'Removes their authenticator and backup codes (e.g. a lost phone). They set 2FA up again at next sign-in and are signed out now.', 'Reset 2FA', 'danger'))) return;
  try { await post(`/users/${encodeURIComponent(u.username)}:reset-mfa`, {}); toast('2FA reset', 'success'); reload(); } catch (err) { if (!err.code?.startsWith('IPAM-STEP-UP')) modal({ title: 'Couldn\'t reset 2FA', body: errorPanel(err) }); }
}

async function unlock(u, reload) {
  try { await post(`/users/${encodeURIComponent(u.username)}:unlock`, {}); toast(`${u.username} unlocked`, 'success'); reload(); } catch (err) { if (!err.code?.startsWith('IPAM-STEP-UP')) modal({ title: 'Couldn\'t unlock', body: errorPanel(err) }); }
}

async function showTemporaryPassword(username, password) {
  await modal({
    title: `Temporary password for ${username}`,
    body: h('div', {},
      h('p', {}, 'Give this to them by a separate channel (Teams call, in person). It\'s shown only now; they must change it at first sign-in.'),
      h('div', { class: 'result-big' }, h('code', {}, password), ' ', copyButton(password))),
    actions: [{ label: 'Done', kind: 'primary', value: true }],
  });
}

// --------------------------------------------------------------------------- roles

export async function renderRoles(root) {
  const r = await get('/roles');
  const perms = Object.entries(r.permissions);
  mount(root,
    h('h1', {}, 'Roles'),
    h('p', { class: 'page-sub' }, 'What each role can do. Roles are fixed; assign them to people on the Users page.'),
    card(null, h('div', { class: 'table-wrap' }, h('table', { class: 'grid' },
      h('thead', {}, h('tr', {}, h('th', {}, 'Permission'), r.roles.map((x) => h('th', { class: 'num' }, x.name)))),
      h('tbody', {}, perms.map(([key, labelText]) => h('tr', {},
        h('td', {}, h('code', {}, key), h('div', { class: 'muted small' }, labelText)),
        r.roles.map((x) => h('td', { class: 'num' }, x.permissions.includes('*') || x.permissions.includes(key) ? '✔' : '')))),
      h('tr', {}, h('td', { class: 'muted' }, 'People with this role'), r.roles.map((x) => h('td', { class: 'num' }, x.users))))))),
    h('p', { class: 'muted small' }, 'Administrators must set up 2FA before doing anything. Releasing templates, confirming or releasing sites, and changing users or API keys also ask for a fresh code.'));
}

// --------------------------------------------------------------------------- API keys

const SCOPES = {
  read: 'Read designs and lookups',
  'hosts:write': 'Assign host addresses',
  'sites:deploy': 'Reserve, confirm and release sites',
  'templates:write': 'Create and release templates',
  'audit:read': 'Read the audit log',
};

export async function renderKeys(root) {
  const keys = await get('/api-keys');
  const reload = () => renderKeys(root);
  mount(root,
    h('div', { class: 'page-head' }, h('h1', {}, 'API keys'), h('div', { class: 'actions' }, button('Issue key', () => issueKey(reload), 'primary'))),
    h('p', { class: 'page-sub' }, 'For scripts and integrations (Site Delivery Wizard, Ansible, PowerShell). Keys skip 2FA, so they\'re scoped, expire, and can\'t manage users or keys. Only a hash is stored.'),
    card(null, table([
      { label: 'Key', value: (k) => h('span', {}, h('code', {}, `ipam_${k.prefix}_…`), h('div', { class: 'muted small' }, k.purpose)) },
      { label: 'Owner', value: (k) => k.owner },
      { label: 'Client', value: (k) => k.clientName || '—' },
      { label: 'Scopes', value: (k) => h('span', { class: 'chips' }, k.scopes.map((s) => chip(s, 'draft'))) },
      { label: 'Expires', value: (k) => h('span', { title: fmtTime(k.expiresAt) }, fromNow(k.expiresAt)) },
      { label: 'Last used', value: (k) => (k.lastUsedAt ? h('span', { title: `${fmtTime(k.lastUsedAt)} from ${k.lastUsedIp}` }, fromNow(k.lastUsedAt)) : 'never') },
      { label: 'Status', value: (k) => (k.revokedAt ? chip('revoked') : new Date(k.expiresAt) < new Date() ? chip('expired') : chip('active')) },
      { label: '', value: (k) => (k.revokedAt ? '' : button('Revoke', () => revokeKey(k, reload), 'small')) },
    ], keys, { empty: 'No keys yet.' })));
}

async function issueKey(reload) {
  const owner = input({ value: session.me.fullName || session.me.username, class: 'wide' });
  const purpose = input({ class: 'wide', placeholder: 'e.g. Site Delivery Wizard server' });
  const client = input({ class: 'mono', placeholder: 'e.g. SiteDeliveryWizard' });
  const days = input({ type: 'number', value: 90, min: 1, max: 365, class: 'narrow' });
  const boxes = Object.entries(SCOPES).map(([s, text]) => h('label', { class: 'check role-check' }, h('input', { type: 'checkbox', value: s, checked: s === 'read' }), h('span', {}, h('code', {}, s), h('span', { class: 'muted small' }, ` — ${text}`))));
  const out = h('div');
  let issued = null;
  const ok = await modal({
    title: 'Issue API key',
    body: h('div', {}, h('div', { class: 'form-grid' }, field('Owner', owner, 'A named person accountable for it'), field('Purpose', purpose), field('Client name', client), field('Expires in (days)', days, 'Maximum 365')), h('h3', {}, 'Scopes'), h('div', { class: 'role-list' }, boxes), out),
    actions: [{ label: 'Cancel', value: false }, {
      label: 'Issue', kind: 'primary', value: true,
      validate: async () => {
        try {
          issued = await post('/api-keys', {
            owner: owner.value.trim(), purpose: purpose.value.trim(), clientName: client.value.trim() || null,
            scopes: boxes.map((b) => b.querySelector('input')).filter((c) => c.checked).map((c) => c.value), expiresInDays: Number(days.value),
          });
          return true;
        } catch (err) { mount(out, errorPanel(err)); return false; }
      },
    }],
  });
  if (!ok) return;
  await modal({
    title: 'Copy the key now',
    body: h('div', {}, h('p', {}, 'This is the only time the full key is shown. Store it in the client\'s secret store (e.g. PowerShell SecretManagement), not in a script.'),
      h('pre', { class: 'json' }, issued.key), copyButton(issued.key, 'Copy key')),
    actions: [{ label: 'Done', kind: 'primary', value: true }],
  });
  reload();
}

async function revokeKey(k, reload) {
  if (!(await confirmBox('Revoke API key', `Revoke ipam_${k.prefix}_… (${k.purpose})? Anything using it stops working immediately.`, 'Revoke', 'danger'))) return;
  try { await post(`/api-keys/${encodeURIComponent(k.prefix)}:revoke`, {}); toast('Key revoked', 'success'); reload(); } catch (err) { if (!err.code?.startsWith('IPAM-STEP-UP')) modal({ title: 'Couldn\'t revoke', body: errorPanel(err) }); }
}
