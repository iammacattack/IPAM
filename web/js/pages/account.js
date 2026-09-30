// My account: password, 2FA enrolment and backup codes. Also the forced first-sign-in screens.
import { api, post, errorPanel } from '../api.js';
import { h, mount, card, chip, field, input, button, toast, modal, fmtTime, copyButton } from '../dom.js';
import { session } from '../session.js';
import { authCard, refreshMe } from '../main.js';

// --------------------------------------------------------------------------- forced screens

export function renderForcedPasswordChange(root, done) {
  mount(root, authCard('Choose a new password',
    h('p', { class: 'small' }, 'Signed in as ', h('strong', {}, session.me.username), ' · ', h('a', { href: '#', onClick: (e) => { e.preventDefault(); document.getElementById('signout').click(); } }, 'sign out')),
    h('p', { class: 'muted' }, 'This is your first sign-in, or an administrator reset your password. Pick a new one to continue.'),
    passwordForm(async () => { toast('Password changed', 'success'); await done(); }, true)));
}

export function renderForcedEnrolment(root, done) {
  const box = h('div');
  mount(root, authCard('Set up two-step verification',
    h('p', { class: 'small' }, 'Signed in as ', h('strong', {}, session.me.username), ' · ', h('a', { href: '#', onClick: (e) => { e.preventDefault(); document.getElementById('signout').click(); } }, 'sign out')),
    h('p', { class: 'muted' }, 'Your role needs 2FA. You\'ll use a code from an authenticator app to sign in and to confirm high-risk actions like releasing a template or confirming a site.'),
    box));
  enrolWizard(box, done);
}

// --------------------------------------------------------------------------- my account

export async function render(root) {
  const me = (await refreshMe()) || session.me;
  const twofa = h('div');
  const drawTwofa = () => {
    const m = session.me;
    mount(twofa,
      h('p', {}, 'Status: ', m.mfaEnrolled ? chip('enrolled') : chip('not set up', 'warning'),
        m.mfaEnrolled ? h('span', { class: 'muted' }, ` · ${m.backupCodesLeft} backup code(s) left`) : null),
      h('p', { class: 'muted small' }, `A fresh code is asked for when you: ${m.stepUpActions.map(label).join(', ')}. One code covers ${m.stepUpWindowMinutes} minute(s).`),
      h('div', { class: 'actions' },
        button(m.mfaEnrolled ? 'Replace authenticator…' : 'Set up authenticator', () => startEnrol(), m.mfaEnrolled ? '' : 'primary'),
        m.mfaEnrolled ? button('New backup codes…', regenerate) : null));
  };
  const startEnrol = () => {
    const box = h('div');
    mount(twofa, box, h('p', {}, button('Cancel', drawTwofa, 'ghost')));
    enrolWizard(box, async () => { await refreshMe(); drawTwofa(); });
  };
  const regenerate = async () => {
    try {
      const r = await post('/auth/mfa/backup-codes', {});
      await showBackupCodes(r.backupCodes);
      await refreshMe();
      drawTwofa();
    } catch (err) { if (err.code !== 'IPAM-STEP-UP-REQUIRED') modal({ title: 'Couldn\'t create codes', body: errorPanel(err) }); }
  };
  drawTwofa();

  mount(root,
    h('h1', {}, 'My account'),
    h('div', { class: 'two-col' },
      card('Profile', h('dl', { class: 'facts' },
        h('dt', {}, 'Username'), h('dd', {}, h('code', {}, me.username)),
        h('dt', {}, 'Name'), h('dd', {}, me.fullName || '—'),
        h('dt', {}, 'Email'), h('dd', {}, me.email || '—'),
        h('dt', {}, 'Roles'), h('dd', {}, h('span', { class: 'chips' }, me.roles.map((r) => chip(r.name, 'draft')))),
        h('dt', {}, 'Can'), h('dd', { class: 'small muted' }, me.permissions.join(', ')),
        h('dt', {}, 'Last sign-in'), h('dd', {}, fmtTime(me.lastLoginAt)),
        h('dt', {}, 'Session'), h('dd', { class: 'small muted' }, `Signs out after ${me.sessionIdleMinutes} minutes idle`))),
      card('Two-step verification (2FA)', twofa)),
    card('Change password', passwordForm(async () => { toast('Password changed. Other sessions were signed out.', 'success'); }, false)));
}

function label(action) {
  return {
    'templates.release': 'release a template', 'sites.confirm': 'confirm a site', 'sites.release': 'release a reservation',
    'users.manage': 'change users', 'apikeys.manage': 'issue or revoke API keys', 'mfa.replace': 'change your 2FA',
  }[action] || action;
}

// --------------------------------------------------------------------------- pieces

function passwordForm(onDone, compact) {
  const current = input({ type: 'password', autocomplete: 'current-password', class: 'wide' });
  const next = input({ type: 'password', autocomplete: 'new-password', class: 'wide' });
  const again = input({ type: 'password', autocomplete: 'new-password', class: 'wide' });
  const status = h('div');
  const submit = async () => {
    mount(status);
    if (next.value !== again.value) { mount(status, h('div', { class: 'alert alert-error compact' }, 'The new passwords don\'t match')); return; }
    try {
      await api('POST', '/auth/change-password', { body: { currentPassword: current.value, newPassword: next.value } });
      [current, next, again].forEach((el) => { el.value = ''; });
      await onDone();
    } catch (err) { mount(status, errorPanel(err)); }
  };
  again.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  return h('div', {},
    h('div', { class: compact ? '' : 'form-grid' },
      field(compact ? 'Current (temporary) password' : 'Current password', current),
      field('New password', next, 'At least 12 characters, with three of: lower case, upper case, digits, symbols'),
      field('New password again', again)),
    button('Change password', submit, 'primary'), status);
}

/** Two-step enrolment: scan the QR code, then confirm with the first code; show backup codes once. */
export async function enrolWizard(box, done) {
  mount(box, h('p', { class: 'muted' }, 'Preparing…'));
  let setup;
  try {
    setup = await post('/auth/mfa/enrol', {});
  } catch (err) { mount(box, errorPanel(err)); return; }
  const code = h('input', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: 6, class: 'code-input', placeholder: '123456' });
  const status = h('div');
  const verify = async () => {
    try {
      const r = await post('/auth/mfa/enrol/verify', { code: code.value.trim() });
      await showBackupCodes(r.backupCodes);
      toast('2FA is on', 'success');
      await done();
    } catch (err) { code.value = ''; mount(status, errorPanel(err)); }
  };
  code.addEventListener('keydown', (e) => { if (e.key === 'Enter') verify(); });
  mount(box,
    h('ol', { class: 'step-list' },
      h('li', {}, 'Open an authenticator app (Microsoft Authenticator, Google Authenticator, 1Password…) and add an account.'),
      h('li', {}, 'Scan this QR code, or type the key below.'),
      h('li', {}, 'Enter the 6-digit code it shows.')),
    h('img', { class: 'qr', src: setup.qrSvg, alt: 'QR code for your authenticator app' }),
    h('span', { class: 'secret small' }, setup.secret.replace(/(.{4})/g, '$1 ').trim()),
    h('div', { class: 'field' }, code),
    button('Turn on 2FA', verify, 'primary'),
    status);
  code.focus();
}

async function showBackupCodes(codes) {
  await modal({
    title: 'Your backup codes',
    body: h('div', {},
      h('p', {}, 'Each code works once, in place of an authenticator code — for when your phone isn\'t available. Keep them somewhere safe (a password manager). They won\'t be shown again.'),
      h('div', { class: 'backup-codes' }, codes.map((c) => h('span', {}, c))),
      copyButton(codes.join('\n'), 'Copy codes')),
    actions: [{ label: 'I\'ve saved them', kind: 'primary', value: true }],
  });
}
