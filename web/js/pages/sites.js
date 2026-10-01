// Sites (Workflow 2): reserve from a released template, confirm, extend, release; browse the design; assign hosts.
import { get, post, errorPanel } from '../api.js';
import { can } from '../session.js';
import {
  h, mount, card, chip, table, button, input, select, field, modal, confirmBox, toast, fmtTime, fromNow, shortHash, downloadCsv, copyButton,
} from '../dom.js';

const FILTERS = [
  { id: 'live', label: 'Live', status: null },
  { id: 'reserved', label: 'Reserved', status: 'reserved' },
  { id: 'allocated', label: 'Allocated', status: 'allocated,active' },
  { id: 'ended', label: 'Released / expired', status: 'released,expired,retired' },
];

// --------------------------------------------------------------------------- list

export async function renderList(root, active = 'live') {
  mount(root, h('p', { class: 'muted' }, 'Loading…'));
  const f = FILTERS.find((x) => x.id === active);
  const sites = await get('/sites', { status: f.status });
  mount(root,
    h('div', { class: 'page-head' }, h('h1', {}, 'Sites'), h('div', { class: 'actions' }, can('sites.deploy') ? button('New site', () => { location.hash = '#/sites/new'; }, 'primary') : null)),
    h('div', { class: 'tabs' }, FILTERS.map((x) => h('button', { type: 'button', class: `tab ${x.id === active ? 'active' : ''}`, onClick: () => renderList(root, x.id) }, x.label))),
    card(null, table([
      { label: 'Site', value: (s) => h('a', { href: `#/sites/${encodeURIComponent(s.siteCode)}` }, s.siteCode) },
      { label: 'Status', value: (s) => chip(s.status) },
      { label: 'Block', value: (s) => s.blocks.map((b) => h('code', {}, b.cidr)) },
      { label: 'Template', value: (s) => (s.template ? `${s.template.key}@v${s.template.version}` : '—') },
      { label: 'Expires', value: (s) => (s.reservation ? h('span', { title: fmtTime(s.reservation.expiresAt) }, fromNow(s.reservation.expiresAt)) : '—') },
      { label: 'Code check', value: (s) => (s.siteCodeStatus === 'unverified' ? chip('unverified', 'deprecated') : chip(s.siteCodeStatus || '—')) },
      { label: 'Requested by', value: (s) => s.clientName || '' },
      { label: 'Created', value: (s) => fmtTime(s.createdAt) },
    ], sites, {
      onRowClick: (s) => { if (s.blocks.length || ['reserved', 'allocated', 'active', 'retired'].includes(s.status)) location.hash = `#/sites/${encodeURIComponent(s.siteCode)}`; },
      empty: 'No sites here yet.',
    })));
}

// --------------------------------------------------------------------------- new

export async function renderNew(root, query) {
  const [released, pools] = await Promise.all([get('/templates', { state: 'RELEASED' }), get('/pools')]);
  const idempotencyKey = crypto.randomUUID(); // one per form: a double-click can't reserve twice

  const code = input({ placeholder: 'e.g. X9', class: 'mono narrow' });
  const country = input({ value: 'AU', class: 'mono narrow' });
  const tpl = select(released.map((t) => ({ value: t.templateKey, label: `${t.templateKey} @v${t.versions[0].version}${t.description ? ' — ' + t.description : ''}` })), query?.get('template') || 'EXAMPLE-NET-10');
  const base = input({ placeholder: 'leave empty: the pool picks the next free block', class: 'mono wide' });
  const pool = select([{ value: '', label: 'Template default' }, ...pools.filter((p) => p.allocationPrefixLength).map((p) => ({ value: p.poolKey, label: `${p.poolKey} (/${p.allocationPrefixLength})` }))], '');
  const days = input({ type: 'number', value: 14, min: 1, max: 90, class: 'narrow' });
  const out = h('div');

  const body = () => ({
    siteCode: code.value.trim().toUpperCase(),
    countryCode: country.value.trim().toUpperCase() || null,
    templateKey: tpl.value,
    baseIp: base.value.trim() || null,
    pool: pool.value || null,
    reservationDays: Number(days.value) || null,
  });

  const preview = async () => {
    if (!code.value.trim()) { toast('Enter a site code', 'warn'); return; }
    mount(out, h('p', { class: 'muted' }, 'Working out the design…'));
    try {
      const r = await post('/sites?dryRun=true', body());
      mount(out, card('Preview (nothing reserved yet)',
        h('p', {}, `${r.siteCode} would get `, r.blocks.map((b) => h('strong', {}, b.cidr)), ` — ${r.subnetCount} subnets from ${r.template.key}@v${r.template.version}.`),
        h('p', { class: 'muted small' }, 'Another request could take this block before you reserve; reserving is what holds it.'),
        networksTable(r.networks.slice(0, 40)),
        r.networks.length > 40 ? h('p', { class: 'muted small' }, `…and ${r.networks.length - 40} more`) : null));
    } catch (err) { mount(out, errorPanel(err)); }
  };

  const reserve = async () => {
    if (!code.value.trim()) { toast('Enter a site code', 'warn'); return; }
    try {
      const r = await post('/sites', body(), { headers: { 'Idempotency-Key': idempotencyKey } });
      toast(`${r.siteCode} reserved: ${r.blocks.map((b) => b.cidr).join(', ')}`, 'success', 6000);
      location.hash = `#/sites/${encodeURIComponent(r.siteCode)}`;
    } catch (err) { mount(out, errorPanel(err)); }
  };

  mount(root,
    h('div', { class: 'crumbs' }, h('a', { href: '#/sites' }, 'Sites'), ' / new'),
    h('h1', {}, 'New site'),
    card('Step 1 of 2 — reserve',
      h('p', {}, 'Reserving holds the block, every subnet, the gateways and the standard server addresses for this site. Nothing is permanent until you confirm; an unconfirmed reservation lapses after the days below and the space goes back to the pool.'),
      h('div', { class: 'form-grid' },
        field('Site code', code, 'Used exactly as typed. New codes are registered as "unverified" for review.'),
        field('Country', country),
        field('Template', tpl, 'Only RELEASED templates are offered'),
        field('Base IP (optional)', base, 'e.g. 10.9.0.0 for a /16'),
        field('Pool', pool),
        field('Reservation lasts (days)', days)),
      h('div', { class: 'actions' }, button('Preview', preview), button('Reserve', reserve, 'primary'))),
    out);
  code.focus();
}

// --------------------------------------------------------------------------- detail

export async function renderDetail(root, code) {
  mount(root, h('p', { class: 'muted' }, 'Loading…'));
  const d = await get(`/sites/${encodeURIComponent(code)}/design`);
  const confirmed = ['allocated', 'active'].includes(d.status);
  const reload = () => renderDetail(root, code);

  const actions = [];
  if (d.status === 'reserved' && can('sites.confirm')) {
    actions.push(button('Confirm allocation', async () => {
      if (!(await confirmBox(`Confirm ${d.siteCode}`, `This makes ${d.blocks.map((b) => b.cidr).join(', ')} a permanent allocation for ${d.siteCode}. After this, host addresses can be assigned to machines.`, 'Confirm'))) return;
      try {
        await post(`/sites/${encodeURIComponent(code)}:confirm`, { reservationId: d.reservation.reservationId });
        toast(`${d.siteCode} confirmed`, 'success');
        reload();
      } catch (err) { modal({ title: 'Couldn\'t confirm', body: errorPanel(err) }); }
    }, 'primary'));
  }
  if (d.status === 'reserved' && can('sites.deploy')) {
    actions.push(button('Extend…', async () => {
      const days = input({ type: 'number', value: 14, min: 1, max: 90, class: 'narrow' });
      const v = await modal({ title: 'Extend reservation', body: field('New expiry: this many days from now', days), actions: [{ label: 'Cancel', value: null }, { label: 'Extend', kind: 'primary', value: () => Number(days.value) }] });
      if (!v) return;
      try { await post(`/sites/${encodeURIComponent(code)}:extend`, { days: v }); toast('Reservation extended', 'success'); reload(); } catch (err) { modal({ title: 'Couldn\'t extend', body: errorPanel(err) }); }
    }));
  }
  if (d.status === 'reserved' && can('sites.release')) {
    actions.push(button('Release', async () => {
      if (!(await confirmBox(`Release ${d.siteCode}`, 'Cancel this reservation. The block goes straight back to the pool.', 'Release', 'danger'))) return;
      try { await post(`/sites/${encodeURIComponent(code)}:release`); toast(`${d.siteCode} released`, 'success'); location.hash = '#/sites'; } catch (err) { modal({ title: 'Couldn\'t release', body: errorPanel(err) }); }
    }, 'danger'));
  }
  if (confirmed && can('sites.retire')) {
    actions.push(button('Retire site…', () => retireDialog(d, reload), 'danger'));
  }
  if (d.status === 'retired' && can('sites.retire')) {
    actions.push(button('Purge…', () => purgeDialog(d), 'danger'));
  }
  actions.push(button('Refresh', reload));

  const facts = [
    ['Status', h('span', {}, chip(d.status), ' ', d.allocationState === 'reserved' ? h('span', { class: 'muted' }, 'waiting for confirmation') : '')],
    ['Block', d.blocks.map((b) => h('span', {}, h('code', {}, b.cidr), ` ${b.vrf}${b.pool ? ' · from ' + b.pool : ' · base IP given'}`))],
    ['Template', d.template ? h('span', {}, h('a', { href: `#/templates/${encodeURIComponent(d.template.key)}/v/${d.template.version}` }, `${d.template.key}@v${d.template.version}`), ' ', chip(d.template.state), ' ', h('code', { title: d.template.contentHash }, shortHash(d.template.contentHash))) : '—'],
    ['Site code', h('span', {}, chip(d.siteCodeStatus || '—', d.siteCodeStatus === 'unverified' ? 'deprecated' : null), d.nonStandardSiteCode ? h('span', { class: 'badge' }, 'non-standard format') : null)],
    d.reservation ? ['Reservation expires', h('span', {}, fmtTime(d.reservation.expiresAt), ' ', h('span', { class: 'muted' }, `(${fromNow(d.reservation.expiresAt)})`))] : null,
    ['Created', `${fmtTime(d.createdAt)}${d.clientName ? ' · via ' + d.clientName : ''}`],
    d.confirmedAt ? ['Confirmed', fmtTime(d.confirmedAt)] : null,
    d.endedAt ? ['Ended', fmtTime(d.endedAt)] : null,
    d.retirement ? ['Retired', h('span', {}, `${fmtTime(d.retirement.retiredAt)} by ${d.retirement.retiredBy} — "${d.retirement.reason}"`, d.retirement.changeRef ? ` (${d.retirement.changeRef})` : '')] : null,
    d.retirement ? ['Address space', d.retirement.spaceReleasedAt
      ? `returned to the pool ${fmtTime(d.retirement.spaceReleasedAt)}`
      : h('span', {}, 'quarantined until ', h('strong', {}, fmtTime(d.retirement.quarantineUntil)), ` (${fromNow(d.retirement.quarantineUntil)}), then returned to the pool`)] : null,
  ].filter(Boolean);

  mount(root,
    h('div', { class: 'crumbs' }, h('a', { href: '#/sites' }, 'Sites'), ' / ', d.siteCode),
    h('div', { class: 'page-head' }, h('h1', {}, d.siteCode), h('div', { class: 'actions' }, actions)),
    card(null, h('dl', { class: 'facts' }, facts.map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)]))),
    d.networks.length ? designCard(d, confirmed, reload) : card('Design', h('p', { class: 'muted' }, `This site is ${d.status}; its address space has been returned to the pool.`)));
}

function designCard(d, confirmed, reload) {
  const sections = [...new Set(d.networks.map((n) => n.section))];
  const secSel = select([{ value: '', label: 'All sections' }, ...sections], '');
  const text = input({ placeholder: 'Filter by VLAN, CIDR or host…' });
  const withHosts = h('input', { type: 'checkbox' });
  const box = h('div');
  const draw = () => {
    const q = text.value.trim().toLowerCase();
    const rows = d.networks.filter((n) =>
      (!secSel.value || n.section === secSel.value)
      && (!withHosts.checked || n.hosts?.length)
      && (!q || [n.cidr, n.vlanKey, n.vlanName, n.vlanId, ...(n.hosts || []).flatMap((x) => [x.member, x.ip, x.hostname])].join(' ').toLowerCase().includes(q)));
    mount(box, h('p', { class: 'muted small' }, `${rows.length} of ${d.networks.length} subnets`), rows.length ? h('div', { class: 'table-wrap tall' }, h('table', { class: 'grid' },
      h('thead', {}, h('tr', {}, ['Section', 'VLAN ID', 'VLAN', 'CIDR', 'Gateway', 'Mask', 'Hosts'].map((x) => h('th', {}, x)))),
      h('tbody', {}, rows.flatMap((n) => networkRows(d, n, confirmed, reload))))) : h('p', { class: 'muted' }, 'No subnets match.'));
  };
  [secSel, withHosts].forEach((el) => el.addEventListener('change', draw));
  text.addEventListener('input', draw);
  draw();
  const csv = () => downloadCsv(`${d.siteCode}-design.csv`,
    ['section', 'vlanId', 'vlanKey', 'vlanName', 'cidr', 'gateway', 'mask', 'prefix', 'member', 'ip', 'hostname', 'status'],
    d.networks.flatMap((n) => (n.hosts?.length ? n.hosts : [null]).map((x) => [n.section, n.vlanId, n.vlanKey, n.vlanName, n.cidr, n.gateway, n.mask, n.prefix, x?.member, x?.ip, x?.hostname, x?.status])));
  return card('Design',
    h('div', { class: 'row' }, secSel, text, h('label', { class: 'check' }, withHosts, ' only subnets with hosts'), h('span', { class: 'spacer' }), button('Download CSV', csv, 'small')),
    confirmed ? null : h('p', { class: 'muted small' }, 'Host addresses are held but can\'t be assigned to machines until the allocation is confirmed.'),
    box);
}

function networkRows(d, n, confirmed, reload) {
  const main = h('tr', { class: n.hosts?.length ? 'has-hosts' : '' },
    h('td', {}, n.section), h('td', { class: 'num' }, n.vlanId ?? '—'),
    h('td', {}, n.vlanKey ? h('span', {}, n.vlanKey, h('div', { class: 'muted small' }, n.vlanName)) : h('span', { class: 'muted' }, 'unassigned')),
    h('td', {}, h('code', {}, n.cidr)), h('td', {}, h('code', {}, n.gateway)), h('td', {}, n.mask),
    h('td', {}, n.hosts?.length ? `${n.hosts.length}` : ''));
  if (!n.hosts?.length) return [main];
  const hostRows = h('tr', { class: 'sub' }, h('td', { colspan: 7 }, table([
    { label: 'Member', value: (x) => x.member },
    { label: 'Role', value: (x) => x.roleCode },
    { label: 'Position', value: (x) => x.hostPosition },
    { label: 'Octet', value: (x) => chip(x.octetUsed) },
    { label: 'IP', value: (x) => h('span', {}, h('code', {}, x.ip), ' ', copyButton(x.ip)) },
    { label: 'Hostname', value: (x) => x.hostname || h('span', { class: 'muted' }, '—') },
    { label: 'Status', value: (x) => chip(x.status) },
    { label: '', value: (x) => (x.status === 'reserved-pattern' && can('hosts.assign') ? button('Assign…', () => assign(d, n, x, reload), 'small', { disabled: !confirmed, title: confirmed ? 'Claim this address for a machine' : 'Confirm the site first' }) : '') },
  ], n.hosts)));
  return [main, hostRows];
}

async function retireDialog(d, reload) {
  const reason = input({ class: 'wide', placeholder: 'e.g. Site decommissioned; customer exit' });
  const change = input({ class: 'mono', placeholder: 'e.g. CHG0012345' });
  const force = h('input', { type: 'checkbox' });
  const confirmCode = input({ class: 'mono narrow', placeholder: d.siteCode });
  const out = h('div');
  const assigned = d.networks.flatMap((n) => (n.hosts || []).filter((x) => x.status === 'assigned'));
  const ok = await modal({
    title: `Retire ${d.siteCode}`,
    body: h('div', {},
      h('p', {}, 'Retiring deletes the site. Straight away its code is free to reuse and it stops answering lookups. Its address space (', d.blocks.map((b) => h('code', {}, b.cidr)),
        ') is ', h('strong', {}, 'quarantined'), ' first, so addresses still in DNS, firewall rules or device configs aren\'t handed to a new site; after that it returns to the pool on its own.'),
      assigned.length ? h('div', { class: 'alert alert-warn compact' }, `${assigned.length} host(s) are still assigned to machines: ${assigned.slice(0, 6).map((x) => x.hostname).join(', ')}${assigned.length > 6 ? '…' : ''}.`) : null,
      h('div', { class: 'form-grid' }, field('Reason', reason, 'Recorded in the audit log'), field('Change reference', change, 'Optional')),
      assigned.length ? h('label', { class: 'check' }, force, ' Retire anyway; those machines are being decommissioned too') : null,
      field(`Type ${d.siteCode} to confirm`, confirmCode),
      h('p', { class: 'muted small' }, 'You\'ll be asked for a code from your authenticator app.'),
      out),
    actions: [{ label: 'Cancel', value: false }, {
      label: 'Retire site', kind: 'danger', value: true,
      validate: async () => {
        if (confirmCode.value.trim().toUpperCase() !== d.siteCode) { mount(out, h('div', { class: 'alert alert-error compact' }, `Type ${d.siteCode} to confirm`)); return false; }
        try {
          await post(`/sites/${encodeURIComponent(d.siteCode)}:retire`, { reason: reason.value.trim(), changeRef: change.value.trim() || null, force: force.checked });
          return true;
        } catch (err) { mount(out, errorPanel(err)); return false; }
      },
    }],
  });
  if (ok) { toast(`${d.siteCode} retired`, 'success'); reload(); }
}

async function purgeDialog(d) {
  const r = d.retirement;
  const early = !r.spaceReleasedAt && new Date(r.quarantineUntil) > new Date();
  const reason = input({ class: 'wide', placeholder: 'e.g. Test site created by mistake' });
  const confirmCode = input({ class: 'mono narrow', placeholder: d.siteCode });
  const out = h('div');
  const ok = await modal({
    title: `Purge ${d.siteCode}`,
    body: h('div', {},
      h('p', {}, 'Purging removes the retired site\'s record for good. The audit trail is kept.'),
      early ? h('div', { class: 'alert alert-warn' },
        h('strong', {}, 'Its address space is still quarantined'), ` until ${fmtTime(r.quarantineUntil)}. Purging now returns `, d.blocks.map((b) => h('code', {}, b.cidr)),
        ' to the pool straight away, so it could be handed to a new site while old DNS records or firewall rules still point at it. Only do this for test sites or mistakes.') : null,
      early ? field('Why release it early?', reason, 'Required; recorded in the audit log') : null,
      field(`Type ${d.siteCode} to confirm`, confirmCode),
      out),
    actions: [{ label: 'Cancel', value: false }, {
      label: early ? 'Purge and release now' : 'Purge', kind: 'danger', value: true,
      validate: async () => {
        if (confirmCode.value.trim().toUpperCase() !== d.siteCode) { mount(out, h('div', { class: 'alert alert-error compact' }, `Type ${d.siteCode} to confirm`)); return false; }
        try {
          await post(`/sites/${encodeURIComponent(d.siteCode)}:purge`, { releaseNow: early, reason: early ? reason.value.trim() : null });
          return true;
        } catch (err) { mount(out, errorPanel(err)); return false; }
      },
    }],
  });
  if (ok) { toast(`${d.siteCode} purged`, 'success'); location.hash = '#/sites'; }
}

async function assign(d, n, x, reload) {
  const hostname = input({ class: 'mono wide', placeholder: `e.g. AU${d.siteCode}OT${x.member}` });
  const status = h('div');
  const ok = await modal({
    title: `Assign ${x.member} at ${d.siteCode}`,
    body: h('div', {}, h('p', {}, `Claim `, h('code', {}, x.ip), ` on ${n.vlanKey} for a named machine. It's recorded against the hostname and audited.`), field('Hostname', hostname), status),
    actions: [{ label: 'Cancel', value: false }, {
      label: 'Assign', kind: 'primary', value: true,
      validate: async () => {
        try {
          await get('/lookup/host-ip', { site: d.siteCode, vlan: n.vlanKey, host: x.member, resolve: 'assign', hostname: hostname.value.trim() });
          return true;
        } catch (err) { mount(status, errorPanel(err)); return false; }
      },
    }],
  });
  if (ok) { toast(`${x.ip} assigned to ${hostname.value.trim().toUpperCase()}`, 'success'); reload(); }
}

export function networksTable(networks) {
  return table([
    { label: 'Section', value: (n) => n.section },
    { label: 'VLAN ID', value: (n) => n.vlanId ?? '—', class: 'num' },
    { label: 'VLAN', value: (n) => n.vlanKey || h('span', { class: 'muted' }, 'unassigned') },
    { label: 'CIDR', value: (n) => h('code', {}, n.cidr) },
    { label: 'Gateway', value: (n) => h('code', {}, n.gateway) },
    { label: 'Hosts', value: (n) => (n.hosts || []).map((x) => `${x.member} ${x.ip}`).join(', ') },
  ], networks);
}
