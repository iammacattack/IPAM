import { get, post, errorPanel } from '../api.js';
import {
  h, mount, card, chip, table, tabs, fmtTime, shortHash, button, input, field, modal, toast, copyButton,
} from '../dom.js';

// --------------------------------------------------------------------------- list

export async function renderList(root) {
  mount(root, h('p', { class: 'muted' }, 'Loading…'));
  const [all, sites] = await Promise.all([get('/templates'), get('/sites')]);
  mount(root,
    h('div', { class: 'page-head' },
      h('h1', {}, 'Site templates'),
      h('div', { class: 'actions' }, button('New template', () => { location.hash = '#/builder/new'; }, 'primary'))),
    h('p', { class: 'muted' }, 'Only RELEASED versions can be deployed to a site. Drafts are editable in the builder; released versions are frozen.'),
    card(null, table([
      { label: 'Template', value: (t) => h('a', { href: `#/templates/${encodeURIComponent(t.templateKey)}` }, t.templateKey) },
      { label: 'Description', value: (t) => t.description || '' },
      { label: 'Versions', value: (t) => h('span', { class: 'chips' }, t.versions.map((v) => h('span', {}, `v${v.version} `, chip(v.state)))) },
      { label: 'Released', value: (t) => { const r = t.versions.find((v) => v.state === 'RELEASED'); return r ? `v${r.version}` : '—'; } },
      { label: 'Subnets', value: (t) => { const v = t.versions[t.versions.length - 1]; return v?.summary?.subnetCount ?? '—'; }, class: 'num' },
      { label: 'Live sites', value: (t) => sites.filter((s) => s.template?.key === t.templateKey).length, class: 'num' },
    ], all, { onRowClick: (t) => { location.hash = `#/templates/${encodeURIComponent(t.templateKey)}`; }, empty: 'No templates yet.' })));
}

// --------------------------------------------------------------------------- detail

export async function renderDetail(root, key, version) {
  mount(root, h('p', { class: 'muted' }, 'Loading…'));
  const t = await get(`/templates/${encodeURIComponent(key)}`);
  if (!t.versions.length) throw new Error('This template has no versions');
  const chosen = version ?? (t.versions.find((v) => v.state === 'RELEASED') || t.versions[t.versions.length - 1]).version;
  const v = await get(`/templates/${encodeURIComponent(key)}/versions/${chosen}`);
  const layout = await post('/templates:layout', { content: v.content });

  const body = h('div');
  let active = 'layout';
  const show = async (id) => {
    active = id;
    mount(tabBar, tabs(TABS, active, show));
    mount(body, h('p', { class: 'muted' }, 'Loading…'));
    try {
      mount(body, await TAB_RENDER[id]({ key, v, layout }));
    } catch (err) {
      mount(body, errorPanel(err));
    }
  };
  const tabBar = h('div');

  const actions = [];
  if (v.state === 'DRAFT') {
    actions.push(button('Edit in builder', () => { location.hash = `#/builder/${encodeURIComponent(key)}/${v.version}`; }, 'primary'));
    actions.push(button('Release…', () => releaseDialog(key, v, layout), ''));
  }
  actions.push(button('New draft from this version', async () => {
    try {
      const nv = await post(`/templates/${encodeURIComponent(key)}/versions`, { fromVersion: v.version });
      toast(`Created ${nv.ref} (DRAFT)`, 'success');
      location.hash = `#/builder/${encodeURIComponent(key)}/${nv.version}`;
    } catch (err) { modal({ title: 'Couldn\'t create a draft', body: errorPanel(err) }); }
  }));
  actions.push(button('Deploy to a site…', () => { location.hash = `#/sites/new?template=${encodeURIComponent(key)}`; }, '', { disabled: v.state !== 'RELEASED' }));

  mount(root,
    h('div', { class: 'crumbs' }, h('a', { href: '#/templates' }, 'Templates'), ' / ', key),
    h('div', { class: 'page-head' }, h('h1', {}, key, ' ', h('span', { class: 'muted' }, `v${v.version}`), ' ', chip(v.state)), h('div', { class: 'actions' }, actions)),
    t.description ? h('p', {}, t.description) : null,
    card('Versions', table([
      { label: 'Version', value: (x) => h('a', { href: `#/templates/${encodeURIComponent(key)}/v/${x.version}` }, `v${x.version}`) },
      { label: 'State', value: (x) => chip(x.state) },
      { label: 'Content hash', value: (x) => h('code', { title: x.contentHash }, shortHash(x.contentHash)) },
      { label: 'Subnets', value: (x) => x.summary?.subnetCount ?? '—', class: 'num' },
      { label: 'Created', value: (x) => `${fmtTime(x.createdAt)} · ${x.createdBy || ''}` },
      { label: 'Released', value: (x) => x.releasedAt ? `${fmtTime(x.releasedAt)} · ${x.releasedBy || ''}` : '—' },
      { label: 'Live sites', value: (x) => x.siteCount ?? 0, class: 'num' },
    ], t.versions, { rowClass: (x) => (x.version === v.version ? 'selected' : '') })),
    h('div', { class: 'card' }, tabBar, body));
  show(active);
}

const TABS = [
  { id: 'layout', label: 'Layout' },
  { id: 'placement', label: 'Host placement' },
  { id: 'validation', label: 'Validation' },
  { id: 'preview', label: 'Preview at a base IP' },
  { id: 'sites', label: 'Sites using it' },
  { id: 'json', label: 'JSON' },
];

const TAB_RENDER = {
  layout: ({ layout }) => layoutView(layout),
  placement: async ({ key, v }) => {
    const m = await get(`/templates/${encodeURIComponent(key)}/versions/${v.version}/placement`);
    return h('div', {},
      h('p', { class: 'muted' }, 'Every fixed host-pool member on every VLAN it lives on, relative to the site block (0.0.x.y). Conflicts block release; calculated and supernet placements are only highlighted.'),
      table([
        { label: 'Role', value: (p) => p.roleCode },
        { label: 'Member', value: (p) => p.member },
        { label: 'VLAN', value: (p) => p.vlanKey },
        { label: 'Subnet (relative)', value: (p) => h('code', {}, p.subnet) },
        { label: 'Position', value: (p) => p.hostPosition },
        { label: 'Address (relative)', value: (p) => p.ip ? h('code', {}, p.ip) : '—' },
        { label: 'Octet used', value: (p) => p.octetUsed ? chip(p.octetUsed) : '—' },
        { label: 'Notes', value: (p) => p.conflict ? h('span', { class: 'error-text' }, p.conflict.message) : (p.warnings || []).join('; ') },
      ], m.placements, { empty: 'No host pools live on this template\'s VLANs.', rowClass: (p) => (p.conflict ? 'row-error' : (p.warnings?.length ? 'row-warn' : '')) }));
  },
  validation: ({ layout }) => validationView(layout),
  preview: ({ key, v }) => previewView(key, v),
  sites: async ({ key, v }) => {
    const sites = (await get('/sites', { status: 'reserved,allocated,active,decommissioning' }))
      .filter((s) => s.template?.key === key && s.template?.version === v.version);
    return table([
      { label: 'Site', value: (s) => h('a', { href: `#/sites/${encodeURIComponent(s.siteCode)}` }, s.siteCode) },
      { label: 'Status', value: (s) => chip(s.status) },
      { label: 'Block', value: (s) => s.blocks.map((b) => b.cidr).join(', ') },
      { label: 'Created', value: (s) => fmtTime(s.createdAt) },
    ], sites, { empty: 'No live sites use this version.' });
  },
  json: ({ v }) => h('div', {}, copyButton(JSON.stringify(v.content, null, 2), 'Copy JSON'), h('pre', { class: 'json' }, JSON.stringify(v.content, null, 2))),
};

export function layoutView(layout, { filterable = true } = {}) {
  if (!layout.summary) return validationView(layout);
  const filter = input({ placeholder: 'Filter by CIDR, section or VLAN…', class: 'wide' });
  const rowsBox = h('div');
  const draw = () => {
    const q = filter.value.trim().toLowerCase();
    const rows = layout.subnets.filter((s) => !q || [s.relativeCidr, s.section, s.vlanKey, s.vlanName, s.vlanId].join(' ').toLowerCase().includes(q));
    mount(rowsBox, table([
      { label: 'Relative CIDR', value: (s) => h('code', {}, s.relativeCidr) },
      { label: 'Size', value: (s) => `/${s.prefix}` },
      { label: 'Section', value: (s) => s.section },
      { label: 'VRF', value: (s) => s.vrf },
      { label: 'VLAN ID', value: (s) => s.vlanId ?? '—', class: 'num' },
      { label: 'VLAN', value: (s) => s.vlanKey ? h('span', {}, s.vlanKey, s.fromRule ? h('span', { class: 'badge' }, 'rule') : null, s.newVlan ? h('span', { class: 'badge badge-new' }, 'new') : null) : h('span', { class: 'muted' }, 'unassigned') },
      { label: 'VLAN name', value: (s) => s.vlanName || '' },
    ], rows));
  };
  filter.addEventListener('input', draw);
  draw();
  return h('div', {},
    table([
      { label: 'Section', value: (s) => s.sectionKey },
      { label: 'VRF', value: (s) => s.vrf },
      { label: 'Starts at', value: (s) => h('code', {}, s.start) },
      { label: 'Units', value: (s) => s.units, class: 'num' },
      { label: 'Subnets', value: (s) => s.subnets, class: 'num' },
      { label: 'By size', value: (s) => Object.entries(s.bySize).map(([k, n]) => `${n} × ${k}`).join(', ') },
      { label: 'VLAN-bound', value: (s) => s.bound, class: 'num' },
    ], layout.summary.sections),
    h('p', { class: 'total' }, h('strong', {}, layout.summary.subnetCount), ' subnets in total'),
    filterable ? filter : null,
    rowsBox);
}

export function validationView(report) {
  return h('div', {},
    report.valid
      ? h('div', { class: 'alert alert-ok' }, '✔ Passes release validation')
      : h('div', { class: 'alert alert-error' }, h('strong', {}, `✖ ${report.errors.length} problem(s) block release`),
        h('ul', {}, report.errors.map((e) => h('li', {}, h('code', {}, e.code), ' ', e.message, e.suggested ? ` (suggested: ${e.suggested})` : '')))),
    report.warnings?.length ? h('div', { class: 'alert alert-warn' }, h('strong', {}, 'Warnings'), h('ul', {}, report.warnings.map((w) => h('li', {}, w)))) : null,
    report.placement ? h('p', { class: 'muted' }, `Host placement: ${report.placement.members} member placement(s), ${report.placement.conflicts} conflict(s), ${report.placement.highlighted.length} highlighted.`) : null,
    report.newVlans?.length ? h('p', { class: 'muted' }, `${report.newVlans.length} VLAN(s) will be added to the library by the bulk rule when this is saved.`) : null);
}

function previewView(key, v) {
  const base = input({ placeholder: 'e.g. 10.9.0.0 — leave empty to see what the pool would pick' , class: 'wide' });
  const out = h('div');
  const run = async () => {
    mount(out, h('p', { class: 'muted' }, 'Computing…'));
    try {
      const p = await get(`/templates/${encodeURIComponent(key)}/preview`, { version: v.version, baseIp: base.value.trim() });
      mount(out,
        h('div', { class: 'alert' }, 'Nothing is saved. ', p.blocks.map((b) => h('span', {}, `Block ${b.blockKey}: `, h('strong', {}, b.cidr), b.nonBinding ? ` (next free in ${b.pool}; not held)` : ''))),
        networksTable(p.networks));
    } catch (err) { mount(out, errorPanel(err)); }
  };
  base.addEventListener('keydown', (e) => { if (e.key === 'Enter') run(); });
  return h('div', {}, h('div', { class: 'row' }, field('Base IP', base), button('Preview', run, 'primary')), out);
}

export function networksTable(networks) {
  return table([
    { label: 'Section', value: (n) => n.section },
    { label: 'VLAN ID', value: (n) => n.vlanId ?? '—', class: 'num' },
    { label: 'VLAN', value: (n) => n.vlanKey || h('span', { class: 'muted' }, 'unassigned') },
    { label: 'CIDR', value: (n) => h('code', {}, n.cidr) },
    { label: 'Gateway', value: (n) => h('code', {}, n.gateway) },
    { label: 'Mask', value: (n) => n.mask },
    { label: 'Hosts', value: (n) => (n.hosts || []).map((x) => `${x.member} ${x.ip}`).join(', ') },
  ], networks);
}

export async function releaseDialog(key, v, layout) {
  if (!layout.valid) {
    await modal({ title: 'Can\'t release yet', body: validationView(layout) });
    return;
  }
  const notes = h('textarea', { rows: 3, class: 'wide', placeholder: 'What this version is and what changed' });
  const evidence = input({ class: 'wide', placeholder: 'e.g. validation passed; preview at 10.9.0.0 checked' });
  const status = h('div');
  const ok = await modal({
    title: `Release ${key}@v${v.version}`,
    body: h('div', {},
      h('p', {}, 'Releasing makes this the version delivery tools can deploy. The current RELEASED version (if any) becomes DEPRECATED if sites use it, otherwise RETIRED. This can\'t be undone.'),
      field('Release notes', notes), field('Evidence', evidence), status),
    actions: [
      { label: 'Cancel', value: false },
      {
        label: 'Release', kind: 'primary', value: true,
        validate: async () => {
          try {
            await post(`/templates/${encodeURIComponent(key)}/versions/${v.version}:release`, { releaseNotes: notes.value, evidence: evidence.value });
            return true;
          } catch (err) { mount(status, errorPanel(err)); return false; }
        },
      },
    ],
  });
  if (ok) {
    toast(`${key}@v${v.version} released`, 'success');
    location.hash = `#/templates/${encodeURIComponent(key)}/v/${v.version}`;
    window.dispatchEvent(new HashChangeEvent('hashchange'));
  }
}
