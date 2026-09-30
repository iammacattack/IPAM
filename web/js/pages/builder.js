// Template builder (Workflow 1). Edits template content in the browser; the server lays it out
// (POST /templates:layout) after every change, so what you see is exactly what will be saved.
import { get, post, patch, errorPanel } from '../api.js';
import {
  h, mount, card, chip, table, button, input, select, field, modal, confirmBox, toast, datalist, debounce,
} from '../dom.js';
import { supernet, overlaps, contains, parseCidr, relocate, size } from '../net.js';
import { setLeaveGuard } from '../main.js';
import { can } from '../session.js';
import { releaseDialog } from './templates.js';

const ZONES = ['', 'Internal', 'DataCentre', 'DMZ', 'OOB', 'Perimeter'];
const BLANK = {
  blocks: [{
    blockKey: 'SITE', prefixLength: 16, vrf: 'NXT', defaultPool: 'SITE-POOL-AU', unitPrefix: 24,
    sections: [{ sectionKey: 'CORP', orgDomain: 'IT', vrf: 'CORP', extent: { start: 'auto', units: 12 }, subnetOverrides: [], vlanBindings: [] }],
  }],
};

let st;

export async function render(root, key, version) {
  mount(root, h('p', { class: 'muted' }, 'Loading…'));
  const [vlans, vrfs, pools, released] = await Promise.all([get('/vlans'), get('/vrfs'), get('/pools'), get('/templates', { state: 'RELEASED' })]);
  st = {
    key, version, isNew: !key, description: '', content: structuredClone(BLANK), state: 'DRAFT',
    dirty: false, layout: null, vlans, vrfs: vrfs.map((v) => v.vrfKey), pools: pools.map((p) => p.poolKey), released,
    filter: { section: '', text: '', unbound: false }, base: '',
  };
  if (key) {
    const [t, v] = await Promise.all([get(`/templates/${encodeURIComponent(key)}`), get(`/templates/${encodeURIComponent(key)}/versions/${version}`)]);
    if (v.state !== 'DRAFT') {
      toast(`${v.ref} is ${v.state} and can't be edited. Create a new draft from it.`, 'warn', 6000);
      location.hash = `#/templates/${encodeURIComponent(key)}/v/${version}`;
      return;
    }
    st.description = t.description || '';
    st.content = v.content;
    st.contentHash = v.contentHash;
  }

  setLeaveGuard(() => (st.dirty ? confirmBox('Unsaved changes', 'You have unsaved changes to this template. Leave and lose them?', 'Leave', 'danger') : true));
  window.onbeforeunload = () => (st.dirty ? true : undefined);

  st.el = {
    head: h('div'), sections: h('div'), status: h('div', { class: 'builder-status' }), subnets: h('div'),
  };
  mount(root,
    h('div', { class: 'crumbs' }, h('a', { href: '#/templates' }, 'Templates'), ' / ', key ? h('a', { href: `#/templates/${encodeURIComponent(key)}` }, key) : 'New', ' / builder'),
    h('div', { class: 'page-head' }, h('h1', {}, key ? `${key} v${version} ` : 'New template ', chip('DRAFT'))),
    datalist('vlan-keys', vlans.flatMap((v) => [v.vlanKey])),
    st.el.head, st.el.sections, st.el.status, st.el.subnets);
  renderHead();
  renderSections();
  await recompute();
}

const blk = () => st.content.blocks[0];
const sec = (k) => blk().sections.find((s) => s.sectionKey === k);

function changed() {
  st.dirty = true;
  scheduleRecompute();
}
const scheduleRecompute = debounce(() => recompute(), 250);

async function recompute() {
  try {
    st.layout = await post('/templates:layout', { content: st.content });
  } catch (err) {
    st.layout = { valid: false, errors: [{ code: err.code, message: err.message }], subnets: [], summary: null, newVlans: [], warnings: [] };
  }
  renderStatus();
  renderSubnets();
}

// --------------------------------------------------------------------------- head: key, description, block

function renderHead() {
  const b = blk();
  const keyInput = input({ value: st.key || '', placeholder: 'e.g. CAT-100', disabled: !st.isNew, class: 'mono' });
  keyInput.addEventListener('change', () => { keyInput.value = keyInput.value.trim().toUpperCase(); st.newKey = keyInput.value; st.dirty = true; });
  const desc = input({ value: st.description, placeholder: 'What this template is for', class: 'wide' });
  desc.addEventListener('change', () => { st.description = desc.value; st.dirty = true; });

  const num = (label, prop, options) => {
    const el = select(options.map((p) => ({ value: p, label: `/${p}` })), b[prop]);
    el.addEventListener('change', () => { b[prop] = Number(el.value); changed(); });
    return field(label, el);
  };
  const vrf = select(st.vrfs, b.vrf);
  vrf.addEventListener('change', () => { b.vrf = vrf.value; changed(); });
  const pool = select(st.pools, b.defaultPool);
  pool.addEventListener('change', () => { b.defaultPool = pool.value; changed(); });

  let starter = null;
  if (st.isNew) {
    starter = select([{ value: '', label: 'Blank (one CORP section)' }, ...st.released.map((t) => ({ value: t.templateKey, label: `Copy of ${t.templateKey}@v${t.versions[0].version}` }))], '');
    starter.addEventListener('change', async () => {
      if (!starter.value) { st.content = structuredClone(BLANK); }
      else {
        const t = st.released.find((x) => x.templateKey === starter.value);
        const v = await get(`/templates/${encodeURIComponent(t.templateKey)}/versions/${t.versions[0].version}`);
        st.content = v.content;
      }
      st.dirty = true;
      renderHead();
      renderSections();
      recompute();
    });
  }

  mount(st.el.head, card('Template',
    h('div', { class: 'form-grid' },
      field('Template key', keyInput, st.isNew ? 'UPPER-KEBAB, e.g. CAT-100. Can\'t be changed later.' : null),
      field('Description', desc),
      starter ? field('Start from', starter) : null),
    blk().sections && st.content.blocks.length > 1 ? h('div', { class: 'alert alert-warn' }, `This template has ${st.content.blocks.length} blocks; the builder edits the first (${b.blockKey}). Others are kept unchanged.`) : null,
    h('h3', {}, `Block ${b.blockKey}`),
    h('div', { class: 'form-grid' },
      num('Block size', 'prefixLength', [16, 17, 18, 19, 20, 21, 22, 23, 24]),
      num('Section unit', 'unitPrefix', [22, 23, 24, 25, 26]),
      field('Block VRF', vrf),
      field('Default pool', pool, 'Where a site gets its block when no base IP is given'))));
}

// --------------------------------------------------------------------------- sections

function extentText(s) {
  const u = s.extent.units;
  const size = u === 'remaining' ? 'the rest of the block' : typeof u === 'object' ? `up to ${u.upTo} units` : `${u} unit(s)`;
  return `${s.extent.start && s.extent.start !== 'auto' ? `from ${s.extent.start}, ` : ''}${size}`;
}

function renderSections() {
  const b = blk();
  const rows = b.sections.map((s, i) => {
    const key = input({ value: s.sectionKey, class: 'mono narrow' });
    key.addEventListener('change', () => { s.sectionKey = key.value.trim().toUpperCase() || s.sectionKey; key.value = s.sectionKey; changed(); });
    const org = select(['', 'IT', 'OT'], s.orgDomain || '');
    org.addEventListener('change', () => { s.orgDomain = org.value || undefined; changed(); });
    const vrf = select(st.vrfs, s.vrf);
    vrf.addEventListener('change', () => { s.vrf = vrf.value; changed(); });

    const startMode = select([{ value: 'auto', label: 'after previous' }, { value: 'at', label: 'at offset' }], s.extent.start && s.extent.start !== 'auto' ? 'at' : 'auto');
    const startAt = input({ value: s.extent.start && s.extent.start !== 'auto' ? s.extent.start : '', placeholder: '0.0.64.0', class: 'mono narrow', hidden: startMode.value === 'auto' });
    const applyStart = () => { s.extent.start = startMode.value === 'auto' ? 'auto' : (startAt.value.trim() || '0.0.0.0'); startAt.hidden = startMode.value === 'auto'; changed(); };
    startMode.addEventListener('change', applyStart);
    startAt.addEventListener('change', applyStart);

    const u = s.extent.units;
    const sizeMode = select([{ value: 'units', label: 'units' }, { value: 'remaining', label: 'remaining' }, { value: 'upTo', label: 'up to' }],
      u === 'remaining' ? 'remaining' : typeof u === 'object' ? 'upTo' : 'units');
    const count = input({ type: 'number', min: 1, value: typeof u === 'number' ? u : (u?.upTo ?? 1), class: 'narrow', hidden: sizeMode.value === 'remaining' });
    const applySize = () => {
      const n = Math.max(1, Number(count.value) || 1);
      s.extent.units = sizeMode.value === 'remaining' ? 'remaining' : sizeMode.value === 'upTo' ? { upTo: n } : n;
      count.hidden = sizeMode.value === 'remaining';
      changed();
    };
    sizeMode.addEventListener('change', applySize);
    count.addEventListener('change', applySize);

    const splitAll = select([{ value: '', label: `/${b.unitPrefix} (default)` }, ...[1, 2, 3].map((d) => ({ value: b.unitPrefix + d, label: `split all to /${b.unitPrefix + d}` }))], '', { class: 'small-select' });
    splitAll.addEventListener('change', () => { if (splitAll.value) doSplitAll(s, Number(splitAll.value)); splitAll.value = ''; });

    const rule = s.vlanRule
      ? `${s.vlanRule.idBase} + 3rd octet${s.vlanRule.positionStep !== 100 ? ` (+${s.vlanRule.positionStep ?? 100}/half)` : ''}`
      : 'none';
    return h('tr', {},
      h('td', {}, key), h('td', {}, org), h('td', {}, vrf),
      h('td', {}, h('div', { class: 'inline' }, startMode, startAt)),
      h('td', {}, h('div', { class: 'inline' }, count, sizeMode)),
      h('td', {}, splitAll),
      h('td', {}, h('button', { type: 'button', class: 'btn btn-small', title: 'Bulk VLAN rule for this section', onClick: () => ruleDialog(s) }, `VLAN rule: ${rule}`)),
      h('td', { class: 'nowrap' },
        button('↑', () => move(i, -1), 'small', { disabled: i === 0, title: 'Move up' }),
        button('↓', () => move(i, 1), 'small', { disabled: i === b.sections.length - 1, title: 'Move down' }),
        button('✕', () => removeSection(i), 'small', { title: 'Remove section' })));
  });
  mount(st.el.sections, card('Sections',
    h('p', { class: 'muted small' }, `The block is ${2 ** (b.unitPrefix - b.prefixLength)} × /${b.unitPrefix} units. Sections are laid out in order; "remaining" takes everything up to the next pinned section or the end of the block.`),
    h('div', { class: 'table-wrap' }, h('table', { class: 'grid' },
      h('thead', {}, h('tr', {}, ['Section', 'Org', 'VRF', 'Starts', 'Size', 'Subnet size', 'Bulk VLANs', ''].map((x) => h('th', {}, x)))),
      h('tbody', {}, rows))),
    button('+ Add section', addSection)));
}

function move(i, d) {
  const s = blk().sections;
  [s[i], s[i + d]] = [s[i + d], s[i]];
  renderSections();
  changed();
}

async function removeSection(i) {
  const s = blk().sections[i];
  if (!(await confirmBox('Remove section', `Remove section ${s.sectionKey} with its splits, merges and VLAN bindings?`, 'Remove', 'danger'))) return;
  blk().sections.splice(i, 1);
  renderSections();
  changed();
}

function addSection() {
  const n = blk().sections.length + 1;
  blk().sections.push({ sectionKey: `SECTION${n}`, vrf: 'DCS', extent: { start: 'auto', units: 1 }, subnetOverrides: [], vlanBindings: [] });
  renderSections();
  changed();
}

async function ruleDialog(s) {
  const r = s.vlanRule || {};
  const on = h('input', { type: 'checkbox', checked: Boolean(s.vlanRule) });
  const idBase = input({ type: 'number', value: r.idBase ?? (s.sectionKey === 'CORP' ? 3000 : 2000) });
  const step = input({ type: 'number', value: r.positionStep ?? 100 });
  const cls = input({ value: r.class ?? s.sectionKey, class: 'mono' });
  const zone = select(ZONES, r.securityZone ?? (s.sectionKey === 'CORP' ? 'Internal' : 'DataCentre'));
  const res = await modal({
    title: `Bulk VLAN rule — ${s.sectionKey}`,
    body: h('div', {},
      h('p', {}, 'Names every subnet in this section that you haven\'t bound yourself. VLAN ID = base + the subnet\'s third octet; for split subnets, each extra half adds the step (e.g. lower /25 = 3001, upper = 3101). Keys look like ', h('code', {}, `${s.sectionKey}-N013`), ', names like ', h('code', {}, `v2013-${s.sectionKey}-13`), '. The VLANs are created in the library when you save.'),
      h('label', { class: 'check' }, on, ' Use a bulk rule for this section'),
      h('div', { class: 'form-grid' }, field('ID base', idBase), field('Step per half/quarter', step), field('VLAN class', cls), field('Security zone', zone))),
    actions: [{ label: 'Cancel', value: null }, { label: 'Apply', kind: 'primary', value: 'ok' }],
  });
  if (res !== 'ok') return;
  if (on.checked) {
    s.vlanRule = { idBase: Number(idBase.value), positionStep: Number(step.value) || 100, class: cls.value.trim() || s.sectionKey };
    if (zone.value) s.vlanRule.securityZone = zone.value;
  } else delete s.vlanRule;
  renderSections();
  changed();
}

// --------------------------------------------------------------------------- status bar

function renderStatus() {
  const L = st.layout;
  const counts = L.summary ? L.summary.sections.map((s) => `${s.sectionKey} ${s.subnets}`).join(' · ') : '';
  const problems = L.errors?.length || 0;
  const saveLabel = st.isNew ? 'Create draft' : 'Save draft';
  const base = input({ value: st.base, placeholder: 'e.g. 10.9.0.0', class: 'mono narrow' });
  base.addEventListener('change', () => { st.base = base.value.trim(); renderSubnets(); });
  mount(st.el.status,
    h('div', { class: 'status-line' },
      h('span', { class: 'big' }, L.summary ? `${L.summary.subnetCount} subnets` : 'Layout has errors'),
      counts ? h('span', { class: 'muted' }, counts) : null,
      L.newVlans?.length ? h('span', { class: 'badge badge-new' }, `${L.newVlans.length} new VLANs on save`) : null,
      problems ? h('button', { type: 'button', class: 'chip chip-error', onClick: () => showProblems() }, `✖ ${problems} problem(s)`) : h('span', { class: 'chip chip-released' }, '✔ valid'),
      st.isNew ? h('span', { class: 'chip chip-deprecated' }, 'not saved yet')
        : st.dirty ? h('span', { class: 'chip chip-deprecated' }, 'unsaved changes') : h('span', { class: 'muted small' }, 'saved'),
      h('span', { class: 'spacer' }),
      h('label', { class: 'inline small' }, 'Show at base ', base),
      button(saveLabel, save, 'primary'),
      can('templates.release') ? button('Release…', release, '', { disabled: st.isNew }) : null),
    problems ? h('div', { class: 'alert alert-error compact' }, h('ul', {}, L.errors.slice(0, 4).map((e) => h('li', {}, h('code', {}, e.code), ' ', e.message, e.suggested ? ` → try ${e.suggested}` : ''))), problems > 4 ? h('a', { href: '#', onClick: (e) => { e.preventDefault(); showProblems(); } }, `…and ${problems - 4} more`) : null) : null);
}

function showProblems() {
  modal({ title: 'Problems', wide: true, body: h('ul', {}, st.layout.errors.map((e) => h('li', {}, h('code', {}, e.code), ' ', e.message, e.suggested ? ` → try ${e.suggested}` : ''))) });
}

// --------------------------------------------------------------------------- subnets

function renderSubnets() {
  const L = st.layout;
  const f = st.filter;
  const secSel = select([{ value: '', label: 'All sections' }, ...blk().sections.map((s) => s.sectionKey)], f.section);
  secSel.addEventListener('change', () => { f.section = secSel.value; renderSubnets(); });
  const text = input({ value: f.text, placeholder: 'Filter CIDR or VLAN…' });
  text.addEventListener('input', debounce(() => { f.text = text.value; renderSubnets(); text.focus(); }, 300));
  const unbound = h('input', { type: 'checkbox', checked: f.unbound });
  unbound.addEventListener('change', () => { f.unbound = unbound.checked; renderSubnets(); });

  const q = f.text.trim().toLowerCase();
  const rows = (L.subnets || []).filter((s) =>
    (!f.section || s.section === f.section)
    && (!f.unbound || !s.vlanKey)
    && (!q || [s.relativeCidr, s.vlanKey, s.vlanName, s.vlanId].join(' ').toLowerCase().includes(q)));
  const baseOk = /^\d+\.\d+\.\d+\.\d+$/.test(st.base);

  const body = rows.length ? h('div', { class: 'table-wrap tall' }, h('table', { class: 'grid' },
    h('thead', {}, h('tr', {}, ['Relative CIDR', baseOk ? `At ${st.base}` : null, 'Size', 'Section', 'VLAN', 'ID', 'Name', 'Change layout'].filter(Boolean).map((x) => h('th', {}, x)))),
    h('tbody', {}, rows.map((s) => subnetRow(s, baseOk))))) : h('p', { class: 'muted' }, L.subnets?.length ? 'No subnets match the filter.' : 'Fix the problems above to see the layout.');

  mount(st.el.subnets, card('Subnets',
    h('div', { class: 'row' }, secSel, text, h('label', { class: 'check' }, unbound, ' unassigned only'), h('span', { class: 'muted small' }, `${rows.length} shown`)),
    h('p', { class: 'muted small' }, 'Type a VLAN key to bind it (a new key opens the create-VLAN form). Split breaks a subnet into smaller ones; merge joins it with its neighbours into one bigger subnet — you\'ll see exactly which rows are absorbed first.'),
    body));
}

function subnetRow(s, baseOk) {
  const b = blk();
  const vlan = input({ value: s.fromRule ? '' : (s.vlanKey || ''), placeholder: s.fromRule ? `${s.vlanKey} (rule)` : 'unassigned', list: 'vlan-keys', class: 'mono vlan-input' });
  vlan.addEventListener('change', () => bind(s, vlan.value));

  const splitOpts = [];
  for (let p = s.prefix + 1; p <= Math.min(30, s.prefix + 4); p++) splitOpts.push({ value: p, label: `into ${2 ** (p - s.prefix)} × /${p}` });
  const split = select([{ value: '', label: '✂ Split…' }, ...splitOpts], '', { class: 'small-select' });
  split.addEventListener('change', () => { if (split.value) doSplit(s, Number(split.value)); split.value = ''; });

  const mergeOpts = [];
  for (let p = s.prefix - 1; p >= Math.max(b.prefixLength + 1, s.prefix - 6); p--) mergeOpts.push({ value: p, label: `into a /${p}` });
  const merge = select([{ value: '', label: '⊕ Merge…' }, ...mergeOpts], '', { class: 'small-select' });
  merge.addEventListener('change', () => { if (merge.value) doMerge(s, Number(merge.value)); merge.value = ''; });

  const touched = (sec(s.section)?.subnetOverrides || []).some((o) => overlaps(normal(o.relativeCidr), s.relativeCidr));
  return h('tr', { class: s.prefix < b.unitPrefix ? 'row-merged' : (s.prefix > b.unitPrefix ? 'row-split' : '') },
    h('td', {}, h('code', {}, s.relativeCidr)),
    baseOk ? h('td', {}, h('code', {}, relocate(s.relativeCidr, st.base))) : null,
    h('td', {}, `/${s.prefix}`),
    h('td', {}, s.section),
    h('td', {}, vlan, s.fromRule ? h('span', { class: 'badge' }, 'rule') : null, s.newVlan ? h('span', { class: 'badge badge-new' }, 'new') : null),
    h('td', { class: 'num' }, s.vlanId ?? ''),
    h('td', {}, s.vlanName || ''),
    h('td', { class: 'nowrap' }, split, merge, touched ? button('Reset', () => doReset(s), 'small', { title: 'Undo splits/merges on this subnet' }) : null));
}

// Overrides may be stored with host bits (a rejected merge); normalise for comparisons.
function normal(c) {
  const { net, prefix } = parseCidr(c);
  return supernet(`${[24, 16, 8, 0].map((x) => (net >>> x) & 255).join('.')}/${prefix}`, prefix);
}

async function doSplit(s, p) {
  const section = sec(s.section);
  const bound = section.vlanBindings.find((x) => x.relativeCidr === s.relativeCidr);
  if (bound && !(await confirmBox('Split subnet', `${s.relativeCidr} carries VLAN ${bound.vlanKey}. Splitting it removes that binding; you can bind the new subnets afterwards.`, 'Split'))) return;
  section.vlanBindings = section.vlanBindings.filter((x) => x.relativeCidr !== s.relativeCidr);
  section.subnetOverrides.push({ relativeCidr: s.relativeCidr, splitTo: p });
  changed();
}

async function doSplitAll(section, p) {
  const unit = blk().unitPrefix;
  const rows = (st.layout.subnets || []).filter((x) => x.section === section.sectionKey && x.prefix === unit);
  if (!rows.length) { toast(`No /${unit} subnets left to split in ${section.sectionKey}`, 'warn'); return; }
  const cidrs = new Set(rows.map((x) => x.relativeCidr));
  const lost = section.vlanBindings.filter((b) => cidrs.has(b.relativeCidr));
  const ok = await confirmBox(`Split ${section.sectionKey}`, h('div', {},
    h('p', {}, `Split all ${rows.length} × /${unit} subnets in ${section.sectionKey} into /${p}: that makes ${rows.length * 2 ** (p - unit)} subnets. Subnets you've already split or merged are left alone.`),
    lost.length ? h('p', { class: 'error-text' }, `VLAN bindings removed: ${lost.map((b) => b.vlanKey).join(', ')}.`) : null), 'Split');
  if (!ok) return;
  section.vlanBindings = section.vlanBindings.filter((b) => !cidrs.has(b.relativeCidr));
  for (const c of cidrs) section.subnetOverrides.push({ relativeCidr: c, splitTo: p });
  changed();
}

async function doMerge(s, p) {
  const target = supernet(s.relativeCidr, p);
  const absorbed = st.layout.subnets.filter((x) => overlaps(x.relativeCidr, target));
  const other = absorbed.find((x) => x.section !== s.section);
  if (other) {
    await modal({ title: 'Can\'t merge', body: h('p', {}, `A /${p} starting at ${target.split('/')[0]} would cross into section ${other.section}. Merges must stay inside one section.`) });
    return;
  }
  const covered = absorbed.reduce((n, x) => n + size(x.prefix), 0);
  if (covered !== size(p)) {
    await modal({ title: 'Can\'t merge', body: h('p', {}, `${target} runs past the end of section ${s.section}.`) });
    return;
  }
  const section = sec(s.section);
  const lostBindings = section.vlanBindings.filter((b) => overlaps(b.relativeCidr, target));
  const ok = await confirmBox(`Merge into ${target}`, h('div', {},
    h('p', {}, `A /${p} has to start on its own boundary, so the merged subnet is `, h('strong', {}, target), `. These ${absorbed.length} subnets become one:`),
    h('p', {}, absorbed.map((x) => h('code', { class: 'pill' }, x.relativeCidr))),
    lostBindings.length ? h('p', { class: 'error-text' }, `VLAN bindings removed: ${lostBindings.map((b) => `${b.vlanKey} (${b.relativeCidr})`).join(', ')}. Bind the merged subnet afterwards.`) : null), 'Merge');
  if (!ok) return;
  section.subnetOverrides = section.subnetOverrides.filter((o) => !contains(target, normal(o.relativeCidr)));
  section.vlanBindings = section.vlanBindings.filter((b) => !overlaps(b.relativeCidr, target));
  section.subnetOverrides.push({ relativeCidr: target, mergeFrom: blk().unitPrefix });
  changed();
}

async function doReset(s) {
  const section = sec(s.section);
  const unit = blk().unitPrefix;
  const lost = section.vlanBindings.filter((b) => overlaps(b.relativeCidr, s.relativeCidr) && parseCidr(b.relativeCidr).prefix !== unit);
  const ok = await confirmBox('Reset subnet', h('div', {},
    h('p', {}, `Undo the splits and merges covering ${s.relativeCidr}, back to plain /${unit} subnets.`),
    lost.length ? h('p', { class: 'error-text' }, `VLAN bindings removed: ${lost.map((b) => b.vlanKey).join(', ')}.`) : null), 'Reset');
  if (!ok) return;
  section.subnetOverrides = section.subnetOverrides.filter((o) => !overlaps(normal(o.relativeCidr), s.relativeCidr));
  section.vlanBindings = section.vlanBindings.filter((b) => !lost.includes(b));
  changed();
}

async function bind(s, raw) {
  const key = raw.trim().toUpperCase();
  const section = sec(s.section);
  if (!key) {
    section.vlanBindings = section.vlanBindings.filter((b) => b.relativeCidr !== s.relativeCidr);
    return changed();
  }
  let known = st.vlans.find((v) => v.vlanKey === key || (v.aliases || []).map((a) => a.toUpperCase()).includes(key));
  if (!known) {
    known = await createVlanDialog(key, s);
    if (!known) return renderSubnets();
  }
  for (const other of blk().sections) {
    const dupe = other.vlanBindings.find((b) => b.vlanKey === known.vlanKey && b.relativeCidr !== s.relativeCidr);
    if (dupe) {
      if (!(await confirmBox('VLAN already used', `${known.vlanKey} is bound to ${dupe.relativeCidr}. A VLAN can appear once per template. Move it here?`, 'Move'))) return renderSubnets();
      other.vlanBindings = other.vlanBindings.filter((b) => b !== dupe);
    }
  }
  section.vlanBindings = section.vlanBindings.filter((b) => b.relativeCidr !== s.relativeCidr);
  section.vlanBindings.push({ relativeCidr: s.relativeCidr, vlanKey: known.vlanKey });
  changed();
}

async function createVlanDialog(key, s) {
  const third = (parseCidr(s.relativeCidr).net >>> 8) & 255;
  const rule = sec(s.section).vlanRule;
  const suggestedId = rule ? rule.idBase + third : '';
  const k = input({ value: key, class: 'mono' });
  const id = input({ type: 'number', value: suggestedId, min: 2, max: 4094 });
  const name = input({ value: suggestedId ? `v${suggestedId}-${key}` : key, class: 'mono' });
  const cls = input({ value: s.section, class: 'mono' });
  const zone = select(ZONES, s.section === 'CORP' ? 'Internal' : 'DataCentre');
  const desc = input({ class: 'wide' });
  const status = h('div');
  let created = null;
  await modal({
    title: 'New VLAN',
    body: h('div', {}, h('p', {}, `${key} isn't in the VLAN library yet. Create it and bind it to ${s.relativeCidr}:`),
      h('div', { class: 'form-grid' }, field('VLAN key', k), field('VLAN ID', id), field('VLAN name', name), field('Class', cls), field('Security zone', zone), field('Description', desc)), status),
    actions: [{ label: 'Cancel', value: null }, {
      label: 'Create and bind', kind: 'primary', value: null,
      validate: async () => {
        try {
          created = await post('/vlans', {
            vlanKey: k.value.trim().toUpperCase(), vlanId: id.value ? Number(id.value) : null, vlanName: name.value.trim(),
            class: cls.value.trim() || null, securityZone: zone.value || null, description: desc.value || null, aliases: [],
          });
          st.vlans.push(created);
          document.getElementById('vlan-keys')?.append(h('option', { value: created.vlanKey }));
          return true;
        } catch (err) { mount(status, errorPanel(err)); return false; }
      },
    }],
  });
  if (created) toast(`VLAN ${created.vlanKey} created`, 'success');
  return created;
}

// --------------------------------------------------------------------------- save / release

async function save() {
  try {
    if (st.isNew) {
      const key = (st.newKey || '').trim();
      if (!key) { toast('Give the template a key first', 'warn'); return false; }
      const r = await post('/templates', { templateKey: key, description: st.description || null, content: st.content });
      st.dirty = false;
      toast(`Created ${r.ref} as a DRAFT${r.vlansCreated ? `; ${r.vlansCreated} VLANs added to the library` : ''}`, 'success', 6000);
      location.hash = `#/builder/${encodeURIComponent(r.templateKey)}/${r.version}`;
      return true;
    }
    const r = await patch(`/templates/${encodeURIComponent(st.key)}/versions/${st.version}`, { content: st.content });
    st.content = r.content;
    st.dirty = false;
    toast(`Saved${r.vlansCreated ? `; ${r.vlansCreated} VLANs added to the library` : ''}`, 'success');
    if (r.vlansCreated) st.vlans = await get('/vlans');
    renderSections();
    await recompute();
    return true;
  } catch (err) {
    await modal({ title: 'Couldn\'t save', body: errorPanel(err), wide: true });
    return false;
  }
}

async function release() {
  if (st.dirty && !(await save())) return;
  const v = await get(`/templates/${encodeURIComponent(st.key)}/versions/${st.version}`);
  const layout = await post('/templates:layout', { content: v.content });
  setLeaveGuard(null);
  window.onbeforeunload = null;
  releaseDialog(st.key, v, layout);
}
