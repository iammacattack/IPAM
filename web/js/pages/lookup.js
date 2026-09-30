// Lookup tester (Workflow 3): what an IaC tool or script would ask, answered the same way.
import { get, post, errorPanel } from '../api.js';
import { h, mount, card, table, button, input, select, field, datalist, copyButton, chip } from '../dom.js';

const FIELDS = ['gateway', 'mask', 'prefix', 'cidr', 'network', 'networkPortion', 'twoOctets', 'spansThirdOctets',
  'broadcast', 'firstUsable', 'lastUsable', 'vlanId', 'vlanName', 'dnsServers', 'validateOctet'];

// Site Delivery Wizard token vocabulary -> API field
const TOKEN_FIELDS = {
  GATEWAY: 'gateway', MASK: 'mask', PREFIX: 'prefix', '3OCT': 'networkPortion', '2OCT': 'twoOctets', ID: 'vlanId',
  NAME: 'vlanName', DNS: 'dnsServers', CIDR: 'cidr', NETWORK: 'network', BROADCAST: 'broadcast',
};

const EXAMPLE = `[VLAN_OT_SERVER]+[WDC01]
[VLAN_OT_SERVER]+[WDC02]
[VLAN_OT_SERVER.Gateway]
[VLAN_OT_SERVER.Mask]
[VLAN_OT_SERVER.Prefix]
[VLAN_OT_SERVER.3OCT]
[VLAN_OT_SERVER.DNS]
[DCS-SECURITY]+[NVR01]`;

export async function render(root) {
  const [sites, vlans, roles] = await Promise.all([get('/sites'), get('/vlans'), get('/host-roles')]);
  const live = sites.map((s) => s.siteCode);
  const vlanNames = vlans.flatMap((v) => [v.vlanKey, ...(v.aliases || [])]);
  const members = roles.flatMap((r) => r.members.filter((m) => m.kind === 'fixed').map((m) => m.name));
  const defaultSite = live.includes('X9') ? 'X9' : (live[0] || '');

  mount(root,
    h('h1', {}, 'Lookup tester'),
    h('p', { class: 'muted' }, 'Ask by site and VLAN name, never by address — the same calls Ansible, PowerShell or the Site Delivery Wizard make. Each lookup is audited.'),
    datalist('dl-sites', live), datalist('dl-vlans', vlanNames), datalist('dl-members', members),
    h('div', { class: 'two-col' }, hostPanel(defaultSite), vlanPanel(defaultSite)),
    tokenPanel(defaultSite));
}

function hostPanel(site) {
  const s = input({ value: site, list: 'dl-sites', class: 'mono' });
  const v = input({ value: 'VLAN_OT_SERVER', list: 'dl-vlans', class: 'mono' });
  const m = input({ value: 'WDC01', list: 'dl-members', class: 'mono' });
  const out = h('div');
  const run = async () => {
    try {
      const r = await get('/lookup/host-ip', { site: s.value.trim(), vlan: v.value.trim(), host: m.value.trim() });
      mount(out, h('div', { class: 'result' },
        h('div', { class: 'result-big' }, h('code', {}, r.ip), ' ', copyButton(r.ip)),
        h('dl', { class: 'facts small' }, [['VLAN', `${r.vlanKey} (${r.vlanId})`], ['Subnet', r.subnet], ['Gateway', r.gateway], ['Position', `${r.hostPosition} → ${r.octetUsed}`], ['Status', chip(r.status)], ['Hostname', r.hostname || '—'], ['Site', `${r.siteCode} · ${r.siteStatus}`]].map(([k, x]) => [h('dt', {}, k), h('dd', {}, x)])),
        h('p', { class: 'muted small' }, 'Script equivalent: ', h('code', {}, `GET /api/v1/lookup/host-ip?site=${r.siteCode}&vlan=${v.value.trim()}&host=${r.member}  (Accept: text/plain)`))));
    } catch (err) { mount(out, errorPanel(err)); }
  };
  [s, v, m].forEach((el) => el.addEventListener('keydown', (e) => { if (e.key === 'Enter') run(); }));
  return card('Host IP by name', h('div', { class: 'form-grid' }, field('Site', s), field('VLAN (key or alias)', v), field('Host-pool member', m)), button('Look up', run, 'primary'), out);
}

function vlanPanel(site) {
  const s = input({ value: site, list: 'dl-sites', class: 'mono' });
  const v = input({ value: 'VLAN_OT_SERVER', list: 'dl-vlans', class: 'mono' });
  const f = select([{ value: '', label: 'All attributes' }, ...FIELDS], '');
  const idx = input({ type: 'number', min: 0, placeholder: 'supernets only', class: 'narrow' });
  const oct = input({ type: 'number', min: 0, max: 255, placeholder: 'for validateOctet', class: 'narrow' });
  const out = h('div');
  const run = async () => {
    try {
      const r = await get('/lookup/vlan', { site: s.value.trim(), vlan: v.value.trim(), field: f.value, index: idx.value, octet: oct.value });
      if (!f.value) {
        mount(out, h('dl', { class: 'facts small' }, Object.entries(r).map(([k, x]) => [h('dt', {}, k), h('dd', {}, h('code', {}, String(x ?? '')))])));
      } else {
        const val = typeof r.value === 'object' ? JSON.stringify(r.value) : String(r.value);
        mount(out, h('div', { class: 'result' }, h('div', { class: 'result-big' }, h('code', {}, val), ' ', copyButton(val)),
          h('p', { class: 'muted small' }, `${r.field} of ${r.vlanKey} at ${r.siteCode}`)));
      }
    } catch (err) { mount(out, errorPanel(err)); }
  };
  return card('VLAN attribute', h('div', { class: 'form-grid' }, field('Site', s), field('VLAN (key or alias)', v), field('Field', f), field('Index', idx), field('Octet', oct)), button('Look up', run, 'primary'), out);
}

function parseTokens(text) {
  const tokens = [];
  const bad = [];
  for (const raw of text.split('\n').map((l) => l.trim()).filter(Boolean)) {
    let m = raw.match(/^\[([^\].]+)\]\s*\+\s*\[([^\]]+)\]$/);
    if (m) { tokens.push({ label: raw, token: { vlan: m[1], host: m[2] } }); continue; }
    m = raw.match(/^\[([^\].]+)\.([^\]]+)\]$/);
    if (m) { tokens.push({ label: raw, token: { vlan: m[1], field: TOKEN_FIELDS[m[2].toUpperCase()] || m[2] } }); continue; }
    bad.push(raw);
  }
  return { tokens, bad };
}

function tokenPanel(site) {
  const s = input({ value: site, list: 'dl-sites', class: 'mono' });
  const text = h('textarea', { rows: 9, class: 'wide mono', spellcheck: 'false' });
  text.value = EXAMPLE;
  const out = h('div');
  const run = async () => {
    const { tokens, bad } = parseTokens(text.value);
    if (!tokens.length) { mount(out, h('div', { class: 'alert alert-error' }, 'No tokens recognised.')); return; }
    try {
      const r = await post('/lookup:resolve-tokens', { site: s.value.trim(), tokens: tokens.map((t) => t.token) });
      mount(out,
        h('p', {}, `${r.resolved} resolved, ${r.failed} failed — one round trip.`),
        table([
          { label: 'Token', value: (x) => h('code', {}, x.label) },
          { label: 'Value', value: (x) => (x.res.error ? h('span', { class: 'error-text' }, `${x.res.error.code}: ${x.res.error.message}`) : h('code', {}, String(x.res.value))) },
        ], tokens.map((t, i) => ({ label: t.label, res: r.results[i] }))),
        bad.length ? h('div', { class: 'alert alert-warn' }, `Not understood: ${bad.join(', ')}`) : null);
    } catch (err) { mount(out, errorPanel(err)); }
  };
  return card('Resolve manifest tokens',
    h('p', { class: 'muted small' }, 'One token per line: ', h('code', {}, '[VLAN]+[HOST]'), ' for a host address, or ', h('code', {}, '[VLAN.Field]'), ' where Field is Gateway, Mask, Prefix, 3OCT, 2OCT, ID, Name, DNS, CIDR, Network or Broadcast.'),
    h('div', { class: 'form-grid' }, field('Site', s)), text, button('Resolve all', run, 'primary'), out);
}
