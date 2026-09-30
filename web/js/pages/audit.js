// Audit log viewer (basic FR-17): filter by the prominent columns or a keyword; export CSV.
import { get, errorPanel } from '../api.js';
import { h, mount, card, chip, table, button, input, select, field, modal, fmtTime, downloadCsv } from '../dom.js';

const ACTIONS = ['', 'site.reserve', 'site.confirm', 'site.extend', 'site.release', 'site.reservation_expired', 'design.read',
  'lookup.host', 'lookup.vlan', 'lookup.batch', 'host.assign', 'template.create', 'template.update', 'template.release',
  'template.version_create', 'vlan.create', 'auth.failed'];

export async function render(root) {
  const action = select(ACTIONS.map((a) => ({ value: a, label: a || 'Any action' })), '');
  const site = input({ class: 'mono narrow', placeholder: 'e.g. X9' });
  const client = input({ placeholder: 'e.g. SiteDeliveryWizard/2.4' });
  const outcome = select([{ value: '', label: 'Any outcome' }, 'success', 'failure', 'denied'], '');
  const q = input({ placeholder: 'keyword in route, query, object, actor…', class: 'wide' });
  const limit = select(['100', '250', '500', '1000'], '100');
  const out = h('div');
  let rows = [];

  const run = async () => {
    mount(out, h('p', { class: 'muted' }, 'Loading…'));
    try {
      rows = await get('/audit', {
        action: action.value, siteCode: site.value.trim().toUpperCase(), clientName: client.value.trim(),
        outcome: outcome.value, q: q.value.trim(), limit: limit.value,
      });
      mount(out, h('p', { class: 'muted small' }, `${rows.length} event(s), newest first`), table([
        { label: 'When', value: (e) => fmtTime(e.occurredAt) },
        { label: 'Action', value: (e) => h('code', {}, e.action) },
        { label: 'Site', value: (e) => e.siteCode || '' },
        { label: 'Object', value: (e) => e.objectKey || '' },
        { label: 'Actor', value: (e) => e.actorDisplay || e.actorId || e.actorType },
        { label: 'Client', value: (e) => e.clientName || '' },
        { label: 'Request', value: (e) => h('span', { class: 'small' }, `${e.httpMethod} ${e.route}`) },
        { label: 'Result', value: (e) => h('span', {}, chip(e.outcome), ' ', e.statusCode, e.errorCode ? h('div', { class: 'small error-text' }, e.errorCode) : null) },
        { label: 'ms', value: (e) => e.durationMs, class: 'num' },
      ], rows, { onRowClick: detail, empty: 'No events match.' }));
    } catch (err) { mount(out, errorPanel(err)); }
  };
  [site, client, q].forEach((el) => el.addEventListener('keydown', (e) => { if (e.key === 'Enter') run(); }));
  [action, outcome, limit].forEach((el) => el.addEventListener('change', run));

  const csv = () => downloadCsv(`ipam-audit-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '')}.csv`,
    ['occurredAt', 'action', 'outcome', 'statusCode', 'errorCode', 'siteCode', 'objectType', 'objectKey', 'actorType', 'actorId', 'clientName', 'sourceIp', 'httpMethod', 'route', 'query', 'durationMs', 'requestId'],
    rows.map((e) => [e.occurredAt, e.action, e.outcome, e.statusCode, e.errorCode, e.siteCode, e.objectType, e.objectKey, e.actorType, e.actorId, e.clientName, e.sourceIp, e.httpMethod, e.route, e.query, e.durationMs, e.requestId]));

  mount(root,
    h('h1', {}, 'Audit log'),
    h('p', { class: 'muted' }, 'Every API request is recorded — reads included — with who, what, when, from where and the result. Rows can\'t be edited or deleted.'),
    card(null,
      h('div', { class: 'form-grid' }, field('Action', action), field('Site', site), field('Client', client), field('Outcome', outcome), field('Keyword', q), field('Show', limit)),
      h('div', { class: 'actions' }, button('Search', run, 'primary'), button('Export CSV', csv))),
    card(null, out));
  run();
}

function detail(e) {
  modal({
    title: `${e.action} · ${fmtTime(e.occurredAt)}`,
    wide: true,
    body: h('dl', { class: 'facts small' }, Object.entries(e).map(([k, v]) => [h('dt', {}, k), h('dd', {}, h('code', {}, v === null ? '—' : typeof v === 'object' ? JSON.stringify(v, null, 2) : String(v)))])),
  });
}
