import { get } from '../api.js';
import { h, mount, card, chip, table, fmtTime, fromNow, button } from '../dom.js';

export async function render(root) {
  mount(root, h('p', { class: 'muted' }, 'Loading…'));
  const [templates, sites, pools, recent] = await Promise.all([
    get('/templates', { state: 'RELEASED' }),
    get('/sites'),
    get('/pools'),
    get('/audit', { limit: 12 }),
  ]);
  const byStatus = (s) => sites.filter((x) => x.status === s).length;
  const expiring = sites
    .filter((s) => s.status === 'reserved')
    .sort((a, b) => new Date(a.reservation.expiresAt) - new Date(b.reservation.expiresAt));
  const sitePool = pools.find((p) => p.poolKey === 'SITE-POOL-AU');

  const stat = (label, value, href, note) =>
    h('a', { class: 'stat', href }, h('div', { class: 'stat-value' }, value), h('div', { class: 'stat-label' }, label), note ? h('div', { class: 'stat-note' }, note) : null);

  mount(root,
    h('div', { class: 'page-head' },
      h('h1', {}, 'Dashboard'),
      h('div', { class: 'actions' },
        button('New site', () => { location.hash = '#/sites/new'; }, 'primary'),
        button('New template', () => { location.hash = '#/builder/new'; }),
        button('Lookup', () => { location.hash = '#/lookup'; }))),
    h('div', { class: 'stats' },
      stat('Released templates', templates.length, '#/templates'),
      stat('Reserved sites', byStatus('reserved'), '#/sites', 'awaiting confirm'),
      stat('Allocated sites', byStatus('allocated') + byStatus('active'), '#/sites'),
      stat('Site blocks from SITE-POOL-AU', sitePool ? sitePool.blocksAllocated : '—', '#/library', sitePool ? `/${sitePool.allocationPrefixLength} each` : null)),
    h('div', { class: 'two-col' },
      card('Reservations awaiting confirmation',
        table([
          { label: 'Site', value: (s) => h('a', { href: `#/sites/${encodeURIComponent(s.siteCode)}` }, s.siteCode) },
          { label: 'Block', value: (s) => s.blocks.map((b) => b.cidr).join(', ') },
          { label: 'Template', value: (s) => s.template ? `${s.template.key}@v${s.template.version}` : '—' },
          { label: 'Expires', value: (s) => h('span', { title: fmtTime(s.reservation.expiresAt) }, fromNow(s.reservation.expiresAt)) },
        ], expiring, { empty: 'No open reservations.' })),
      card('Recent activity',
        table([
          { label: 'When', value: (e) => h('span', { title: fmtTime(e.occurredAt) }, fromNow(e.occurredAt)) },
          { label: 'Action', value: (e) => e.action },
          { label: 'Site', value: (e) => e.siteCode || '' },
          { label: 'Client', value: (e) => e.clientName || '' },
          { label: 'Result', value: (e) => chip(e.outcome) },
        ], recent, { empty: 'No activity yet.' }),
        h('p', {}, h('a', { href: '#/audit' }, 'Open the audit log →')))));
}
