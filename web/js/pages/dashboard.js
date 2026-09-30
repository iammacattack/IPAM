import { get } from '../api.js';
import { h, mount, card, chip, table, fmtTime, fromNow, button } from '../dom.js';
import { can } from '../session.js';

export async function render(root) {
  mount(root, h('p', { class: 'muted' }, 'Loading…'));
  const [templates, sites, pools, recent] = await Promise.all([
    get('/templates', { state: 'RELEASED' }),
    get('/sites'),
    get('/pools'),
    can('audit.read') ? get('/audit', { limit: 12 }) : Promise.resolve(null),
  ]);
  const byStatus = (s) => sites.filter((x) => x.status === s).length;
  const expiring = sites
    .filter((s) => s.status === 'reserved')
    .sort((a, b) => new Date(a.reservation.expiresAt) - new Date(b.reservation.expiresAt));
  const sitePool = pools.find((p) => p.poolKey === 'SITE-POOL-AU');

  const stat = (label, value, href, note, tone) =>
    h('a', { class: 'stat', href, dataset: tone ? { tone } : null }, h('div', { class: 'stat-value' }, value), h('div', { class: 'stat-label' }, label), note ? h('div', { class: 'stat-note' }, note) : null);

  mount(root,
    h('div', { class: 'page-head' },
      h('h1', {}, 'Dashboard'),
      h('div', { class: 'actions' },
        can('sites.deploy') ? button('New site', () => { location.hash = '#/sites/new'; }, 'primary') : null,
        can('templates.write') ? button('New template', () => { location.hash = '#/builder/new'; }) : null,
        button('Lookup', () => { location.hash = '#/lookup'; }))),
    h('div', { class: 'stats' },
      stat('Released templates', templates.length, '#/templates', null, 'info'),
      stat('Reserved sites', byStatus('reserved'), '#/sites', 'awaiting confirm', 'warning'),
      stat('Allocated sites', byStatus('allocated') + byStatus('active'), '#/sites', null, 'success'),
      stat('Site blocks from SITE-POOL-AU', sitePool ? sitePool.blocksAllocated : '—', '#/library', sitePool ? `/${sitePool.allocationPrefixLength} each` : null, 'violet')),
    h('div', { class: 'two-col' },
      card('Reservations awaiting confirmation',
        table([
          { label: 'Site', value: (s) => h('a', { href: `#/sites/${encodeURIComponent(s.siteCode)}` }, s.siteCode) },
          { label: 'Block', value: (s) => s.blocks.map((b) => b.cidr).join(', ') },
          { label: 'Template', value: (s) => s.template ? `${s.template.key}@v${s.template.version}` : '—' },
          { label: 'Expires', value: (s) => h('span', { title: fmtTime(s.reservation.expiresAt) }, fromNow(s.reservation.expiresAt)) },
        ], expiring, { empty: 'No open reservations.' })),
      recent === null ? card('Signed in', h('p', {}, 'Use the menu on the left. Your roles decide what you see: ', h('a', { href: '#/account' }, 'My account'), ' lists them.')) : card('Recent activity',
        table([
          { label: 'When', value: (e) => h('span', { title: fmtTime(e.occurredAt) }, fromNow(e.occurredAt)) },
          { label: 'Action', value: (e) => e.action },
          { label: 'Site', value: (e) => e.siteCode || '' },
          { label: 'Client', value: (e) => e.clientName || '' },
          { label: 'Result', value: (e) => chip(e.outcome) },
        ], recent, { empty: 'No activity yet.' }),
        h('p', {}, h('a', { href: '#/audit' }, 'Open the audit log →')))));
}
