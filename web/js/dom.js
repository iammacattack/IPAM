// Small DOM helpers. Everything is built with createElement/textContent, never innerHTML,
// so values from the API (hostnames, descriptions) can't inject markup.

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked' || k === 'disabled' || k === 'selected' || k === 'hidden') el[k] = Boolean(v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

export function mount(root, ...children) {
  clear(root);
  append(root, children);
}

// --------------------------------------------------------------------------- toasts

export function toast(message, kind = 'info', ms = 4000) {
  const box = document.getElementById('toasts');
  const t = h('div', { class: `toast toast-${kind}`, role: 'status' }, message);
  box.append(t);
  setTimeout(() => t.remove(), ms);
}

// --------------------------------------------------------------------------- modal

/** Show a modal. `actions` is [{label, value, kind}]. Resolves with the chosen value (or null on cancel). */
export function modal({ title, body, actions = [{ label: 'Close', value: null }], wide = false, onOpen }) {
  return new Promise((resolve) => {
    const close = (value) => {
      overlay.remove();
      document.removeEventListener('keydown', onKey);
      resolve(value);
    };
    const onKey = (e) => { if (e.key === 'Escape') close(null); };
    const buttons = actions.map((a) =>
      h('button', {
        type: 'button',
        class: `btn ${a.kind ? 'btn-' + a.kind : ''}`,
        onClick: async () => {
          if (a.validate) {
            const ok = await a.validate();
            if (!ok) return;
          }
          close(typeof a.value === 'function' ? a.value() : a.value);
        },
      }, a.label));
    const dialog = h('div', { class: `modal ${wide ? 'modal-wide' : ''}`, role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
      h('div', { class: 'modal-head' }, h('h2', {}, title), h('button', { type: 'button', class: 'btn-link', 'aria-label': 'Close', onClick: () => close(null) }, '✕')),
      h('div', { class: 'modal-body' }, body),
      h('div', { class: 'modal-foot' }, buttons));
    const overlay = h('div', { class: 'overlay', onClick: (e) => { if (e.target === overlay) close(null); } }, dialog);
    document.body.append(overlay);
    document.addEventListener('keydown', onKey);
    const first = dialog.querySelector('input, select, textarea');
    (first || buttons[buttons.length - 1])?.focus();
    if (onOpen) onOpen(dialog);
  });
}

export async function confirmBox(title, message, okLabel = 'Continue', kind = 'primary') {
  const v = await modal({
    title,
    body: typeof message === 'string' ? h('p', {}, message) : message,
    actions: [{ label: 'Cancel', value: false }, { label: okLabel, value: true, kind }],
  });
  return v === true;
}

// --------------------------------------------------------------------------- bits

export function chip(text, kind) {
  const k = kind || String(text || '').toLowerCase().replace(/[^a-z0-9]+/g, '-');
  return h('span', { class: `chip chip-${k}` }, text ?? '—');
}

export function card(title, ...children) {
  return h('section', { class: 'card' }, title ? h('h2', { class: 'card-title' }, title) : null, children);
}

export function field(label, control, hint) {
  return h('label', { class: 'field' }, h('span', { class: 'field-label' }, label), control, hint ? h('span', { class: 'hint' }, hint) : null);
}

export function input(attrs = {}) {
  return h('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', ...attrs });
}

export function select(options, value, attrs = {}) {
  const el = h('select', attrs, options.map((o) => {
    const opt = typeof o === 'object' ? o : { value: o, label: o };
    return h('option', { value: opt.value, selected: String(opt.value) === String(value) }, opt.label ?? opt.value);
  }));
  return el;
}

export function button(label, onClick, kind = '', attrs = {}) {
  return h('button', { type: 'button', class: `btn ${kind ? 'btn-' + kind : ''}`, onClick, ...attrs }, label);
}

export function datalist(id, values) {
  return h('datalist', { id }, [...new Set(values)].map((v) => h('option', { value: v })));
}

/** columns: [{label, value: row => node|string, class}] */
export function table(columns, rows, { onRowClick, empty = 'Nothing to show', rowClass } = {}) {
  if (!rows.length) return h('p', { class: 'muted' }, empty);
  return h('div', { class: 'table-wrap' },
    h('table', { class: 'grid' },
      h('thead', {}, h('tr', {}, columns.map((c) => h('th', { class: c.class }, c.label)))),
      h('tbody', {}, rows.map((r) => h('tr', {
        class: [onRowClick ? 'clickable' : '', rowClass ? rowClass(r) : ''].join(' ').trim() || null,
        onClick: onRowClick ? () => onRowClick(r) : null,
      }, columns.map((c) => h('td', { class: c.class }, c.value(r))))))));
}

export function tabs(items, active, onSelect) {
  return h('div', { class: 'tabs', role: 'tablist' }, items.map((t) =>
    h('button', { type: 'button', role: 'tab', class: `tab ${t.id === active ? 'active' : ''}`, 'aria-selected': String(t.id === active), onClick: () => onSelect(t.id) }, t.label)));
}

export function fmtTime(v) {
  if (!v) return '—';
  const d = new Date(v);
  return d.toLocaleString('en-AU', { dateStyle: 'medium', timeStyle: 'short' });
}

export function fromNow(v) {
  if (!v) return '—';
  const ms = new Date(v) - Date.now();
  const abs = Math.abs(ms);
  const units = [['day', 86400000], ['hour', 3600000], ['minute', 60000]];
  for (const [name, size] of units) {
    if (abs >= size || name === 'minute') {
      const n = Math.max(1, Math.round(abs / size));
      const s = `${n} ${name}${n === 1 ? '' : 's'}`;
      return ms >= 0 ? `in ${s}` : `${s} ago`;
    }
  }
  return '';
}

export function shortHash(hash) {
  return hash ? hash.replace('sha256:', '').slice(0, 12) : '—';
}

export function copyButton(text, label = 'Copy') {
  return h('button', {
    type: 'button', class: 'btn btn-small', title: 'Copy to clipboard',
    onClick: async (e) => {
      e.stopPropagation();
      try { await navigator.clipboard.writeText(text); toast('Copied'); } catch { toast('Copy failed', 'error'); }
    },
  }, label);
}

export function downloadCsv(filename, header, rows) {
  const esc = (v) => {
    const s = v === null || v === undefined ? '' : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const csv = [header, ...rows].map((r) => r.map(esc).join(',')).join('\n');
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  const a = h('a', { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}
