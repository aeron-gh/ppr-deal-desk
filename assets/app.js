/* PPR Deal Desk. Static, no external requests. Data is AES-GCM encrypted and unlocked in the browser. */
(() => {
  'use strict';

  const STORE = 'ppr-desk-v1';
  const KEYSTORE = 'ppr-desk-key-v1';
  const CRM_URL = id => `${(DATA && DATA.crmBase) || ''}/#Opportunity/view/${encodeURIComponent(id)}`;
  const LIVE_STAGES = new Set(['Information requested', 'Screening', 'Proprietary review', 'Owner meeting', 'LOI']);
  const DECISIONS = ['Pursue', 'Ask team to draft a reply', 'Call me about it', 'Park for later', 'Pass'];

  const COLS = [
    { id: 'you', title: 'Your call', hint: 'Needs your decision, reply or a call', color: 'var(--you)' },
    { id: 'team', title: 'Team on it', hint: 'Team prepares, checks or fixes CRM. Nothing goes out without you', color: 'var(--team)' },
    { id: 'wait', title: 'Waiting on them', hint: 'Owner or broker owes us a reply', color: 'var(--wait)' },
    { id: 'new', title: 'New in', hint: 'Not looked at yet', color: 'var(--new)' },
    { id: 'warm', title: 'Keep warm', hint: 'Not selling now, or nothing open', color: 'var(--warm)' },
    { id: 'done', title: 'Handled', hint: 'Drag cards here once dealt with (this device only)', color: 'var(--done)' },
    { id: 'closed', title: 'Closed', hint: 'Closed in CRM or ended', color: 'var(--closed)', collapsible: true },
    { id: 'outreach', title: 'Emailed, no reply', hint: 'Cold emails with no reply yet', color: 'var(--closed)', collapsible: true, list: true },
  ];
  const COL_BY_ID = Object.fromEntries(COLS.map(c => [c.id, c]));

  const FILTERS = [
    { id: 'all', label: 'All' },
    { id: 'live', label: 'Live deals', test: d => LIVE_STAGES.has(d.stage) },
    { id: 'email', label: 'Has emails', test: d => d.threads.length > 0 },
    { id: 'unread', label: 'Unread reply', test: d => d.unread },
    { id: 'scraper', label: 'Scraper', test: d => d.source === 'Scraper' },
    { id: 'prop', label: 'Proprietary', test: d => d.source === 'Proprietary' },
    { id: 'broker', label: 'Broker', test: d => d.source === 'Broker' || d.source === 'Referral' },
    { id: 'emailonly', label: 'No CRM card', test: d => !d.crm },
    { id: 'fix', label: 'Needs CRM fix', test: d => d.flags.some(f => /CRM out of date|CRM date passed|not answered/.test(f)) || /CRM says waiting on you, but/.test(d.why) },
  ];

  // ---------- small helpers ----------
  const $ = s => document.querySelector(s);
  const el = (tag, attrs = {}, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? '' : v);
    }
    for (const k of kids.flat()) if (k != null && k !== false) n.append(k.nodeType ? k : document.createTextNode(String(k)));
    return n;
  };
  const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const enc = new TextEncoder();
  const melFmt = new Intl.DateTimeFormat('en-AU', { timeZone: 'Australia/Melbourne', day: 'numeric', month: 'short' });
  const melFull = new Intl.DateTimeFormat('en-AU', { timeZone: 'Australia/Melbourne', weekday: 'short', day: 'numeric', month: 'short', hour: 'numeric', minute: '2-digit' });
  const fmtDay = iso => (iso ? melFmt.format(new Date(iso)) : '');
  const fmtFull = iso => (iso ? melFull.format(new Date(iso)) : '');
  const ago = iso => {
    if (!iso) return '';
    const days = Math.floor((Date.now() - new Date(iso).getTime()) / 864e5);
    if (days <= 0) return 'today';
    if (days === 1) return '1 day';
    if (days < 60) return `${days} days`;
    return fmtDay(iso);
  };
  const name = s => (s || '').replace(/\s*<[^>]*>\s*/g, '').replace(/^"|"$/g, '').trim() || s;
  const emailOf = s => ((s || '').match(/[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+/) || [''])[0].toLowerCase();
  const toast = msg => { const t = $('#toast'); t.textContent = msg; t.hidden = false; clearTimeout(toast._t); toast._t = setTimeout(() => (t.hidden = true), 2200); };

  // ---------- local state ----------
  const load = () => { try { return JSON.parse(localStorage.getItem(STORE)) || {}; } catch (e) { return {}; } };
  const state = Object.assign({ moves: {}, dec: {}, notes: {} }, load());
  const save = () => { try { localStorage.setItem(STORE, JSON.stringify(state)); } catch (e) { /* storage blocked */ } };

  // ---------- data ----------
  let DATA = null, DEALS = [], BY_ID = {};
  let filter = 'all', query = '', expanded = { closed: false, outreach: false };

  const colOf = d => state.moves[d.id] || d.col;
  const lastActivity = d => d.lastIn || d.lastEmail || d.added;

  // ---------- unlock ----------
  async function deriveKey(pw, blob) {
    const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64(blob.salt), iterations: blob.iter, hash: 'SHA-256' }, base,
      { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
  }
  async function decrypt(key, blob) {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(blob.iv), additionalData: enc.encode(blob.aad) }, key, b64(blob.ct));
    const stream = new Blob([pt]).stream().pipeThrough(new DecompressionStream('gzip'));
    return JSON.parse(await new Response(stream).text());
  }
  async function fetchBlob() {
    const r = await fetch('data/deals.enc.json', { cache: 'no-cache' });
    if (!r.ok) throw new Error('Could not load the data file');
    return r.json();
  }
  async function tryRemembered() {
    let raw; try { raw = localStorage.getItem(KEYSTORE); } catch (e) { return false; }
    if (!raw) return false;
    try {
      const key = await crypto.subtle.importKey('raw', b64(raw), 'AES-GCM', true, ['decrypt']);
      start(await decrypt(key, await fetchBlob()));
      return true;
    } catch (e) { try { localStorage.removeItem(KEYSTORE); } catch (_) {} return false; }
  }
  $('#lockForm').addEventListener('submit', async e => {
    e.preventDefault();
    const btn = $('#unlockBtn'), msg = $('#lockMsg');
    btn.disabled = true; btn.textContent = 'Opening…'; msg.textContent = '';
    try {
      const blob = await fetchBlob();
      const key = await deriveKey($('#pw').value.trim(), blob);
      const data = await decrypt(key, blob);
      if ($('#remember').checked) {
        const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', key));
        try { localStorage.setItem(KEYSTORE, btoa(String.fromCharCode(...rawKey))); } catch (_) {}
      }
      $('#pw').value = '';
      start(data);
    } catch (err) {
      msg.textContent = err && err.message === 'Could not load the data file' ? err.message : 'That password did not work.';
    } finally { btn.disabled = false; btn.textContent = 'Open'; }
  });
  $('#lockBtn').addEventListener('click', () => { try { localStorage.removeItem(KEYSTORE); } catch (_) {} location.hash = ''; location.reload(); });

  function start(data) {
    DATA = data;
    DEALS = data.deals;
    BY_ID = Object.fromEntries(DEALS.map(d => [d.id, d]));
    $('#lock').hidden = true; $('#app').hidden = false;
    $('#snap').textContent = `Data as of ${fmtFull(data.snapshot)} Melbourne`;
    renderChips(); renderAll(); openFromHash();
  }

  // ---------- rendering ----------
  function visible(d) {
    const f = FILTERS.find(x => x.id === filter);
    if (f && f.test && !f.test(d)) return false;
    if (!query) return true;
    const hay = [d.name, d.contact, d.contactEmail, d.company, d.broker, d.stage, d.why, d.action,
      ...d.threads.map(t => t.subj)].join(' ').toLowerCase();
    return query.split(/\s+/).every(w => hay.includes(w));
  }

  function renderAll() { renderSummary(); renderBoard(); renderChecks(); renderTray(); }

  function renderSummary() {
    const c = id => DEALS.filter(d => colOf(d) === id).length;
    const s = DATA.stats || {};
    const box = $('#summary'); box.replaceChildren();
    const stat = (n, label, cls, onclick) => box.append(el('div', { class: 'stat ' + (cls || ''), onclick, role: 'button', tabindex: 0 }, el('b', { text: n }), el('span', { text: label })));
    stat(c('you'), 'need your call', 'you', () => scrollToCol('you'));
    stat(c('team'), 'with the team', '', () => scrollToCol('team'));
    stat(c('wait'), 'waiting on them', '', () => scrollToCol('wait'));
    stat(s.new7 ?? '', 'new deal cards this week', '', () => { filter = 'all'; query = ''; $('#q').value = ''; renderChips(); renderBoard(); });
    stat(DATA.outreach.length, 'emailed, no reply', '', () => { expanded.outreach = true; renderBoard(); scrollToCol('outreach'); });
  }

  function renderChips() {
    const box = $('#chips'); box.replaceChildren();
    for (const f of FILTERS) {
      const n = f.test ? DEALS.filter(f.test).length : DEALS.length;
      box.append(el('button', { class: 'chip' + (filter === f.id ? ' on' : ''), onclick: () => { filter = f.id; renderChips(); renderBoard(); } }, `${f.label} `, el('span', { class: 'muted', text: n })));
    }
  }

  function sortDeals(list, colId) {
    const rank = d => (d.basis === 'reviewed' ? 0 : 1);
    return list.sort((a, b) => (colId === 'you' || colId === 'team' ? rank(a) - rank(b) : 0) ||
      (lastActivity(b) || '').localeCompare(lastActivity(a) || ''));
  }

  function card(d) {
    const moved = state.moves[d.id] && state.moves[d.id] !== d.col;
    const dec = state.dec[d.id];
    const meta = el('div', { class: 'meta' });
    if (d.stage && d.stage !== 'Closed') meta.append(el('span', { class: 'tag' + (LIVE_STAGES.has(d.stage) ? ' stage-live' : ''), text: d.stage === 'Email only' ? 'No CRM card' : d.stage }));
    if (d.source && !['Other', 'Email only'].includes(d.source) && !(d.stage || '').toLowerCase().startsWith(d.source.toLowerCase())) meta.append(el('span', { class: 'tag', text: d.source }));
    for (const f of d.flags.filter(f => f !== 'No CRM card').slice(0, 2)) meta.append(el('span', { class: 'tag flag', text: f }));
    if (dec) meta.append(el('span', { class: 'tag dec', text: dec.d }));
    if (moved) meta.append(el('span', { class: 'tag moved', text: 'Moved by you' }));
    if (state.notes[d.id]) meta.append(el('span', { class: 'tag', text: 'Note' }));
    const act = lastActivity(d);
    const hot = d.lastIn && (!d.lastOut || d.lastIn > d.lastOut);
    meta.append(el('span', { class: 'age' + (hot && ['you', 'team'].includes(colOf(d)) ? ' hot' : ''), title: act ? fmtFull(act) : '', text: ago(act) }));
    const c = el('article', { class: 'card', draggable: 'true', tabindex: 0, 'data-id': d.id, onclick: () => openDeal(d.id), onkeydown: e => { if (e.key === 'Enter') openDeal(d.id); } },
      d.unread ? el('span', { class: 'unread', title: 'Unread reply in the inbox' }) : null,
      el('div', { class: 'name', text: d.name }),
      el('p', { class: 'why', text: d.why }),
      d.action ? el('div', { class: 'act', text: '→ ' + d.action }) : null,
      meta);
    c.addEventListener('dragstart', e => { e.dataTransfer.setData('text/plain', d.id); e.dataTransfer.effectAllowed = 'move'; c.classList.add('dragging'); });
    c.addEventListener('dragend', () => c.classList.remove('dragging'));
    return c;
  }

  function renderBoard() {
    const board = $('#board'); board.replaceChildren();
    const vis = DEALS.filter(visible);
    for (const col of COLS) {
      const section = el('section', { class: 'col' + (col.collapsible && !expanded[col.id] ? ' collapsed' : ''), 'data-col': col.id });
      const body = el('div', { class: 'col-body', 'data-col': col.id });
      let count;
      if (col.list) {
        const q = query;
        const rows = DATA.outreach.filter(x => filter === 'all' && (!q || (x.to + ' ' + (x.subj || '')).toLowerCase().includes(q)));
        count = rows.length;
        if (expanded[col.id] || (q && rows.length)) {
          for (const x of rows.slice(0, 300)) {
            body.append(el('div', { class: 'list-row' },
              el('a', { href: gmailThread(x.tid), target: '_blank', rel: 'noopener noreferrer', text: x.to || '(unknown)' }),
              el('span', { class: 'muted', text: (x.bounced ? 'bounced · ' : '') + fmtDay(x.ts) })));
          }
          if (rows.length > 300) body.append(el('div', { class: 'muted small', text: `Showing 300 of ${rows.length}. Search to narrow.` }));
        } else body.append(el('button', { class: 'ghost col-more', onclick: () => { expanded[col.id] = true; renderBoard(); }, text: `Show ${rows.length}` }));
      } else {
        const list = sortDeals(vis.filter(d => colOf(d) === col.id), col.id);
        count = list.length;
        const open = !col.collapsible || expanded[col.id] || (query && list.length);
        if (open) {
          const lim = col.id === 'closed' && !query ? 80 : 400;
          list.slice(0, lim).forEach(d => body.append(card(d)));
          if (list.length > lim) body.append(el('div', { class: 'muted small', text: `Showing ${lim} of ${list.length}. Search to find the rest.` }));
          if (!list.length) body.append(el('div', { class: 'empty', text: col.id === 'done' ? 'Drag a card here when it is handled' : 'Nothing here' }));
        } else body.append(el('button', { class: 'ghost col-more', onclick: () => { expanded[col.id] = true; renderBoard(); }, text: `Show ${list.length}` }));
        body.addEventListener('dragover', e => { e.preventDefault(); body.classList.add('over'); });
        body.addEventListener('dragleave', () => body.classList.remove('over'));
        body.addEventListener('drop', e => { e.preventDefault(); body.classList.remove('over'); moveDeal(e.dataTransfer.getData('text/plain'), col.id); });
      }
      section.append(
        el('div', { class: 'col-head' }, el('span', { class: 'dot', style: null }), el('h2', { text: col.title }), el('span', { class: 'count', text: count })),
        el('div', { class: 'col-hint', text: col.hint }), body);
      section.querySelector('.dot').style.background = col.color;
      board.append(section);
    }
  }

  function scrollToCol(id) {
    if (!$('#board').hidden || switchView('board')) {
      const n = document.querySelector(`.col[data-col="${id}"]`);
      if (n) n.scrollIntoView({ behavior: 'smooth', inline: 'start', block: 'nearest' });
    }
  }

  function moveDeal(id, colId) {
    const d = BY_ID[id]; if (!d) return;
    if (colId === d.col) delete state.moves[id]; else state.moves[id] = colId;
    save(); renderAll();
    if (!$('#drawer').hidden && current === id) openDeal(id);
    toast(`Moved to ${COL_BY_ID[colId].title}`);
  }

  // ---------- links ----------
  const gmailThread = tid => `https://mail.google.com/mail/?authuser=${encodeURIComponent(DATA.mailbox)}#all/${encodeURIComponent(tid)}`;
  const gmailCompose = (to, subj) => `https://mail.google.com/mail/?authuser=${encodeURIComponent(DATA.mailbox)}&view=cm&fs=1&to=${encodeURIComponent(to)}&su=${encodeURIComponent(subj || '')}`;
  const safeHref = u => (/^https?:\/\//i.test(u || '') ? u : (u ? 'https://' + u.replace(/^\/+/, '') : null));

  function linkify(text) {
    const frag = document.createDocumentFragment();
    const re = /(https?:\/\/[^\s<>"')\]]+)/g;
    let last = 0, m;
    while ((m = re.exec(text))) {
      if (m.index > last) frag.append(document.createTextNode(text.slice(last, m.index)));
      const url = m[1].replace(/[.,;:]+$/, '');
      frag.append(el('a', { href: url, target: '_blank', rel: 'noopener noreferrer', text: url.length > 80 ? url.slice(0, 77) + '…' : url }));
      last = m.index + url.length;
    }
    if (last < text.length) frag.append(document.createTextNode(text.slice(last)));
    return frag;
  }

  // ---------- drawer ----------
  let current = null;
  function openDeal(id) {
    const d = BY_ID[id]; if (!d) return;
    current = id;
    if (location.hash !== '#d=' + id) history.replaceState(null, '', '#d=' + encodeURIComponent(id));
    const box = $('#drawerInner'); box.replaceChildren();
    const col = COL_BY_ID[colOf(d)];

    box.append(el('div', { class: 'd-head' }, el('h2', { text: d.name }), el('button', { class: 'x', 'aria-label': 'Close', onclick: closeDeal, text: '×' })));
    const tags = el('div', { class: 'd-tags' });
    tags.append(el('span', { class: 'tag' + (LIVE_STAGES.has(d.stage) ? ' stage-live' : ''), text: d.stage === 'Email only' ? 'No CRM card' : d.stage }));
    if (d.source) tags.append(el('span', { class: 'tag', text: d.source }));
    for (const f of d.flags) tags.append(el('span', { class: 'tag flag', text: f }));
    if (d.f && d.f.cFit) tags.append(el('span', { class: 'tag', text: 'Fit: ' + d.f.cFit }));
    box.append(tags);

    // where it stands
    const basisText = { reviewed: 'Checked by reading the full thread on 10 Nov', crm: 'From the CRM card', email: 'From the email thread' }[d.basis] || '';
    const stand = el('div', { class: 'stand' },
      el('div', { class: 'lbl', text: col.title + (state.moves[d.id] ? ' (moved by you)' : '') }),
      el('p', { class: 'why', text: d.why }),
      d.action ? el('div', { class: 'next', text: '→ ' + d.action + (d.who ? `   ·   with ${d.who}` : '') }) : null,
      el('div', { class: 'basis', text: basisText }));
    stand.style.background = getComputedStyle(document.documentElement).getPropertyValue(`--${col.id === 'outreach' ? 'closed' : col.id}-bg`) || '#f5f5f5';
    stand.querySelector('.lbl').style.color = col.color;
    box.append(stand);

    // action buttons
    const latest = d.threads[d.threads.length - 1];
    const row = el('div', { class: 'btnrow' });
    if (latest) row.append(el('a', { class: 'btn primary', href: gmailThread(latest.id), target: '_blank', rel: 'noopener noreferrer', text: 'Open latest email in Gmail' }));
    const to = d.contactEmail || (latest && latest.msgs.map(m => m.dir === 'in' ? emailOf(m.from) : '').filter(Boolean).pop());
    if (to) row.append(el('a', { class: 'btn', href: gmailCompose(to, latest ? (/^re:/i.test(latest.subj) ? latest.subj : 'Re: ' + latest.subj) : ''), target: '_blank', rel: 'noopener noreferrer', text: 'New email', title: 'To ' + to }));
    if (d.crm) row.append(el('a', { class: 'btn', href: CRM_URL(d.id), target: '_blank', rel: 'noopener noreferrer', text: 'Open CRM card' }));
    if (d.listing && safeHref(d.listing)) row.append(el('a', { class: 'btn', href: safeHref(d.listing), target: '_blank', rel: 'noopener noreferrer', text: 'Listing' }));
    if (d.website && safeHref(d.website)) row.append(el('a', { class: 'btn', href: safeHref(d.website), target: '_blank', rel: 'noopener noreferrer', text: 'Website' }));
    box.append(row);

    // decision
    const dec = state.dec[d.id];
    const seg = el('div', { class: 'seg' });
    for (const label of DECISIONS) {
      seg.append(el('button', { class: dec && dec.d === label ? 'on' : '', onclick: () => setDecision(d.id, dec && dec.d === label ? null : label) , text: label }));
    }
    const note = el('textarea', { placeholder: 'Note for the team (optional). Saved on this device.' });
    note.value = state.notes[d.id] || '';
    note.addEventListener('input', () => { if (note.value.trim()) state.notes[d.id] = note.value; else delete state.notes[d.id]; save(); renderTray(); });
    note.addEventListener('blur', () => renderBoard());
    const move = el('select', { 'aria-label': 'Move to column', onchange: e => moveDeal(d.id, e.target.value) },
      ...COLS.filter(c => !c.list).map(c => el('option', { value: c.id, selected: colOf(d) === c.id ? 'selected' : null, text: c.title })));
    box.append(el('div', { class: 'decide' },
      el('h3', { text: 'Your decision' }), seg, note,
      el('div', { class: 'row' }, el('span', { class: 'muted small', text: 'Move to' }), move,
        state.moves[d.id] ? el('button', { class: 'ghost', onclick: () => moveDeal(d.id, d.col), text: 'Undo move' }) : null)));

    // tabs
    const panes = {};
    const tabs = el('div', { class: 'tabs', role: 'tablist' });
    const paneBox = el('div', { class: 'pane' });
    const tabDefs = [['emails', `Emails (${d.threads.reduce((n, t) => n + t.msgs.length, 0)})`], ['crm', 'CRM notes'], ['facts', 'Facts']];
    const show = id => { for (const b of tabs.children) b.classList.toggle('on', b.dataset.tab === id); paneBox.replaceChildren(panes[id]()); };
    for (const [id, label] of tabDefs) tabs.append(el('button', { class: 'tab', 'data-tab': id, onclick: () => show(id), text: label }));
    panes.emails = () => emailsPane(d);
    panes.crm = () => crmPane(d);
    panes.facts = () => factsPane(d);
    box.append(tabs, paneBox);
    show(d.threads.length ? 'emails' : 'crm');

    $('#drawer').hidden = false; $('#scrim').hidden = false;
    $('#drawerInner').scrollTop = 0;
  }
  function closeDeal() {
    $('#drawer').hidden = true; $('#scrim').hidden = true; current = null;
    history.replaceState(null, '', location.pathname + location.search);
  }
  function openFromHash() {
    const m = location.hash.match(/^#d=(.+)$/);
    if (m && BY_ID[decodeURIComponent(m[1])]) openDeal(decodeURIComponent(m[1]));
  }
  window.addEventListener('hashchange', openFromHash);
  $('#scrim').addEventListener('click', closeDeal);

  function emailsPane(d) {
    const wrap = el('div');
    if (!d.threads.length) {
      wrap.append(el('p', { class: 'muted', text: `No email in the ${DATA.mailbox} inbox is linked to this deal. Replies sent from the other outreach addresses are not visible here.` }));
      return wrap;
    }
    const threads = [...d.threads].sort((a, b) => (b.msgs[b.msgs.length - 1].ts || '').localeCompare(a.msgs[a.msgs.length - 1].ts || ''));
    threads.forEach((t, ti) => {
      const box = el('div', { class: 'thread' });
      box.append(el('div', { class: 'thread-head' },
        el('b', { text: t.subj || '(no subject)' }),
        el('span', { class: 'muted small' }, t.link ? 'Linked by: ' + t.link : '', el('a', { href: gmailThread(t.id), target: '_blank', rel: 'noopener noreferrer', text: 'Open in Gmail' }))));
      const msgs = [...t.msgs].sort((a, b) => (b.ts || '').localeCompare(a.ts || ''));
      if (msgs.length > 1) box.append(el('div', { class: 'muted small order', text: 'Newest first. Tap a message to open or close it.' }));
      msgs.forEach((m, i) => {
        const openByDefault = ti === 0 && i === 0 || (ti === 0 && i === 1 && m.dir === 'in');
        const body = el('div', { class: 'msg-body' }); body.append(linkify(m.body || ''));
        const snip = el('div', { class: 'msg-snip', text: (m.body || '').replace(/\s+/g, ' ').slice(0, 140) });
        body.hidden = !openByDefault; snip.hidden = openByDefault;
        const dirLabel = { in: 'Them', out: 'Us', draft: 'Draft, not sent' }[m.dir] || m.dir;
        const fromName = m.dir === 'in' && t.kind === 'fwd' && /@(pprcapital|pprrcapital)\./i.test(m.from) ? 'Forwarded owner reply' : name(m.from);
        const msg = el('div', { class: 'msg' },
          el('div', { class: 'msg-head', onclick: () => { body.hidden = !body.hidden; snip.hidden = !body.hidden; } },
            el('span', { class: 'dir ' + m.dir, text: dirLabel }), el('span', { class: 'who', text: fromName }),
            m.labels && m.labels.includes('UNREAD') ? el('span', { class: 'tag flag', text: 'Unread' }) : null,
            el('span', { class: 'msg-date', text: fmtFull(m.ts) })),
          snip, body,
          m.att && m.att.length ? el('div', { class: 'att' }, ...m.att.map(a => el('span', { text: '📎 ' + a }))) : null);
        box.append(msg);
      });
      wrap.append(box);
    });
    return wrap;
  }

  function crmPane(d) {
    const wrap = el('div');
    if (!d.crm) { wrap.append(el('p', { class: 'muted', text: 'There is no CRM card for this business yet.' })); return wrap; }
    const f = d.f || {};
    const block = (title, text) => { if (text) wrap.append(el('div', { class: 'sub', text: title }), el('div', { class: 'note-block' }, linkify(String(text).trim()))); };
    const nextLine = [f.cNextStep, f.cNextStepDate ? `(date: ${f.cNextStepDate})` : '', f.cWaitingOn ? `Waiting on: ${f.cWaitingOn}` : ''].filter(Boolean).join('\n');
    block('Next step', nextLine || 'None recorded');
    block('Handoff brief', f.cHandoffBrief);
    block('Deal history', f.cDealHistory);
    block('Description', f.description);
    return wrap;
  }

  function factsPane(d) {
    const f = d.f || {};
    const rows = [
      ['Stage', d.stage], ['Source', d.source], ['Contact', [d.contact, d.contactEmail].filter(Boolean).join(' · ')],
      ['Company', d.company], ['Broker', d.broker], ['Asking price', f.cScraperAskingPrice], ['EBITDA (estimate)', f.cScraperEBITDAEstimate],
      ['Industry', f.cScraperIndustry], ['Location', f.cScraperLocation], ['Size bracket', f.cSizeBracket], ['Fit', f.cFit],
      ['Owner timing', f.cOwnerTiming], ['Owner meeting', f.cOwnerMeetingDate], ['Bolt-on for', f.cBoltonCandidateFor],
      ['Trip', [f.cTripCity, f.cTripNote].filter(Boolean).join(' · ')], ['Scraper verdict', [f.cScraperVerdict, f.cScraperQualityScore ? 'score ' + f.cScraperQualityScore : ''].filter(Boolean).join(', ')],
      ['Scraper summary', f.cScraperSummary], ['Scraper reasoning', f.cScraperReason], ['Closed reason', f.cClosedReason !== 'Not closed' ? f.cClosedReason : ''],
      ['Added to CRM', d.crm ? fmtFull(d.added) : ''], ['Created by', f.createdByName],
      ['Last email', fmtFull(d.lastEmail)], ['Last reply from them', fmtFull(d.lastIn)], ['Last email from us', fmtFull(d.lastOut)],
    ].filter(([, v]) => v);
    const dl = el('dl', { class: 'facts' });
    for (const [k, v] of rows) dl.append(el('dt', { text: k }), el('dd', {}, linkify(String(v))));
    const wrap = el('div', {}, dl);
    wrap.append(el('p', { class: 'muted small', text: 'Estimates come from the scraper or broker ads and are not verified.' }));
    return wrap;
  }

  function setDecision(id, label) {
    if (label) state.dec[id] = { d: label, at: new Date().toISOString() }; else delete state.dec[id];
    save(); renderAll(); openDeal(id);
    if (label) toast(`Saved: ${label}`);
  }

  // ---------- decisions tray ----------
  function trayItems() {
    const ids = new Set([...Object.keys(state.dec), ...Object.keys(state.notes)]);
    return [...ids].filter(id => BY_ID[id]).map(id => ({ d: BY_ID[id], dec: state.dec[id], note: state.notes[id] }))
      .sort((a, b) => ((b.dec && b.dec.at) || '').localeCompare((a.dec && a.dec.at) || ''));
  }
  function trayText() {
    const items = trayItems();
    const today = new Intl.DateTimeFormat('en-AU', { timeZone: 'Australia/Melbourne', day: 'numeric', month: 'short', year: 'numeric' }).format(new Date());
    const lines = [`Deal decisions from Nikita (${today})`, ''];
    items.forEach((x, i) => {
      lines.push(`${i + 1}. ${x.d.name}: ${x.dec ? x.dec.d : 'Note'}`);
      if (x.note) lines.push(`   Note: ${x.note.trim().replace(/\n+/g, ' ')}`);
      if (x.d.crm) lines.push(`   CRM: ${CRM_URL(x.d.id)}`);
    });
    return lines.join('\n');
  }
  function renderTray() {
    const items = trayItems();
    $('#trayCount').textContent = items.length;
    const list = $('#trayList'); list.replaceChildren();
    if (!items.length) list.append(el('p', { class: 'muted', text: 'Open a deal and pick a decision or add a note. They collect here so you can send them to the team in one go.' }));
    for (const x of items) {
      list.append(el('div', { class: 'tray-item', onclick: () => { $('#tray').hidden = true; openDeal(x.d.id); } },
        el('b', { text: x.d.name }), el('span', { text: x.dec ? x.dec.d : 'Note only' }),
        x.note ? el('div', { class: 'muted small', text: x.note }) : null));
    }
  }
  async function copyText(t) {
    try { await navigator.clipboard.writeText(t); }
    catch (e) { const ta = el('textarea'); ta.value = t; document.body.append(ta); ta.select(); document.execCommand('copy'); ta.remove(); }
    toast('Copied');
  }
  $('#trayBtn').addEventListener('click', () => { $('#tray').hidden = !$('#tray').hidden; renderTray(); });
  $('#trayClose').addEventListener('click', () => ($('#tray').hidden = true));
  $('#trayCopy').addEventListener('click', () => copyText(trayText()));
  $('#trayWa').addEventListener('click', () => window.open('https://wa.me/?text=' + encodeURIComponent(trayText()), '_blank', 'noopener'));
  $('#trayMail').addEventListener('click', () => { location.href = 'mailto:?subject=' + encodeURIComponent('Deal decisions') + '&body=' + encodeURIComponent(trayText()); });
  $('#trayDownload').addEventListener('click', () => {
    const a = el('a', { href: URL.createObjectURL(new Blob([trayText()], { type: 'text/plain' })), download: 'deal-decisions.txt' });
    document.body.append(a); a.click(); a.remove();
  });
  $('#trayClear').addEventListener('click', () => {
    if (!trayItems().length) return;
    state.dec = {}; state.notes = {}; save(); renderAll(); toast('Cleared');
  });

  // ---------- checks ----------
  function renderChecks() {
    const box = $('#checks'); box.replaceChildren();
    const open = DEALS.filter(d => colOf(d) !== 'closed');
    const groups = [
      ['CRM card is out of date', 'The email shows something newer than the CRM card.', open.filter(d => d.flags.includes('CRM out of date') || /CRM says waiting on you, but/.test(d.why))],
      ['Replies not answered from this inbox', `The latest reply has no answer from ${DATA.mailbox}. It may have been answered from another address or by phone.`, open.filter(d => d.flags.includes('Latest reply not answered from this inbox'))],
      ['CRM next-step date has passed', 'Needs checking or a new date. Not a chase.', open.filter(d => d.flags.includes('CRM date passed'))],
      ['Unsent drafts', 'A draft sits in the thread and was never sent.', open.filter(d => d.flags.includes('Unsent draft in thread'))],
      ['No CRM card', 'Email conversations with no matching CRM card.', open.filter(d => !d.crm && colOf(d) !== 'warm')],
      ['Weaker email links', 'Email linked by listing name in the subject only. Worth a quick check.', DEALS.filter(d => d.threads.some(t => /subject|Broker domain/.test(t.link || '')))],
    ];
    let total = 0;
    for (const [title, hint, list] of groups) {
      total += list.length;
      const ul = el('ul');
      for (const d of list.slice(0, 60)) ul.append(el('li', { onclick: () => openDeal(d.id) }, el('b', { text: d.name }), el('span', { text: COL_BY_ID[colOf(d)].title })));
      if (!list.length) ul.append(el('li', { class: 'muted', text: 'Nothing here' }));
      box.append(el('div', { class: 'check-box' }, el('h3', { text: `${title} (${list.length})` }), el('p', { text: hint }), ul));
    }
    const cov = DATA.coverage || {};
    box.append(el('div', { class: 'check-box' }, el('h3', { text: 'About this data' }),
      el('p', { text: `Snapshot from ${fmtFull(DATA.snapshot)} Melbourne. Not live.` }),
      el('p', { text: `CRM: all ${cov.crmCards} cards read; ${cov.crmDeals} real deals after removing website spam and tests. Email: ${DATA.mailbox} since ${fmtDay(cov.emailSince)}, ${cov.threads} deal threads read in full, including sent mail.` }),
      el('p', { text: 'Not visible: replies sent from the other outreach addresses, texts, calls and WhatsApp. CRM stage history is not available, so stage movement is not shown.' }),
      el('p', { text: 'Decisions, notes and moved cards are saved only in this browser.' })));
    $('#checksCount').textContent = groups.slice(0, 4).reduce((n, g) => n + g[2].length, 0);
  }

  function switchView(v) {
    for (const b of document.querySelectorAll('.view')) b.classList.toggle('on', b.dataset.view === v);
    $('#board').hidden = v !== 'board'; $('#checks').hidden = v !== 'checks';
    $('.filters').hidden = v !== 'board';
    return true;
  }
  for (const b of document.querySelectorAll('.view')) b.addEventListener('click', () => switchView(b.dataset.view));

  // ---------- search & keys ----------
  let qTimer;
  $('#q').addEventListener('input', e => { clearTimeout(qTimer); qTimer = setTimeout(() => { query = e.target.value.trim().toLowerCase(); renderBoard(); }, 120); });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') { if (!$('#tray').hidden) $('#tray').hidden = true; else if (!$('#drawer').hidden) closeDeal(); }
    if (e.key === '/' && !/input|textarea|select/i.test(document.activeElement.tagName) && !$('#app').hidden) { e.preventDefault(); $('#q').focus(); }
  });

  // ---------- boot ----------
  if (!window.crypto || !crypto.subtle || typeof DecompressionStream === 'undefined') {
    $('#lockMsg').textContent = 'This browser is too old to open the desk. Please use a current Chrome, Safari or Edge.';
  } else {
    tryRemembered();
  }
})();
