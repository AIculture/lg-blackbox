/* LG Black Box admin UI: collapsible sections, colored buttons, table filters, toasts and background updates (no page reload). */
(function () {
    'use strict';

    var LS = 'lgbb.open.';
    // Actions that change state and are safe to run in the background. Downloads, the report file and the abuse preview page are NOT in this list.
    var ACTIONS = /[?&]action=lg_bb_(login|clear|recorder|savequeries)(&|$)/;
    var ICONS = [
        [/recent alerts/i, 'dashicons-megaphone'], [/report|paste/i, 'dashicons-media-text'], [/incident/i, 'dashicons-warning'], [/recorder|burst/i, 'dashicons-chart-bar'],
        [/login|protection/i, 'dashicons-shield'], [/probe|scanner/i, 'dashicons-search'], [/country|geo/i, 'dashicons-admin-site-alt3'],
        [/source/i, 'dashicons-networking'], [/automatic|auto/i, 'dashicons-update'], [/rate|cron/i, 'dashicons-dashboard'],
        [/blocked/i, 'dashicons-dismiss'], [/server/i, 'dashicons-desktop'], [/slow|heavy|request/i, 'dashicons-clock'],
        [/sample/i, 'dashicons-list-view'], [/config/i, 'dashicons-admin-generic']
    ];
    // Sections that start collapsed unless the person opened them before.
    var COLLAPSED = /server right now|slow|sample|config|recorder|incident/i;

    function $(sel, ctx) { return (ctx || document).querySelector(sel); }
    function $$(sel, ctx) { return Array.prototype.slice.call((ctx || document).querySelectorAll(sel)); }
    function el(tag, cls, html) { var e = document.createElement(tag); if (cls) { e.className = cls; } if (html !== undefined) { e.innerHTML = html; } return e; }
    function slug(t) { return String(t).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'sec'; }
    function shortTitle(t) {
        t = String(t).trim();
        if (/^report/i.test(t)) { return 'Report'; }
        if (/^server right now/i.test(t)) { return 'Server now'; }
        if (/^slow/i.test(t)) { return 'Slow requests'; }
        t = t.split(/[,(]/)[0].trim();
        return t.length > 24 ? t.slice(0, 23) + '…' : t;
    }
    function iconFor(t) { for (var i = 0; i < ICONS.length; i++) { if (ICONS[i][0].test(t)) { return ICONS[i][1]; } } return 'dashicons-admin-generic'; }
    function remember(k, v) { try { if (v === undefined) { return localStorage.getItem(LS + k); } localStorage.setItem(LS + k, v ? '1' : '0'); } catch (e) { /* storage blocked */ } return null; }
    function rowsIn(node) { return $$('table tbody tr', node).length; }

    /* ------------------------------------------------------------ toasts and progress bar */
    function toasts() {
        var t = document.getElementById('lgbb-toasts');
        if (!t) { t = el('div'); t.id = 'lgbb-toasts'; t.setAttribute('role', 'status'); t.setAttribute('aria-live', 'polite'); document.body.appendChild(t); }
        return t;
    }
    function toast(text, tone) {
        if (!text) { return; }
        tone = tone || (/^(not |could not|cannot|invalid|forbidden|the report could not)/i.test(text) ? 'warn' : 'good');
        var n = el('div', 'lgbb-toast is-' + tone);
        n.appendChild(el('span', 'dashicons ' + (tone === 'good' ? 'dashicons-yes-alt' : 'dashicons-warning')));
        n.appendChild(el('span', '', ''));
        n.lastChild.textContent = text;
        var x = el('button', '', '&times;'); x.type = 'button'; x.setAttribute('aria-label', 'Dismiss');
        x.onclick = function () { n.remove(); };
        n.appendChild(x);
        toasts().appendChild(n);
        setTimeout(function () { if (n.parentNode) { n.remove(); } }, tone === 'good' ? 6000 : 11000);
    }
    var barTimer = null;
    function bar(state) {
        var b = document.getElementById('lgbb-bar');
        if (!b) { b = el('div'); b.id = 'lgbb-bar'; document.body.appendChild(b); }
        clearTimeout(barTimer);
        if (state === 'start') { b.style.opacity = '1'; b.style.width = '12%'; barTimer = setTimeout(function () { b.style.width = '70%'; }, 120); }
        else { b.style.width = '100%'; barTimer = setTimeout(function () { b.style.opacity = '0'; b.style.width = '0'; }, 260); }
    }

    /* ------------------------------------------------------------ enhance: turn the flat WordPress markup into a modern layout */
    function enhance(root) {
        // 1. WordPress notices (the result of an action) become toasts.
        $$('.notice.inline', root).forEach(function (n) { toast(n.textContent.replace(/\s+/g, ' ').trim()); n.remove(); });

        // 2. Group everything after each h2 into a collapsible card.
        var kids = Array.prototype.slice.call(root.children);
        var card = null, body = null, cards = [];
        kids.forEach(function (k) {
            if (k.classList.contains('lgbb-hero') || k.classList.contains('lgbb-meta') || k.classList.contains('lgbb-nav')) { card = null; return; }
            if (k.tagName === 'H2') {
                var title = k.textContent.replace(/\s+/g, ' ').trim();
                var id = k.id || slug(title);
                card = el('section', 'lgbb-card'); card.id = id;
                var d = el('details'); var s = el('summary');
                var ic = el('span', 'lgbb-card__icon'); ic.appendChild(el('span', 'dashicons ' + iconFor(title + ' ' + id)));
                var h = el('h2', 'lgbb-card__title'); h.textContent = title;
                s.appendChild(ic); s.appendChild(h); s.appendChild(el('span', 'lgbb-badges')); s.appendChild(el('span', 'lgbb-chev'));
                d.appendChild(s); body = el('div', 'lgbb-card__body'); d.appendChild(body); card.appendChild(d);
                root.insertBefore(card, k); k.remove();
                var saved = remember(id), open = saved === null ? !COLLAPSED.test(title) : saved === '1';
                if (open) { d.setAttribute('open', ''); }
                cards.push(card);
                return;
            }
            if (card) { body.appendChild(k); }
        });

        // 3. Inside a card, each h3 becomes a collapsible sub-section; long lists start collapsed.
        cards.forEach(function (c) {
            var b = $('.lgbb-card__body', c), subs = [], cur = null, curBody = null;
            Array.prototype.slice.call(b.children).forEach(function (k) {
                if (k.tagName === 'H3') {
                    var t = k.textContent.replace(/\s+/g, ' ').trim(), id = k.id || (c.id + '-' + slug(t));
                    cur = el('details', 'lgbb-sub'); cur.id = id;
                    var s = el('summary'); var h = el('h3', 'lgbb-sub__title'); h.textContent = t;
                    s.appendChild(h); s.appendChild(el('span', 'lgbb-badges')); s.appendChild(el('span', 'lgbb-chev'));
                    cur.appendChild(s); curBody = el('div', 'lgbb-sub__body'); cur.appendChild(curBody);
                    b.insertBefore(cur, k); k.remove(); subs.push(cur);
                    return;
                }
                if (cur) { curBody.appendChild(k); }
            });
            subs.forEach(function (sd) {
                var n = rowsIn(sd), saved = remember(sd.id);
                var open = saved === null ? (n <= 10 && !/server|slow|sample/i.test(sd.id)) : saved === '1';
                if (open) { sd.setAttribute('open', ''); }
            });
        });

        // Incidents are the one section that should be open whenever there is something in it.
        cards.forEach(function (c) {
            if (/incident/i.test(c.id + ' ' + $('.lgbb-card__title', c).textContent) && remember(c.id) === null && rowsIn(c) > 0) { $('details', c).setAttribute('open', ''); }
        });

        // 4. Long tables get a scroll area (sticky header) and a filter box.
        $$('table.widefat', root).forEach(function (t) {
            if (t.parentNode.classList.contains('lgbb-scroll')) { return; }
            var n = $$('tbody tr', t).length, wrap = el('div', 'lgbb-scroll');
            t.parentNode.insertBefore(wrap, t); wrap.appendChild(t);
            if (n > 12) {
                var f = el('input', 'lgbb-filter'); f.type = 'search'; f.placeholder = 'Filter ' + n + ' rows';
                wrap.parentNode.insertBefore(f, wrap);
                f.addEventListener('input', function () {
                    var q = f.value.toLowerCase();
                    $$('tbody tr', t).forEach(function (r) { r.style.display = !q || r.textContent.toLowerCase().indexOf(q) > -1 ? '' : 'none'; });
                });
            }
        });

        // 5. Badges: row counts and a bad/ok tint where the heading text says so.
        $$('.lgbb-card, .lgbb-sub', root).forEach(function (c) {
            var host = c.classList.contains('lgbb-card') ? $('.lgbb-card__body', c) : $('.lgbb-sub__body', c);
            var badges = $('.lgbb-badges', c.classList.contains('lgbb-card') ? $('summary', c) : $('summary', c));
            if (!badges) { return; }
            var n = $$('table tbody tr', host).length;
            if (c.classList.contains('lgbb-sub') || !$('.lgbb-sub', host)) { if (n) { badges.appendChild(el('span', 'lgbb-badge', n + (n === 1 ? ' row' : ' rows'))); } }
            var on = $$('.lgbb-pill--on', host).length, off = $$('.lgbb-pill--off', host).length;
            if (on && !off && !c.classList.contains('lgbb-sub')) { badges.appendChild(el('span', 'lgbb-badge is-good', 'ON')); }
        });

        // 6. ON / OFF words become pills.
        $$('strong', root).forEach(function (s) {
            var t = s.textContent.trim();
            if (t === 'ON' || t === 'OFF') { s.className = 'lgbb-pill lgbb-pill--' + t.toLowerCase(); }
        });

        // 7. Colored buttons by what they do.
        $$('a.button, button.button, a[href*="admin-post.php?action=lg_bb_"]:not(.lgbb-switch), #lgbb td a[href*="op="]', root).forEach(function (b) {
            if (b.classList.contains('lgbb-switch') || b.classList.contains('lgbb-btn') && b.dataset.tone) { return; }
            var t = b.textContent.replace(/\s+/g, ' ').trim(), tone = '';
            if (/^(download|raw log|copy)/i.test(t)) { tone = 'ghost'; }
            else if (/report abuse/i.test(t)) { tone = 'warn'; }
            else if (/^(block|clear|delete|disable|turn off|remove|refuse|reset)/i.test(t) || /block site-wide/i.test(t)) { tone = 'danger'; }
            else if (/^(enable|turn on|save|send|allow|always allow|unblock|never block|apply|add)/i.test(t) || b.classList.contains('button-primary')) { tone = 'good'; }
            else if (/^\d+h$/.test(t)) { tone = b.classList.contains('button-primary') ? 'info' : ''; }
            b.classList.add('lgbb-btn'); b.dataset.tone = tone || 'plain';
            if (tone) { b.classList.add('lgbb-btn--' + tone); }
            if (b.closest('td, .lgbb-sub__body p span, .lgbb-nav') && !b.classList.contains('button')) { b.classList.add('lgbb-btn--sm'); }
            if (b.tagName === 'A' && !b.classList.contains('button')) { b.classList.add('lgbb-btn--sm'); b.removeAttribute('style'); }
            b.classList.remove('button-primary');
        });

        // 8. Navigation bar built from the cards.
        var old = $('.lgbb-nav', root); if (old) { old.remove(); }
        var nav = el('nav', 'lgbb-nav'); nav.setAttribute('aria-label', 'Sections');
        cards.forEach(function (c) {
            var a = el('a'); a.href = '#' + c.id; a.dataset.target = c.id;
            a.appendChild(el('span', 'dashicons ' + iconFor($('.lgbb-card__title', c).textContent + ' ' + c.id)));
            a.appendChild(document.createTextNode(shortTitle($('.lgbb-card__title', c).textContent)));
            nav.appendChild(a);
        });
        var tools = el('div', 'lgbb-nav__tools');
        var ex = el('button', 'button lgbb-btn lgbb-btn--sm', 'Expand all'); ex.type = 'button'; ex.dataset.tone = 'plain';
        var co = el('button', 'button lgbb-btn lgbb-btn--sm', 'Collapse all'); co.type = 'button'; co.dataset.tone = 'plain';
        ex.onclick = function () { $$('details', root).forEach(function (d) { d.setAttribute('open', ''); }); };
        co.onclick = function () { $$('details', root).forEach(function (d) { d.removeAttribute('open'); }); };
        tools.appendChild(ex); tools.appendChild(co); nav.appendChild(tools);
        var anchor = $('.lgbb-meta', root) || $('.lgbb-hero', root);
        if (anchor) { anchor.insertAdjacentElement('afterend', nav); } else { root.insertBefore(nav, root.firstChild); }
        spy(nav, cards);
    }

    // Highlight the section that is currently in view.
    var observer = null;
    function spy(nav, cards) {
        if (observer) { observer.disconnect(); }
        if (!('IntersectionObserver' in window)) { return; }
        observer = new IntersectionObserver(function (entries) {
            entries.forEach(function (e) {
                if (e.isIntersecting) {
                    $$('a', nav).forEach(function (a) { a.classList.toggle('is-active', a.dataset.target === e.target.id); });
                }
            });
        }, { rootMargin: '-20% 0px -70% 0px' });
        cards.forEach(function (c) { observer.observe(c); });
    }

    /* ------------------------------------------------------------ background requests */
    function root() { return document.getElementById('lgbb'); }
    function busy(on, trigger) {
        var r = root(); if (r) { r.classList.toggle('is-busy', on); }
        if (trigger) { trigger.classList.toggle('is-loading', on); }
        bar(on ? 'start' : 'done');
    }
    function cleanUrl(u) {
        try { var x = new URL(u, location.href); x.searchParams.delete('lgmsg'); return x.pathname + (x.search || '') + x.hash; } catch (e) { return u; }
    }
    function swap(html, finalUrl, push) {
        var doc = new DOMParser().parseFromString(html, 'text/html');
        var next = doc.getElementById('lgbb');
        if (!next) { location.href = finalUrl; return false; }
        var cur = root(), y = window.scrollY;
        cur.replaceWith(document.importNode(next, true));
        enhance(root());
        window.scrollTo(0, y);
        try { history[push ? 'pushState' : 'replaceState'](null, '', cleanUrl(finalUrl)); } catch (e) { /* ignore */ }
        return true;
    }
    function go(url, init, trigger, push) {
        busy(true, trigger);
        var finalUrl = url;
        return fetch(url, Object.assign({ credentials: 'same-origin', redirect: 'follow' }, init || {}))
            .then(function (r) { finalUrl = r.url || url; return r.text(); })
            .then(function (html) { swap(html, finalUrl, push); })
            .catch(function () { toast('Could not update in the background, reloading the page.', 'warn'); setTimeout(function () { location.href = url; }, 700); })
            .then(function () { busy(false, trigger); });
    }
    function soft(href) {
        try {
            var u = new URL(href, location.href);
            if (u.origin !== location.origin) { return false; }
            if (/\/admin-post\.php$/.test(u.pathname) && ACTIONS.test(u.search)) { return true; }
            return /\/tools\.php$/.test(u.pathname) && u.searchParams.get('page') === 'lg-blackbox';
        } catch (e) { return false; }
    }

    document.addEventListener('click', function (e) {
        var a = e.target.closest ? e.target.closest('#lgbb a[href]') : null;
        if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || a.target === '_blank') { return; }
        var href = a.getAttribute('href');
        if (href && href.charAt(0) === '#') {
            var t = document.getElementById(href.slice(1));
            if (t) { e.preventDefault(); var d = $('details', t) || t; if (d.tagName === 'DETAILS') { d.setAttribute('open', ''); } t.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
            return;
        }
        if (!soft(href)) { return; }
        e.preventDefault();
        var msg = a.getAttribute('data-confirm');
        if (msg && !window.confirm(msg)) { return; }
        if (a.classList.contains('lgbb-switch')) { a.classList.toggle('is-on'); }
        go(href, null, a, !/admin-post\.php/.test(href));
    });
    document.addEventListener('keydown', function (e) {
        if ((e.key === ' ' || e.key === 'Spacebar') && e.target.classList && e.target.classList.contains('lgbb-switch')) { e.preventDefault(); e.target.click(); }
    });
    document.addEventListener('submit', function (e) {
        var f = e.target;
        if (!f.closest || !f.closest('#lgbb') || f.method.toLowerCase() !== 'post') { return; }
        var act = f.querySelector('input[name=action]');
        if (!act || !/^lg_bb_(login|clear|recorder|savequeries)$/.test(act.value) || !/admin-post\.php/.test(f.action)) { return; }
        e.preventDefault();
        var btn = e.submitter || f.querySelector('button');
        go(f.action, { method: 'POST', body: new FormData(f) }, btn, false);
    });
    // Remember which sections are open.
    document.addEventListener('toggle', function (e) {
        var d = e.target;
        if (!d || d.tagName !== 'DETAILS' || !d.closest || !d.closest('#lgbb')) { return; }
        var holder = d.classList.contains('lgbb-sub') ? d : d.parentNode;
        if (holder && holder.id) { remember(holder.id, d.open); }
    }, true);
    window.addEventListener('popstate', function () { if (root()) { go(location.href, null, null, false); } });

    function init() { var r = root(); if (r) { enhance(r); } }
    if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', init); } else { init(); }
})();
