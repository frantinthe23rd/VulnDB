/*
 * tpscan report renderer. Plain browser JavaScript with no dependencies, shared by
 * the standalone HTML report the CLI writes and the VulnDB site's exposure page.
 *
 * Report data comes from untrusted pages (URLs, CSP strings, vendor-controlled
 * hostnames), so every value is written with textContent; nothing from the
 * report is parsed as HTML.
 *
 *   TPScanReport.render(containerElement, reportObject)
 */
(function (root) {
  'use strict';

  var RATINGS = ['critical', 'high', 'medium', 'low', 'none'];
  var TREE_KINDS = { script: 1, iframe: 1, worker: 1, 'service-worker': 1 };

  var CSS = [
    '.tps{--tps-bg:var(--bg,#0f172a);--tps-surface:var(--surface,#1e293b);--tps-border:var(--border,#334155);',
    '--tps-accent:var(--accent,#38bdf8);--tps-text:var(--text,#e2e8f0);--tps-muted:var(--muted,#94a3b8);',
    '--tps-crit:var(--crit,#ef4444);--tps-high:var(--high,#f97316);--tps-med:var(--med,#eab308);--tps-low:var(--low,#22c55e);',
    'color:var(--tps-text);font-family:"Segoe UI",system-ui,sans-serif;line-height:1.5;font-size:15px}',
    '.tps *{box-sizing:border-box}',
    '.tps section{background:var(--tps-surface);border:1px solid var(--tps-border);border-radius:12px;padding:20px 22px;margin:0 0 18px}',
    '.tps h2{font-size:1.05rem;margin:0 0 12px;color:var(--tps-accent);font-weight:600}',
    '.tps h3{font-size:.92rem;margin:16px 0 8px;color:var(--tps-text)}',
    '.tps .tps-muted{color:var(--tps-muted)}',
    '.tps .tps-url{font-family:ui-monospace,Consolas,monospace;font-size:.82rem;word-break:break-all}',
    '.tps .tps-head{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-start;justify-content:space-between}',
    '.tps .tps-head h1{font-size:1.25rem;margin:0 0 4px;word-break:break-all}',
    '.tps .tps-tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:16px}',
    '.tps .tps-tile{background:var(--tps-bg);border:1px solid var(--tps-border);border-radius:10px;padding:12px 14px}',
    '.tps .tps-tile b{display:block;font-size:1.5rem;font-variant-numeric:tabular-nums}',
    '.tps .tps-tile span{font-size:.78rem;color:var(--tps-muted)}',
    '.tps .tps-badge{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;',
    'padding:2px 8px;border-radius:4px;border:1px solid currentColor;white-space:nowrap}',
    '.tps .tps-badge.big{font-size:.95rem;padding:6px 14px}',
    '.tps .r-critical{color:var(--tps-crit)}.tps .r-high{color:var(--tps-high)}.tps .r-medium{color:var(--tps-med)}',
    '.tps .r-low{color:var(--tps-low)}.tps .r-none{color:var(--tps-muted)}',
    '.tps details.tps-vendor{border-top:1px solid var(--tps-border)}',
    '.tps details.tps-vendor:first-of-type{border-top:0}',
    '.tps details.tps-vendor>summary{display:grid;grid-template-columns:86px minmax(0,1.3fr) minmax(0,1fr) 60px;gap:12px;',
    'align-items:center;padding:10px 4px;cursor:pointer;list-style:none}',
    '.tps details.tps-vendor>summary::-webkit-details-marker{display:none}',
    '.tps details.tps-vendor>summary:hover{background:rgba(148,163,184,.06)}',
    '.tps .tps-vname{font-weight:600}',
    '.tps .tps-cat{font-size:.78rem;color:var(--tps-muted)}',
    '.tps .tps-count{text-align:right;color:var(--tps-muted);font-size:.85rem;white-space:nowrap}',
    '.tps .tps-items{padding:4px 4px 14px 14px}',
    '.tps .tps-item{border-left:3px solid var(--tps-border);padding:8px 12px;margin:8px 0;background:var(--tps-bg);border-radius:0 8px 8px 0}',
    '.tps .tps-item.r-critical{border-left-color:var(--tps-crit)}.tps .tps-item.r-high{border-left-color:var(--tps-high)}',
    '.tps .tps-item.r-medium{border-left-color:var(--tps-med)}.tps .tps-item.r-low{border-left-color:var(--tps-low)}',
    '.tps .tps-item{color:var(--tps-text)}',
    '.tps .tps-meta{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:.78rem;color:var(--tps-muted);margin-top:4px}',
    '.tps ul.tps-reasons{margin:6px 0 0;padding-left:18px;font-size:.85rem}',
    '.tps .tps-mod{display:inline-block;font-size:.7rem;padding:1px 7px;border-radius:10px;background:rgba(56,189,248,.12);color:var(--tps-accent);margin-right:4px}',
    '.tps ul.tps-tree,.tps ul.tps-tree ul{list-style:none;margin:0;padding-left:18px}',
    '.tps ul.tps-tree{padding-left:0}',
    '.tps ul.tps-tree li{position:relative;padding:3px 0 3px 14px;border-left:1px solid var(--tps-border)}',
    '.tps ul.tps-tree li::before{content:"";position:absolute;left:0;top:14px;width:10px;border-top:1px solid var(--tps-border)}',
    '.tps .tps-node{display:inline-flex;flex-wrap:wrap;gap:6px;align-items:baseline}',
    '.tps .tps-node.third .tps-url{color:var(--tps-high)}',
    '.tps .tps-kind{font-size:.7rem;color:var(--tps-muted);text-transform:uppercase;letter-spacing:.4px}',
    '.tps .tps-leaf{font-size:.78rem;color:var(--tps-muted)}',
    '.tps table.tps-kv{width:100%;border-collapse:collapse;font-size:.88rem}',
    '.tps table.tps-kv th{text-align:left;color:var(--tps-muted);font-weight:500;padding:6px 12px 6px 0;width:200px;vertical-align:top}',
    '.tps table.tps-kv td{padding:6px 0;vertical-align:top}',
    '.tps ul.tps-issues{margin:0;padding-left:18px}',
    '.tps ul.tps-issues li{margin:3px 0}',
    '.tps .tps-pill{display:inline-block;margin:2px 6px 2px 0;padding:2px 9px;border-radius:12px;background:var(--tps-bg);border:1px solid var(--tps-border);font-size:.82rem}',
    '.tps section.tps-limits{border-color:var(--tps-med);background:rgba(234,179,8,.06)}',
    '.tps section.tps-limits h2{color:var(--tps-med)}',
    '.tps section.tps-limits li{margin:4px 0;font-size:.88rem}',
    '.tps .tps-bar{display:flex;height:8px;border-radius:4px;overflow:hidden;background:var(--tps-bg);margin-top:14px;gap:2px}',
    '.tps .tps-bar i{display:block;height:100%}',
    '@media (max-width:640px){.tps section{padding:16px 14px}',
    '.tps details.tps-vendor>summary{grid-template-columns:76px minmax(0,1fr) auto}.tps details.tps-vendor>summary .tps-domains{display:none}',
    '.tps table.tps-kv th{width:120px}}',
  ].join('');

  function el(tag, props) {
    var node = document.createElement(tag);
    if (props) {
      for (var k in props) {
        if (k === 'text') node.textContent = props[k];
        else if (k === 'cls') node.className = props[k];
        else node.setAttribute(k, props[k]);
      }
    }
    for (var i = 2; i < arguments.length; i++) {
      var c = arguments[i];
      if (c === null || c === undefined || c === false) continue;
      if (Array.isArray(c)) c.forEach(function (x) { if (x) node.appendChild(typeof x === 'string' ? document.createTextNode(x) : x); });
      else node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return node;
  }

  function badge(rating, big, noneLabel) {
    return el('span', { cls: 'tps-badge r-' + rating + (big ? ' big' : ''), text: rating === 'none' ? (noneLabel || 'no third party') : rating });
  }

  function plural(n, word) {
    return n + ' ' + word + (n === 1 ? '' : 's');
  }

  function fmtDate(iso) {
    var d = new Date(iso);
    if (isNaN(d)) return iso;
    return d.toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }) + ' UTC';
  }

  function tile(value, label) {
    return el('div', { cls: 'tps-tile' }, el('b', { text: String(value) }), el('span', { text: label }));
  }

  function headerSection(r) {
    var s = r.summary;
    var colours = { critical: 'var(--tps-crit)', high: 'var(--tps-high)', medium: 'var(--tps-med)', low: 'var(--tps-low)' };
    var bar = el('div', { cls: 'tps-bar', role: 'img', 'aria-label': 'Third-party items by rating' });
    ['critical', 'high', 'medium', 'low'].forEach(function (k) {
      if (s.byRating[k]) bar.appendChild(el('i', { style: 'flex:' + s.byRating[k] + ';background:' + colours[k], title: s.byRating[k] + ' ' + k }));
    });
    var signals = r.page.sensitiveSignals.length ? 'Sensitive page: ' + r.page.sensitiveSignals.join(', ') : 'No password, payment or login fields found';
    return el('section', null,
      el('div', { cls: 'tps-head' },
        el('div', null,
          el('h1', { cls: 'tps-url', text: r.scan.finalUrl }),
          el('div', { cls: 'tps-muted', text: 'Scanned ' + fmtDate(r.scan.scannedAt) + ' · passes: ' + r.scan.passes.join(', ') + ' · tpscan ' + r.scan.toolVersion }),
          r.scan.url !== r.scan.finalUrl ? el('div', { cls: 'tps-muted tps-url', text: 'Requested ' + r.scan.url }) : null,
          el('div', { cls: 'tps-muted', text: signals })),
        el('div', null, el('div', { cls: 'tps-muted', text: 'Overall exposure' }), badge(r.page.rating, true))),
      el('div', { cls: 'tps-tiles' },
        tile(s.vendors, 'third-party vendors' + (s.unknownVendors ? ' (' + s.unknownVendors + ' unmapped)' : '')),
        tile(s.thirdPartyDomains, 'third-party domains'),
        tile(s.topFrameThirdPartyScripts, 'third-party scripts in the top frame'),
        tile(s.sriCoverage.with + ' of ' + s.sriCoverage.of, 'of those pinned with SRI'),
        tile(s.byRating.critical + s.byRating.high, 'critical or high items')),
      bar);
  }

  function itemCard(it, byId) {
    var parent = it.loadedBy === 'page' ? 'the page' : it.loadedBy ? (byId[it.loadedBy] ? byId[it.loadedBy].url : it.loadedBy) : 'unknown';
    var meta = el('div', { cls: 'tps-meta' },
      el('span', { text: it.kind }),
      el('span', { text: 'frame: ' + it.frame }),
      el('span', { text: 'loaded by: ' + parent }),
      it.kind === 'script' ? el('span', { text: 'SRI: ' + (it.sri === true ? 'yes' : it.sri === false ? 'no' : 'unknown') }) : null,
      it.kind === 'iframe' ? el('span', { text: 'sandbox: ' + (it.sandbox === null ? 'none' : it.sandbox || '(fully sandboxed)') }) : null,
      it.status !== null ? el('span', { text: 'status ' + it.status }) : null,
      el('span', { text: 'seen: ' + it.passes.join(', ') }));
    return el('div', { cls: 'tps-item r-' + it.rating },
      el('div', null, badge(it.rating), ' ', el('span', { cls: 'tps-url', text: it.url })),
      it.modifiers.length ? el('div', { style: 'margin-top:6px' }, it.modifiers.map(function (m) { return el('span', { cls: 'tps-mod', text: m }); })) : null,
      meta,
      it.reasons.length ? el('ul', { cls: 'tps-reasons' }, it.reasons.map(function (x) { return el('li', { text: x }); })) : null);
  }

  function vendorsSection(r, byId) {
    var sec = el('section', null, el('h2', { text: 'Vendors' }));
    if (!r.vendors.length) {
      sec.appendChild(el('p', { cls: 'tps-muted', text: 'No third-party requests were seen.' }));
      return sec;
    }
    r.vendors.forEach(function (v) {
      var d = el('details', { cls: 'tps-vendor' },
        el('summary', null,
          badge(v.rating),
          el('div', null, el('div', { cls: 'tps-vname', text: v.vendor }), el('div', { cls: 'tps-cat', text: v.category + (v.known ? '' : ' · not in vendor map') })),
          el('div', { cls: 'tps-url tps-muted tps-domains', text: v.domains.join(', ') }),
          el('div', { cls: 'tps-count', text: plural(v.items.length, 'item') })),
        el('div', { cls: 'tps-items' }, v.items.map(function (id) { return byId[id] ? itemCard(byId[id], byId) : null; })));
      sec.appendChild(d);
    });
    var firstParty = r.items.filter(function (i) { return i.party !== 'third'; }).length;
    if (firstParty) sec.appendChild(el('p', { cls: 'tps-muted', style: 'margin:12px 0 0;font-size:.85rem', text: plural(firstParty, 'first-party or owned request') + ' not listed (in the JSON and CSV).' }));
    return sec;
  }

  function treeSection(r, byId) {
    var children = {};
    r.items.forEach(function (it) {
      var p = it.loadedBy || 'unknown';
      (children[p] = children[p] || []).push(it);
    });
    function leafSummary(list) {
      var counts = {};
      list.forEach(function (it) { if (!TREE_KINDS[it.kind]) counts[it.kind] = (counts[it.kind] || 0) + 1; });
      var parts = Object.keys(counts).sort().map(function (k) { return counts[k] + ' ' + k; });
      return parts.length ? el('span', { cls: 'tps-leaf', text: '→ ' + parts.join(', ') }) : null;
    }
    function branch(parentId, depth) {
      var list = (children[parentId] || []).filter(function (it) { return TREE_KINDS[it.kind]; });
      if (!list.length || depth > 12) return null;
      return el('ul', null, list.map(function (it) {
        return el('li', null,
          el('span', { cls: 'tps-node' + (it.party === 'third' ? ' third' : '') },
            badge(it.rating, false, it.party === 'owned' ? 'owned' : 'first party'), el('span', { cls: 'tps-kind', text: it.kind }), el('span', { cls: 'tps-url', text: it.url }),
            leafSummary(children[it.id] || [])),
          branch(it.id, depth + 1));
      }));
    }
    var tree = el('ul', { cls: 'tps-tree' },
      el('li', null, el('span', { cls: 'tps-node' }, el('b', { text: 'page' }), leafSummary(children.page || [])), branch('page', 0)));
    var sec = el('section', null, el('h2', { text: 'Script chain' }),
      el('p', { cls: 'tps-muted', style: 'margin:0 0 10px;font-size:.85rem', text: 'Who loaded what. Third-party nodes are highlighted; other requests are counted beside the item that made them.' }),
      tree);
    var orphans = (children.unknown || []).filter(function (it) { return it.party === 'third'; });
    if (orphans.length) {
      sec.appendChild(el('h3', { text: 'Loader not identified' }));
      sec.appendChild(el('ul', { cls: 'tps-issues' }, orphans.map(function (it) {
        return el('li', null, badge(it.rating), ' ', el('span', { cls: 'tps-kind', text: it.kind + ' ' }), el('span', { cls: 'tps-url', text: it.url }));
      })));
    }
    return sec;
  }

  function controlsSection(r) {
    var csp = r.page.csp;
    var rows = [
      ['CSP', csp.present ? (csp.reportOnly ? 'report-only (not enforced)' : 'enforcing') : 'none'],
      ['script-src', csp.scriptSrc ? csp.scriptSrc.join(' ') : 'not set'],
      ['connect-src', csp.connectSrc ? csp.connectSrc.join(' ') : 'not set'],
      ['SRI coverage', r.summary.sriCoverage.with + ' of ' + plural(r.summary.sriCoverage.of, 'third-party script') + ' in the top frame'],
      ['Permissions-Policy', r.page.permissionsPolicy || 'not set'],
      ['Inline scripts', String(r.page.inlineScripts.count)],
      ['Third-party cookies', String(r.cookies.thirdParty.length)],
    ];
    var sec = el('section', null, el('h2', { text: 'Page controls' }),
      el('table', { cls: 'tps-kv' }, el('tbody', null, rows.map(function (row) {
        return el('tr', null, el('th', { text: row[0] }), el('td', { cls: /src$/.test(row[0]) ? 'tps-url' : '', text: row[1] }));
      }))));
    if (csp.issues.length) {
      sec.appendChild(el('h3', { text: 'CSP findings' }));
      sec.appendChild(el('ul', { cls: 'tps-issues' }, csp.issues.map(function (i) { return el('li', { text: i }); })));
    }
    if (csp.policies.length) {
      sec.appendChild(el('h3', { text: 'Policies' }));
      sec.appendChild(el('ul', { cls: 'tps-issues' }, csp.policies.map(function (p) {
        return el('li', null, el('span', { cls: 'tps-muted', text: p.source + (p.reportOnly ? ', report-only: ' : ': ') }), el('span', { cls: 'tps-url', text: p.raw }));
      })));
    }
    if (r.cookies.thirdParty.length) {
      sec.appendChild(el('h3', { text: 'Third-party cookies' }));
      sec.appendChild(el('div', null, r.cookies.thirdParty.map(function (c) {
        return el('span', { cls: 'tps-pill', text: c.domain + ' · ' + c.name + ' · SameSite=' + c.sameSite + (c.secure ? ' · Secure' : '') });
      })));
    }
    return sec;
  }

  function consentSection(r) {
    var c = r.consent;
    var sec = el('section', null, el('h2', { text: 'Consent' }));
    if (c.mode === 'none' || !c.diff) {
      sec.appendChild(el('p', { cls: 'tps-muted', text: 'Consent was not exercised in this scan (--consent none).' }));
      return sec;
    }
    sec.appendChild(el('p', { cls: 'tps-muted', style: 'margin:0 0 6px', text: c.passes.map(function (p) {
      return p.name + ': ' + (p.clicked ? 'clicked via ' + p.method : 'no consent control found');
    }).join(' · ') }));
    function list(title, names, empty) {
      return [el('h3', { text: title }), names.length
        ? el('div', null, names.map(function (n) { return el('span', { cls: 'tps-pill', text: n }); }))
        : el('p', { cls: 'tps-muted', style: 'margin:0', text: empty })];
    }
    sec.appendChild(el('div', null, list('Vendors that appear only after accepting', c.diff.onlyAfterAccept, 'None.')));
    sec.appendChild(el('div', null, list('Vendors that load before any choice', c.diff.preConsent, 'None.')));
    if (c.mode === 'both' || c.mode === 'reject') {
      sec.appendChild(el('div', null, list('New vendors after rejecting', c.diff.afterReject, 'None.')));
    }
    return sec;
  }

  function listSection(title, entries, cls) {
    return el('section', { cls: cls || '' }, el('h2', { text: title }),
      el('ul', { cls: 'tps-issues' }, entries.map(function (x) { return el('li', { text: x }); })));
  }

  function render(container, report) {
    if (!document.getElementById('tps-style')) {
      var style = el('style', { id: 'tps-style' });
      style.textContent = CSS;
      document.head.appendChild(style);
    }
    var byId = {};
    report.items.forEach(function (it) { byId[it.id] = it; });
    var wrap = el('div', { cls: 'tps' },
      headerSection(report),
      vendorsSection(report, byId),
      treeSection(report, byId),
      controlsSection(report),
      consentSection(report),
      report.blocked.length ? listSection('Blocked by the private-address guard', report.blocked.map(function (b) { return b.url + ': ' + b.reason; })) : null,
      report.errors.length ? listSection('Scan errors', report.errors) : null,
      listSection('Limitations', report.limitations, 'tps-limits'));
    container.replaceChildren(wrap);
  }

  root.TPScanReport = { render: render, ratings: RATINGS };
})(typeof window !== 'undefined' ? window : this);
