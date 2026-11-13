/* Lightwork markdown: a small, dependency-free renderer for agent prose.
 *
 * The result of a goal, a deliverable, or an answer arrives as markdown-ish
 * text from a model. This turns it into DOM the way a chat client would:
 * headings, paragraphs, lists (nested, ordered, task), fenced and inline
 * code, tables, block quotes, rules, emphasis and links.
 *
 * Every node is built through the DOM API from text, never from markup
 * strings, so model output can't inject markup. Links keep only http(s), mailto,
 * same-origin paths and fragments; anything else renders as plain text.
 * Raw HTML in the source is shown as text, not interpreted.
 */
(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.lwMarkdown = api;
})(typeof window !== 'undefined' ? window : globalThis, function () {
  'use strict';

  var SAFE_HREF = /^(https?:|mailto:|\/(?!\/)|#)/i;
  var FENCE = /^\s{0,3}(`{3,}|~{3,})\s*([\w+-]*)\s*$/;
  var HEADING = /^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$/;
  var RULE = /^\s{0,3}([-*_])(?:\s*\1){2,}\s*$/;
  var QUOTE = /^\s{0,3}>\s?(.*)$/;
  var LIST_ITEM = /^(\s*)([-*+]|\d{1,9}[.)])\s+(.*)$/;
  var TABLE_SEP = /^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$/;
  var TASK = /^\[([ xX])\]\s+(.*)$/;
  var BARE_URL = /^https?:\/\/[^\s<>()\[\]]+/;

  function isBlank(line) { return !line || !line.trim(); }

  function safeHref(url) {
    url = String(url || '').trim();
    if (!url || /[\x00-\x1f\s\\]/.test(url)) return null;
    return SAFE_HREF.test(url) ? url : null;
  }

  /* ---------------------------------------------------------- inline --- */

  function inline(text, parent, doc) {
    var buf = '';
    function flush() {
      if (buf) { parent.appendChild(doc.createTextNode(buf)); buf = ''; }
    }
    function wrap(tag, inner) {
      flush();
      var el = doc.createElement(tag);
      inline(inner, el, doc);
      parent.appendChild(el);
    }
    // A valid opening **, __ or ~~ that finds no closing marker in the rest
    // of the text cannot find one from any later position either. Each kind
    // is therefore searched to the end of the text at most once: a long run
    // of unclosed markers would otherwise cost one full scan apiece.
    var unclosed = {};
    var i = 0, n = text.length, m, rest;
    while (i < n) {
      var ch = text[i];
      rest = text.slice(i);
      if (ch === '\\' && i + 1 < n && /[\\`*_{}\[\]()#+\-.!~|>]/.test(text[i + 1])) {
        buf += text[i + 1]; i += 2; continue;
      }
      if (ch === '`') {
        m = /^(`+)([^`]|[^`][\s\S]*?[^`])\1(?!`)/.exec(rest);
        if (m) {
          flush();
          var code = doc.createElement('code');
          code.textContent = m[2].replace(/^ (?=\S)|(?<=\S) $/g, '');
          parent.appendChild(code);
          i += m[0].length; continue;
        }
      }
      if (ch === '!' && text[i + 1] === '[') {
        m = /^!\[([^\]]*)\]\(((?:[^()\s]|\([^()\s]*\))+)(?:\s+"[^"]*")?\)/.exec(rest);
        if (m) {
          // Never fetch a remote image on the model's say-so; show it as a link.
          var alt = m[1] || 'image';
          var ihref = safeHref(m[2]);
          if (ihref) { flush(); parent.appendChild(link(doc, ihref, alt)); }
          else buf += alt;
          i += m[0].length; continue;
        }
      }
      if (ch === '[') {
        m = /^\[([^\]]+)\]\(((?:[^()\s]|\([^()\s]*\))+)(?:\s+"[^"]*")?\)/.exec(rest);
        if (m) {
          var href = safeHref(m[2]);
          if (href) {
            flush();
            var a = link(doc, href, null);
            inline(m[1], a, doc);
            parent.appendChild(a);
          } else {
            buf += m[1];
          }
          i += m[0].length; continue;
        }
      }
      if (ch === '<') {
        m = /^<(https?:\/\/[^\s>]+|mailto:[^\s>]+)>/.exec(rest);
        if (m) {
          var ahref = safeHref(m[1]);
          if (ahref) { flush(); parent.appendChild(link(doc, ahref, m[1])); }
          else buf += m[1];
          i += m[0].length; continue;
        }
      }
      if (ch === 'h' && (m = BARE_URL.exec(rest))) {
        var url = m[0].replace(/[.,;:!?'"]+$/, '');
        var uhref = safeHref(url);
        if (uhref) { flush(); parent.appendChild(link(doc, uhref, url)); }
        else buf += url;
        i += url.length; continue;
      }
      if (ch === '*' || ch === '_') {
        var dbl = ch + ch;
        if (text[i + 1] === ch && !unclosed[dbl]) {
          m = ch === '*' ? /^\*\*(?=\S)([\s\S]+?)(?<=\S)\*\*/.exec(rest)
                         : /^__(?=\S)([\s\S]+?)(?<=\S)__(?![A-Za-z0-9])/.exec(rest);
          if (m) { wrap('strong', m[1]); i += m[0].length; continue; }
          if (i + 2 < n && /\S/.test(text[i + 2])) unclosed[dbl] = true;
        }
        var prev = i > 0 ? text[i - 1] : ' ';
        var okStart = ch === '*' || !/[A-Za-z0-9]/.test(prev);
        if (okStart) {
          m = ch === '*' ? /^\*(?=\S)([^*]+?)(?<=\S)\*/.exec(rest)
                         : /^_(?=\S)([^_]+?)(?<=\S)_(?![A-Za-z0-9])/.exec(rest);
          if (m) { wrap('em', m[1]); i += m[0].length; continue; }
        }
      }
      if (ch === '~' && text[i + 1] === '~' && !unclosed['~~']) {
        m = /^~~(?=\S)([\s\S]+?)(?<=\S)~~/.exec(rest);
        if (m) { wrap('del', m[1]); i += m[0].length; continue; }
        if (i + 2 < n && /\S/.test(text[i + 2])) unclosed['~~'] = true;
      }
      buf += ch; i += 1;
    }
    flush();
  }

  function link(doc, href, text) {
    var a = doc.createElement('a');
    a.setAttribute('href', href);
    if (/^https?:/i.test(href) || /^mailto:/i.test(href)) {
      a.setAttribute('rel', 'noopener noreferrer');
      if (/^https?:/i.test(href)) a.setAttribute('target', '_blank');
    }
    if (text != null) a.textContent = text;
    return a;
  }

  /* ---------------------------------------------------------- blocks --- */

  function blocks(lines, parent, doc) {
    var i = 0, n = lines.length, para = [];
    function flushPara() {
      if (!para.length) return;
      var p = doc.createElement('p');
      for (var k = 0; k < para.length; k++) {
        if (k) p.appendChild(doc.createElement('br'));
        inline(para[k].trim(), p, doc);
      }
      parent.appendChild(p);
      para = [];
    }
    while (i < n) {
      var line = lines[i], m;
      if (isBlank(line)) { flushPara(); i += 1; continue; }

      if ((m = FENCE.exec(line))) {
        flushPara();
        var fence = m[1], lang = m[2], body = [];
        i += 1;
        while (i < n && !(lines[i].trim().indexOf(fence[0]) === 0 && lines[i].trim().length >= fence.length && /^[`~]+\s*$/.test(lines[i].trim()))) {
          body.push(lines[i]); i += 1;
        }
        i += 1;  // closing fence (or end of input)
        var pre = doc.createElement('pre');
        var code = doc.createElement('code');
        if (lang) code.className = 'language-' + lang.replace(/[^\w+-]/g, '');
        code.textContent = body.join('\n');
        pre.appendChild(code);
        parent.appendChild(pre);
        continue;
      }
      if ((m = HEADING.exec(line))) {
        flushPara();
        // A goal page already has its title; keep model headings below it.
        var h = doc.createElement('h' + Math.min(6, m[1].length + 1));
        inline(m[2], h, doc);
        parent.appendChild(h);
        i += 1; continue;
      }
      if (RULE.test(line)) {
        flushPara(); parent.appendChild(doc.createElement('hr')); i += 1; continue;
      }
      if (QUOTE.test(line)) {
        flushPara();
        var q = [];
        while (i < n && (m = QUOTE.exec(lines[i]))) { q.push(m[1]); i += 1; }
        var bq = doc.createElement('blockquote');
        blocks(q, bq, doc);
        parent.appendChild(bq);
        continue;
      }
      if (line.indexOf('|') !== -1 && i + 1 < n && TABLE_SEP.test(lines[i + 1]) && lines[i + 1].indexOf('|') !== -1) {
        flushPara();
        var header = cells(line), aligns = cells(lines[i + 1]).map(function (c) {
          var l = c.charAt(0) === ':', r = c.charAt(c.length - 1) === ':';
          return l && r ? 'center' : r ? 'right' : l ? 'left' : '';
        });
        i += 2;
        var rows = [];
        while (i < n && !isBlank(lines[i]) && lines[i].indexOf('|') !== -1) { rows.push(cells(lines[i])); i += 1; }
        parent.appendChild(table(doc, header, aligns, rows));
        continue;
      }
      if ((m = LIST_ITEM.exec(line))) {
        flushPara();
        var indent = m[1].length;
        var ordered = /\d/.test(m[2]);
        var items = [], cur = null;
        while (i < n) {
          var l = lines[i], lm = LIST_ITEM.exec(l);
          if (lm && lm[1].length <= indent) {
            if (lm[1].length < indent || (/\d/.test(lm[2]) !== ordered)) break;
            cur = { head: lm[3], tail: [] };
            items.push(cur);
            i += 1; continue;
          }
          if (isBlank(l)) {
            // A blank line ends the list unless the next line is still indented.
            if (i + 1 < n && !isBlank(lines[i + 1]) && /^\s+/.test(lines[i + 1]) && leading(lines[i + 1]) > indent) {
              cur.tail.push(''); i += 1; continue;
            }
            break;
          }
          if (leading(l) > indent && cur) { cur.tail.push(l.slice(Math.min(leading(l), indent + 2))); i += 1; continue; }
          break;
        }
        var list = doc.createElement(ordered ? 'ol' : 'ul');
        if (ordered) {
          var start = parseInt(m[2], 10);
          if (start !== 1 && !isNaN(start)) list.setAttribute('start', String(start));
        }
        items.forEach(function (it) {
          var li = doc.createElement('li');
          var tm = TASK.exec(it.head);
          if (tm) {
            var box = doc.createElement('input');
            box.type = 'checkbox'; box.disabled = true; box.checked = tm[1] !== ' ';
            box.setAttribute('aria-label', tm[1] === ' ' ? 'not done' : 'done');
            li.appendChild(box); li.appendChild(doc.createTextNode(' '));
            it.head = tm[2];
            li.className = 'task';
          }
          inline(it.head, li, doc);
          if (it.tail.length) blocks(it.tail, li, doc);
          list.appendChild(li);
        });
        parent.appendChild(list);
        continue;
      }
      para.push(line);
      i += 1;
    }
    flushPara();
  }

  function leading(line) { return line.length - line.replace(/^\s+/, '').length; }

  function cells(line) {
    var t = line.trim();
    if (t.charAt(0) === '|') t = t.slice(1);
    if (t.charAt(t.length - 1) === '|') t = t.slice(0, -1);
    return t.split(/(?<!\\)\|/).map(function (c) { return c.trim().replace(/\\\|/g, '|'); });
  }

  function table(doc, header, aligns, rows) {
    var tbl = doc.createElement('table');
    var thead = doc.createElement('thead'), tr = doc.createElement('tr');
    header.forEach(function (c, idx) {
      var th = doc.createElement('th'); th.setAttribute('scope', 'col');
      if (aligns[idx]) th.style.textAlign = aligns[idx];
      inline(c, th, doc); tr.appendChild(th);
    });
    thead.appendChild(tr); tbl.appendChild(thead);
    var tbody = doc.createElement('tbody');
    rows.forEach(function (r) {
      var row = doc.createElement('tr');
      for (var k = 0; k < header.length; k++) {
        var td = doc.createElement('td');
        if (aligns[k]) td.style.textAlign = aligns[k];
        inline(r[k] || '', td, doc); row.appendChild(td);
      }
      tbody.appendChild(row);
    });
    tbl.appendChild(tbody);
    return tbl;
  }

  /* ------------------------------------------------------------- api --- */

  function render(text, doc) {
    doc = doc || document;
    var frag = doc.createDocumentFragment();
    var lines = String(text == null ? '' : text).replace(/\r\n?/g, '\n').split('\n');
    blocks(lines, frag, doc);
    return frag;
  }

  /* Replace an element's text with its rendered form. The element keeps its
     id/classes; data-markdown is dropped so CSS can stop pre-wrapping it. */
  function renderInto(el, text) {
    if (!el) return;
    if (text == null) text = el.textContent;
    var doc = el.ownerDocument || document;
    var frag = render(text, doc);
    while (el.firstChild) el.removeChild(el.firstChild);
    el.appendChild(frag);
    el.removeAttribute('data-markdown');
  }

  function upgrade(rootEl) {
    var scope = rootEl || (typeof document !== 'undefined' ? document : null);
    if (!scope || !scope.querySelectorAll) return;
    Array.prototype.forEach.call(scope.querySelectorAll('[data-markdown]'), function (el) {
      renderInto(el, el.textContent);
    });
  }

  return { render: render, renderInto: renderInto, upgrade: upgrade, safeHref: safeHref };
});
