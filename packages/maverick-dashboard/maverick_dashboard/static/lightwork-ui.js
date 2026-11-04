/* Lightwork dashboard shell behaviors, kept apart from templates/base.html;
   served by GET /static/lightwork-ui.js. Loaded at the end of <body>, so
   the DOM is ready without defer. First section: reusable feedback
   primitives (mvToast/mvConfirm/mvForm/mvCopy). Second: halt pill, goal
   form, sidebar + preferences behaviors. */
    // Bind every same-origin browser mutation to the workspace this document
    // was rendered under. A selection changed in another tab then receives a
    // server-side 409 instead of writing into the newly selected tenant.
    (function () {
      var meta = document.querySelector('meta[name="lightwork-workspace-tenant"]');
      var expected = meta ? String(meta.getAttribute('content') || '').trim() : '';
      window.mvWorkspaceTenant = expected;
      if (!expected) return;

      var contextChanged = false;
      function invalidateWorkspace() {
        if (contextChanged) return;
        contextChanged = true;
        var notice = document.createElement('section');
        notice.className = 'panel'; notice.setAttribute('role', 'alert');
        var message = 'Your workspace changed in another tab. Changes here are paused. Keep any draft you need, then reopen this page in the current workspace.';
        if (window.LightworkI18n) window.LightworkI18n.set(notice, message);
        else notice.textContent = message;
        notice.appendChild(document.createTextNode(' '));
        var reopen = document.createElement('a'); reopen.href = window.location.href;
        if (window.LightworkI18n) window.LightworkI18n.set(reopen, 'Reopen in current workspace');
        else reopen.textContent = 'Reopen in current workspace';
        notice.appendChild(reopen);
        // Keep recovery inside the content layout so the fixed sidebar cannot
        // cover the link. The alert announces the change without moving focus
        // away from a draft the person may still need to copy.
        var content = document.querySelector('main') || document.body;
        content.insertBefore(notice, content.firstChild);
        window.dispatchEvent(new CustomEvent('lightwork:context-changed'));
        // Pages clear what they showed for the previous workspace or account
        // on these. Sent from document and bubbling, so listeners on document
        // and on window both hear them.
        ['lightwork:workspace-changed', 'lightwork:account-context-changed', 'lightwork:authority-changed',
         'lightwork:draft-context-changed', 'lightwork:copilot-context-changed'].forEach(function (name) {
          document.dispatchEvent(new CustomEvent(name, {bubbles: true}));
        });
      }
      window.addEventListener('storage', function (event) {
        if (event.key === 'lightwork-workspace-changed') invalidateWorkspace();
      });
      var nativeFetch = window.fetch.bind(window);
      window.fetch = function (input, init) {
        var opts = init ? Object.assign({}, init) : {};
        var method = String(opts.method || (input instanceof Request ? input.method : 'GET')).toUpperCase();
        var unsafe = !['GET', 'HEAD', 'OPTIONS'].includes(method);
        var rawUrl = input instanceof Request ? input.url : input;
        var sameOrigin = false;
        try { sameOrigin = new URL(String(rawUrl), window.location.href).origin === window.location.origin; }
        catch (e) { sameOrigin = false; }
        if (!unsafe || !sameOrigin) return nativeFetch(input, init);
        if (contextChanged) return Promise.reject(new Error('Workspace changed. Reopen this page before saving.'));

        var headers = new Headers(opts.headers || (input instanceof Request ? input.headers : undefined));
        if (!headers.has('X-Lightwork-Expected-Tenant')) {
          headers.set('X-Lightwork-Expected-Tenant', expected);
        }
        opts.headers = headers;
        if (input instanceof Request) return nativeFetch(new Request(input, opts));
        return nativeFetch(input, opts);
      };

      document.addEventListener('submit', function (event) {
        var form = event.target;
        if (!(form instanceof HTMLFormElement)) return;
        var method = String(form.method || 'get').toUpperCase();
        if (['GET', 'HEAD', 'OPTIONS'].includes(method)) return;
        var sameOrigin = false;
        try { sameOrigin = new URL(form.action || window.location.href, window.location.href).origin === window.location.origin; }
        catch (e) { sameOrigin = false; }
        if (!sameOrigin) return;
        if (contextChanged) { event.preventDefault(); event.stopImmediatePropagation(); return; }
        var field = form.querySelector('input[name="_expected_tenant"]');
        if (!field) {
          field = document.createElement('input');
          field.type = 'hidden'; field.name = '_expected_tenant';
          form.appendChild(field);
        }
        field.value = expected;
      }, true);
    })();

    // Reusable feedback primitives, on every page that extends base.html.
    // Prefer these over the browser's native dialogs. Contract: docs/ui-primitives.md.
    //   window.mvToast(message, {error, quiet}) -> transient status/alert toast
    //   window.mvConfirm(message, {okText, cancelText, danger, typed}) -> Promise<bool>
    //     (native <dialog>; focus starts on the safe choice and returns to the
    //     opener; not re-entrant; falls back to window.confirm). Say what will
    //     happen and to what ("Delete the automation "Weekly report"? It stops
    //     running."); okText names the action ("Delete automation"), never "OK".
    //     danger: style the action as destructive. typed: a word the person
    //     must type before the action unlocks, for workspace-wide deletes.
    //   window.mvCopy(text) -> copy to clipboard with a toast (+ fallback)
    (function () {
      var region = document.getElementById('mv-toasts');
      var alertRegion = document.getElementById('mv-toasts-alert');
      window.mvToast = function (message, opts) {
        opts = opts || {};
        // Route to a region whose live politeness is fixed at load (an injected
        // role can't reliably upgrade a polite region to assertive); prefix
        // errors so the state survives grayscale / color-blindness.
        var target = opts.error ? alertRegion : region;
        if (!target) return;
        var t = document.createElement('div');
        t.className = 'mv-toast' + (opts.error ? ' mv-toast--error' : '');
        t.textContent = (opts.error ? '⚠ ' : '') + String(message);
        // quiet: the page already says these words where the person is (its
        // own status line or a focus move), so the toast is shown, not read
        // a second time.
        if (opts.quiet) t.setAttribute('aria-hidden', 'true');
        if(window.LightworkI18n){t.lang=window.LightworkI18n.languageFor(String(message));t.dir='auto';}
        target.appendChild(t);
        setTimeout(function () {
          t.style.transition = 'opacity 200ms'; t.style.opacity = '0';
          setTimeout(function () { t.remove(); }, 220);
        }, opts.error ? 5000 : 3200);
      };
      // A way back from a delete (Gmail's Undo Send): the item goes from the
      // page at once and a toast offers Undo, and Ctrl+Z or Cmd+Z, for
      // opts.seconds (10 by default, never under 5; the time stops while the
      // pointer or focus is on the toast). The delete is sent only when that
      // time is up, when the person leaves the page (keepalive), or when
      // another delete starts. Nothing is kept anywhere in the meantime, so
      // a privacy erasure is never held back by it. If the delete then fails,
      // undo() puts the item back and the failure is shown.
      //   window.mvUndo(message, {run(keepalive) -> Promise<Response>, undo(), done(), action, seconds, latest, values})
      var pendingUndo = null;
      function typing(target) {
        return target && target.closest && !!target.closest('input, textarea, select, [contenteditable="true"]');
      }
      window.mvUndo = function (message, opts) {
        opts = opts || {};
        if (pendingUndo) pendingUndo.commit(false);   // one at a time: the earlier delete goes through now
        var wait = Math.max(5, Number(opts.seconds) || 10) * 1000;
        var toast = document.createElement('div');
        toast.className = 'mv-toast mv-toast--undo';
        // The words go through the translator like other product copy; a
        // name in opts.values ({name}) is shown as written, never translated.
        var words = document.createElement('span');
        if (window.LightworkI18n) window.LightworkI18n.set(words, String(message), opts.values); else words.textContent = String(message).replace(/\{([A-Za-z0-9_]+)\}/g, function (whole, key) { return opts.values && Object.prototype.hasOwnProperty.call(opts.values, key) ? String(opts.values[key]) : whole; });
        var undoBtn = document.createElement('button'); undoBtn.type = 'button';
        undoBtn.className = 'mv-toast__undo'; undoBtn.setAttribute('aria-keyshortcuts', 'Control+Z Meta+Z');
        if (window.LightworkI18n) window.LightworkI18n.set(undoBtn, 'Undo'); else undoBtn.textContent = 'Undo';
        toast.append(words, document.createTextNode(' '), undoBtn);
        if (region) region.appendChild(toast);
        var settled = false, timer = null, startedAt = 0, hard = null;
        // opts.latest (epoch ms): the delete goes through by then even while
        // the toast is paused, e.g. before a schedule's next run.
        if (opts.latest) hard = setTimeout(function () { entry.commit(false); }, Math.max(0, Number(opts.latest) - Date.now()));
        function start() { startedAt = Date.now(); timer = setTimeout(function () { entry.commit(false); }, wait); }
        function pause() { if (timer) { clearTimeout(timer); timer = null; wait = Math.max(1000, wait - (Date.now() - startedAt)); } }
        function finish() {
          settled = true; pause(); if (hard) clearTimeout(hard);
          toast.remove();
          window.removeEventListener('pagehide', onHide);
          document.removeEventListener('keydown', onKey);
          if (pendingUndo === entry) pendingUndo = null;
        }
        function onHide() { entry.commit(true); }
        function onKey(event) {
          if ((event.ctrlKey || event.metaKey) && !event.shiftKey && !event.altKey &&
              String(event.key).toLowerCase() === 'z' && !typing(event.target)) {
            event.preventDefault(); entry.undo();
          }
        }
        var entry = {
          commit: async function (keepalive) {
            if (settled) return 'settled';
            finish();
            try {
              var response = await opts.run(!!keepalive);
              if (response && response.ok === false) throw response;
              if (opts.done) opts.done();
              return 'done';
            } catch (failure) {
              if (opts.undo) opts.undo();
              // A page that already explained the refusal marks it handled.
              if (!(failure && failure.handled)) window.mvFail(failure, opts.action || 'delete it');
              return 'failed';
            }
          },
          undo: function () {
            if (settled) return 'settled';
            finish();
            if (opts.undo) opts.undo();
            mvToast(productText('Restored.'));
            return 'undone';
          }
        };
        undoBtn.addEventListener('click', function () { entry.undo(); });
        toast.addEventListener('mouseenter', pause);
        toast.addEventListener('focusin', pause);
        toast.addEventListener('mouseleave', function () { if (!settled && !timer && !toast.contains(document.activeElement)) start(); });
        toast.addEventListener('focusout', function () { if (!settled && !timer) start(); });
        window.addEventListener('pagehide', onHide);
        document.addEventListener('keydown', onKey);
        pendingUndo = entry;
        start();
        return entry;
      };
      var dlg = document.getElementById('mv-confirm');
      var msgEl = document.getElementById('mv-confirm-msg');
      var okBtn = document.getElementById('mv-confirm-ok');
      var cancelBtn = document.getElementById('mv-confirm-cancel');
      window.mvConfirm = function (message, opts) {
        opts = opts || {};
        if (!dlg || typeof dlg.showModal !== 'function') {
          return Promise.resolve(window.confirm(opts.productCopy && window.LightworkI18n ? window.LightworkI18n.text(String(message), opts.values) : String(message)));
        }
        if (dlg.open) return Promise.resolve(false);   // not re-entrant (shared dialog)
        var opener = document.activeElement;           // restore focus on close
        if (opts.productCopy && window.LightworkI18n) window.LightworkI18n.set(msgEl, String(message), opts.values);
        else { msgEl.textContent = String(message); msgEl.lang = 'und'; msgEl.dir = 'auto'; }
        if (window.LightworkI18n) { window.LightworkI18n.set(okBtn, opts.okText || 'Confirm'); window.LightworkI18n.set(cancelBtn, opts.cancelText || 'Cancel'); }
        else { okBtn.textContent = opts.okText || 'Confirm'; cancelBtn.textContent = opts.cancelText || 'Cancel'; }
        okBtn.classList.toggle('btn--danger', !!opts.danger);
        okBtn.classList.toggle('btn--primary', !opts.danger);
        var typedWrap = document.getElementById('mv-confirm-typed');
        if (typedWrap) typedWrap.remove();
        typedWrap = null;
        var typedInput = null;
        if (opts.typed) {
          typedWrap = document.createElement('p'); typedWrap.id = 'mv-confirm-typed'; typedWrap.className = 'mv-confirm__typed';
          var typedLabel = document.createElement('label'); typedLabel.setAttribute('for', 'mv-confirm-typed-input');
          typedLabel.textContent = window.LightworkI18n ? window.LightworkI18n.text('Type {word} to confirm', {word: String(opts.typed)}) : 'Type ' + String(opts.typed) + ' to confirm';
          typedInput = document.createElement('input'); typedInput.id = 'mv-confirm-typed-input'; typedInput.className = 'input';
          typedInput.autocomplete = 'off'; typedInput.spellcheck = false;
          typedWrap.append(typedLabel, typedInput);
          msgEl.insertAdjacentElement('afterend', typedWrap);
          okBtn.disabled = true;
          typedInput.addEventListener('input', function () { okBtn.disabled = typedInput.value.trim() !== String(opts.typed); });
        } else okBtn.disabled = false;
        return new Promise(function (resolve) {
          function done(val) {
            if (typedWrap) typedWrap.remove();
            okBtn.disabled = false;
            okBtn.removeEventListener('click', onOk);
            cancelBtn.removeEventListener('click', onCancel);
            dlg.removeEventListener('cancel', onCancel);
            if (dlg.open) dlg.close();
            // Return focus to the opener when it survives; a delete that removed
            // its own row leaves the caller to re-home focus to a stable spot.
            if (opener && opener.isConnected && typeof opener.focus === 'function') opener.focus();
            resolve(val);
          }
          function onOk() { if (typedInput && typedInput.value.trim() !== String(opts.typed)) return; done(true); }
          function onCancel(e) { if (e) e.preventDefault(); done(false); }
          okBtn.addEventListener('click', onOk);
          cancelBtn.addEventListener('click', onCancel);
          dlg.addEventListener('cancel', onCancel);   // Esc / backdrop
          dlg.showModal();
          cancelBtn.focus();
        });
      };
      // Collect a small set of typed fields in a modal form (replaces per-value
      // window.prompt chains). fields: [{key,label,type,required,default,options,
      // placeholder,help}] where type is text|number|date|bool|select. Resolves to
      // a {key:value} object, or null if cancelled. Falls back to sequential
      // prompts where <dialog> is unsupported.
      var fdlg = document.getElementById('mv-form');
      function productText(source, values) {
        return window.LightworkI18n ? window.LightworkI18n.text(source, values) : source;
      }
      function productSet(element, source, values) {
        if (window.LightworkI18n) window.LightworkI18n.set(element, source, values);
        else element.textContent = source;
      }
      function booleanDefault(value) {
        // Imported fields can carry serialized booleans. Only an explicit
        // affirmative value may preselect a boolean; "false" is not truthy here.
        return value === true || value === 1 ||
          (typeof value === 'string' && /^(true|yes|1)$/i.test(value.trim()));
      }
      window.mvForm = function (title, fields, opts) {
        opts = opts || {};
        fields = fields || [];
        if (!fdlg || typeof fdlg.showModal !== 'function') {
          var out0 = {};
          for (var i = 0; i < fields.length; i++) {
            var s = fields[i];
            var promptLabel = (s.label || s.key) + (s.required ? ' (required)' : '');
            var boolField = s.type === 'bool' || s.type === 'checkbox';
            var choices = (s.options || []).map(function (o) {
              return String(o && o.value != null ? o.value : o);
            });
            if (boolField) promptLabel += ' (true or false)';
            if (s.type === 'select') promptLabel += ' (' + choices.join(', ') + ')';
            var problem = '';
            while (true) {
              var v0 = window.prompt((problem ? problem + '\n' : '') + promptLabel,
                boolField ? String(booleanDefault(s.default)) : s.default != null ? String(s.default) : '');
              if (v0 === null) return Promise.resolve(null);
              if (!s.preserveWhitespace) v0 = v0.trim();
              if (!v0 && s.required && !s.allowEmpty) { problem = productText('This field is required.'); continue; }
              if (boolField) {
                if (!/^(true|false|yes|no|1|0)$/i.test(v0)) {
                  problem = productText('Enter true or false.'); continue;
                }
                out0[s.key] = /^(true|yes|1)$/i.test(v0);
              } else if (v0 || s.allowEmpty) {
                if (s.type === 'number' && !Number.isFinite(Number(v0))) {
                  problem = productText('Enter a valid number.'); continue;
                }
                if (s.type === 'select' && choices.indexOf(v0) < 0) {
                  problem = productText('Choose one of the listed values.'); continue;
                }
                out0[s.key] = v0;
              }
              break;
            }
          }
          return Promise.resolve(out0);
        }
        if (fdlg.open) return Promise.resolve(null);   // shared dialog, not re-entrant
        var opener = document.activeElement;
        var form = document.getElementById('mv-form-form');
        var body = document.getElementById('mv-form-fields');
        var errEl = document.getElementById('mv-form-err');
        var cancelBtn = document.getElementById('mv-form-cancel');
        var titleElement = document.getElementById('mv-form-title');
        if (!title || opts.productCopy) productSet(titleElement, String(title || 'Details'));
        else { titleElement.textContent = String(title); titleElement.lang = 'und'; titleElement.dir = 'auto'; }
        productSet(document.getElementById('mv-form-ok'), opts.okText || 'OK');
        body.textContent = ''; errEl.textContent = '';
        var controls = [];
        fields.forEach(function (f) {
          var id = 'mvf-' + f.key;
          var wrap = document.createElement('div'); wrap.className = 'mv-form__field';
          var ctl;
          if (f.type === 'bool' || f.type === 'checkbox') {
            wrap.className += ' mv-form__check';
            ctl = document.createElement('input'); ctl.type = 'checkbox'; ctl.checked = booleanDefault(f.default); ctl.id = id;
            var l1 = document.createElement('label'); l1.setAttribute('for', id); l1.textContent = f.label || f.key; l1.lang = 'und'; l1.dir = 'auto';
            wrap.appendChild(ctl); wrap.appendChild(l1);
          } else {
            var lab = document.createElement('label'); lab.setAttribute('for', id);
            lab.textContent = f.label || f.key; lab.lang = 'und'; lab.dir = 'auto';
            wrap.appendChild(lab);
            if (f.type === 'select') {
              ctl = document.createElement('select');
              (f.options || []).forEach(function (o) {
                var op = document.createElement('option');
                op.value = (o && o.value != null) ? o.value : o;
                op.textContent = (o && o.label != null) ? o.label : o; op.lang = 'und'; op.dir = 'auto';
                ctl.appendChild(op);
              });
              if (f.default != null) ctl.value = String(f.default);
            } else {
              ctl = document.createElement('input');
              ctl.type = f.type === 'number' ? 'number' : f.type === 'date' ? 'date' : 'text';
              if (f.type === 'number') ctl.step = 'any';
              ctl.className = 'input';
              if (f.default != null) ctl.value = String(f.default);
              if (f.placeholder) ctl.placeholder = f.placeholder;
            }
            ctl.id = id;
            ctl.required = !!f.required;
            wrap.appendChild(ctl);
          }
          if (f.help) {
            var h = document.createElement('div'); h.className = 'mv-form__help';
            h.id = id + '-help'; h.textContent = f.help; h.lang = 'und'; h.dir = 'auto';
            ctl.setAttribute('aria-describedby', h.id); wrap.appendChild(h);
          }
          controls.push({ f: f, ctl: ctl });
          body.appendChild(wrap);
        });
        return new Promise(function (resolve) {
          function collect() {
            var out = {}, missing = [], firstMissing = null;
            controls.forEach(function (c) {
              c.ctl.removeAttribute('aria-invalid');
              if (c.f.type === 'bool' || c.f.type === 'checkbox') { out[c.f.key] = c.ctl.checked; return; }
              var val = c.ctl.value || '';
              if (!c.f.preserveWhitespace) val = val.trim();
              if (!val && c.f.required && !c.f.allowEmpty) {
                missing.push(c.f.label || c.f.key); c.ctl.setAttribute('aria-invalid', 'true');
                if (!firstMissing) firstMissing = c.ctl;
                return;
              }
              if (val || c.f.allowEmpty) out[c.f.key] = val;
            });
            if (missing.length) {
              if (window.LightworkI18n) window.LightworkI18n.set(errEl, 'Required: {fields}', {fields: missing.join(', ')});
              else errEl.textContent = 'Required: ' + missing.join(', ');
              firstMissing.focus(); return null;
            }
            return out;
          }
          function done(val) {
            form.removeEventListener('submit', onSubmit);
            cancelBtn.removeEventListener('click', onCancel);
            fdlg.removeEventListener('cancel', onCancel);
            if (fdlg.open) fdlg.close();
            if (opener && opener.isConnected && typeof opener.focus === 'function') opener.focus();
            resolve(val);
          }
          function onSubmit(e) { e.preventDefault(); var v = collect(); if (v !== null) done(v); }
          function onCancel(e) { if (e) e.preventDefault(); done(null); }
          form.addEventListener('submit', onSubmit);
          cancelBtn.addEventListener('click', onCancel);
          fdlg.addEventListener('cancel', onCancel);   // Esc / backdrop
          fdlg.showModal();
          var first = body.querySelector('input, select'); if (first) first.focus();
        });
      };
      // Copy text to the clipboard with a toast; falls back for old browsers.
      window.mvCopy = function (text) {
        function ok() { mvToast(productText('Copied to clipboard')); }
        function fail() { mvToast(productText('Copy failed — select and copy manually'), { error: true }); }
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(String(text)).then(ok, fail);
          return;
        }
        var ta, opener = document.activeElement;
        try {
          ta = document.createElement('textarea');
          ta.value = String(text); ta.style.position = 'fixed'; ta.style.opacity = '0';
          document.body.appendChild(ta); ta.select();
          if (document.execCommand('copy')) ok(); else fail();
        } catch (e) { fail(); }
        finally {
          if (ta) ta.remove();
          if (opener && opener.isConnected && typeof opener.focus === 'function') opener.focus();
        }
      };
      // Small DOM builder + a uniform timestamp formatter, shared by the
      // list-rendering pages (was reimplemented per page).
      window.mvEl = function (tag, cls, text) {
        var e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text != null) e.textContent = text;
        return e;
      };
      // The one empty state, same markup as templates/_empty_state.html:
      // "[What will appear here]. [How to add the first one]." plus at most
      // one next step — {label, href} for a link or {label, onClick} for a
      // button; leave it out when the viewer can't use the destination.
      // opts.compact: the smaller version for panels, tiles and charts.
      window.mvEmpty = function (title, body, action, opts) {
        var box = window.mvEl('div', 'mv-empty' + (opts && opts.compact ? ' mv-empty--compact' : ''));
        box.appendChild(window.mvEl('p', 'mv-empty__title', title));
        if (body) box.appendChild(window.mvEl('p', 'mv-empty__body', body));
        if (action && action.label && (action.href || action.onClick)) {
          var next = window.mvEl(action.href ? 'a' : 'button', 'btn mv-empty__action', action.label);
          if (action.href) next.setAttribute('href', action.href);
          else { next.type = 'button'; next.addEventListener('click', action.onClick); }
          box.appendChild(next);
        }
        return box;
      };
      // Only the business-error envelope carries trusted, authored display copy.
      // Legacy detail strings continue through the restrictive plain-copy filter.
      window.mvBusinessError = function (value) {
        var d = value && (value.detail || value);
        if (!d || d.schema !== 'lightwork.error.v1' || typeof d.code !== 'string' ||
            !/^[a-z][a-z0-9_.-]{0,79}$/.test(d.code) || typeof d.message !== 'string' ||
            !d.message.trim() || d.message.length > 1200 || /[\x00-\x1f]/.test(d.message)) return null;
        return d;
      };
      window.mvErrorResponse = async function (response) {
        var payload = {};
        try { payload = await response.clone().json(); } catch (_) {}
        return {status: response.status, detail: payload.detail};
      };
      window.mvRenderError = function (element, failure, action, payload) {
        var detail = window.mvBusinessError(payload || failure);
        var legacy = payload && window.mvPlainDetail(payload.detail);
        element.replaceChildren(document.createTextNode(detail ? detail.message :
          (legacy || window.mvErrorText(failure, action))));
        if (!detail) return;
        var fields = detail.field_errors;
        if (fields && typeof fields === 'object') Object.keys(fields).slice(0, 30).forEach(function (name) {
          if (!/^[A-Za-z][A-Za-z0-9_.-]{0,79}$/.test(name) || typeof fields[name] !== 'string' || fields[name].length > 400) return;
          var copy = document.createElement('span'); copy.className = 'business-field-error';
          copy.textContent = ' ' + fields[name]; element.appendChild(copy);
          var form = element.closest('form');
          if (form) Array.from(form.elements).forEach(function (input) {
            if (input.name === name) { input.setAttribute('aria-invalid', 'true');
              if (element.id) input.setAttribute('aria-describedby', element.id); }
          });
        });
        var next = detail.next_action;
        if (!next || typeof next.href !== 'string' || typeof next.label !== 'string' || next.label.length > 120) return;
        try {
          var decoded = decodeURIComponent(next.href), url = new URL(next.href, location.href);
          if (next.href[0] !== '/' || /^\/\//.test(decoded) || /[\\\x00-\x1f]/.test(decoded) || url.origin !== location.origin) return;
          var link = document.createElement('a'); link.href = url.pathname + url.search + url.hash;
          link.textContent = next.label; link.className = 'business-next-action';
          element.appendChild(document.createTextNode(' ')); element.appendChild(link);
        } catch (_) {}
      };
      // Plain-language error text for a failed request. Pass the fetch
      // Response (or a thrown error) and, optionally, what the person was
      // trying to do ("save the policy"). Never shows HTTP codes, exception
      // class names or server internals. One definition: the English sentence
      // comes from plainErrorText and a translated interface localizes it.
      function plainErrorText(failure, action) {
        var business = window.mvBusinessError(failure);
        if (business) return business.message;
        var what = action ? ('Could not ' + action + '. ') : '';
        var status = failure && typeof failure.status === 'number' ? failure.status : 0;
        if (!status) {
          var name = failure && failure.name;
          if (name === 'AbortError') return what + 'It took too long. Try again.';
          if (name === 'TypeError' || (failure && /fetch|network/i.test(String(failure.message || failure)))) {
            return what + 'Lightwork could not be reached. Check your connection and try again.';
          }
          return what + 'Something went wrong. Try again.';
        }
        if (status === 400 || status === 422) return what + 'Some of the details need fixing. Check what you entered and try again.';
        if (status === 401) return what + 'Your sign-in has expired. Sign in again to continue.';
        if (status === 403) {
          // Reason code from the server: a feature that is turned off is not a missing permission.
          var off = typeof window.mvFeatureOff === 'function' && window.mvFeatureOff(failure);
          if (off) return what + window.mvFeatureOffText(off);
          return what + 'You do not have permission to do this. Ask an administrator.';
        }
        if (status === 404) return what + 'That item no longer exists. Refresh the page to see the latest.';
        if (status === 409) {
          // A conflict can mean an existing item, missing setup, or a changed
          // version. Keep a safe server explanation when one was supplied.
          var explanation = typeof window.mvPlainDetail === 'function' &&
            window.mvPlainDetail(failure && failure.detail);
          return what + (explanation || 'This cannot be done right now. Review the item or its settings before trying again.');
        }
        if (status === 413) return what + 'That is too large. Try a smaller file or fewer items.';
        if (status === 429) return what + 'Too many requests right now. Wait a moment and try again.';
        if (status === 503) {
          // Only say "turned off" when the caller knows the server said so
          // (featureOff flag or its detail text); a plain 503 is temporary.
          var off = failure.featureOff === true ||
            /\b(turned off|is disabled|not enabled)\b/i.test(typeof failure.detail === 'string' ? failure.detail : '');
          return what + (off
            ? 'This feature is turned off. An administrator can turn it on in Settings.'
            : 'This is temporarily unavailable. Try again in a few minutes.');
        }
        if (status >= 500) return what + 'Something went wrong on our side. Try again in a minute.';
        return what + 'Something went wrong. Try again.';
      }
      window.mvErrorText = function (failure, action) {
        var value = plainErrorText(failure, action), locale = window.LightworkI18n;
        if (!locale || locale.language === 'en') return value;
        var prefix = action ? 'Could not ' + action + '. ' : '';
        var reason = prefix && value.startsWith(prefix) ? value.slice(prefix.length) : value;
        if (prefix && locale.has(reason)) return locale.text('This action could not be completed. {reason}', {reason: locale.text(reason)});
        return locale.text(value);
      };
      // A server message is shown only when it is already a plain sentence
      // written for people ("Pick a later date."). Codes, snake_case names,
      // paths, data and developer words return '' so the caller falls back
      // to mvErrorText.
      var JARGON = /\b(tenant|principal|payload|endpoint|schema|uuid|sha-?\d*|digest|idempotency|revision|lease|json|yaml|toml|http|https|api|config|configuration|token|traceback|exception|null|undefined|nan|maverick|sqlite|postgres|stdout|stderr|regex|cas|etag|manifest|runtime|webhook)\b/i;
      window.mvPlainDetail = function (detail) {
        if (typeof detail !== 'string') return '';
        var text = detail.trim();
        if (text.length < 8 || text.length > 300) return '';
        if (!/^[A-Z]/.test(text) || !/[.!?]$/.test(text)) return '';
        if (/[_{}<>\[\]`\\|=]|\/\w|\w\(|\b[a-z]+[A-Z]\w*\b|(?:^|[^\d,.])[45]\d\d(?![\d,])/.test(text)) return '';
        if (JARGON.test(text)) return '';
        return text;
      };
      // Show that error as a toast; returns the text for callers that also
      // write it into the page.
      window.mvFail = function (failure, action) {
        var text = window.mvErrorText(failure, action);
        mvToast(text, { error: true });
        return text;
      };
      // One JSON request: the page's cookies, JSON in and out, and a plain
      // sentence on failure. Resolves to the parsed body (null when empty).
      // Rejects with an Error whose message is mvErrorText(failure, action)
      // (or a business error's own message) and which keeps status, detail,
      // payload and headers, so mvFeatureOff(error) and
      // mvRenderError(el, error, action, error.payload) still work.
      //   const data = await mvFetchJSON('/api/v1/x', {method: 'POST', body: {...}}, 'save the policy');
      // Options beyond fetch's own:
      //   timeout: ms   give up (AbortError, error.timedOut) after this long;
      //                 a page's own signal still cancels it too.
      //   onAccess(error)  runs before the rejection when access is gone: a
      //                 401 or 403 (or accessStatuses), or a redirect to the
      //                 sign-in page; the page clears what it showed privately.
      //   plainDetail   use the server's explanation when it is a plain
      //                 sentence written for people (mvPlainDetail).
      //   raw           resolve to the response itself (a download), unread.
      //   messages      the page's own sentence for a status it knows more
      //                 about ({409: 'This changed since the list loaded…'},
      //                 timeout: for the deadline, offline: when the
      //                 server cannot be reached, or unreadable: for a reply
      //                 whose body cannot be read); every other failure gets
      //                 mvErrorText's words.
      //   serverDetail  the page's own fallback sentence. A refusal shows the
      //                 server's detail as written whenever it is a sentence
      //                 (a string), else the page's sentence for that status
      //                 (messages), else this one. For a lost access the
      //                 page's sentence for the status comes first.
      //   onContextChange(error)  runs before the rejection when a 409 says
      //                 the account or workspace changed (its detail matches
      //                 contextChange: a RegExp or a test function, by default
      //                 a detail starting "Your account or workspace changed.");
      //                 the page clears what it showed privately.
      var OWN_OPTIONS = ['timeout', 'onAccess', 'accessStatuses', 'plainDetail', 'raw', 'messages', 'serverDetail', 'onContextChange', 'contextChange'];
      var CONTEXT_CHANGED = /^Your account or workspace changed\./;
      function serverSentence(detail, opts) {
        return opts.serverDetail != null && typeof detail === 'string' && detail ? detail : '';
      }
      function contextChanged(detail, opts) {
        var test = opts.contextChange || CONTEXT_CHANGED;
        if (typeof detail !== 'string') return false;
        return typeof test === 'function' ? !!test(detail) : test.test(detail);
      }
      function fetchFailure(failure, action, opts) {
        var plain = opts.plainDetail && typeof window.mvPlainDetail === 'function' ? window.mvPlainDetail(failure.detail) : '';
        var own = opts.messages && Object.prototype.hasOwnProperty.call(opts.messages, failure.status) ? opts.messages[failure.status] : '';
        var fallback = opts.serverDetail != null ? String(opts.serverDetail) : '';
        var error = new Error(plain || serverSentence(failure.detail, opts) || own || fallback || window.mvErrorText(failure, action));
        error.status = failure.status; error.detail = failure.detail; error.headers = failure.headers; error.payload = failure.payload;
        return error;
      }
      // A body that is not read is released, so the request ends and the page
      // can go quiet.
      function release(response) {
        try { if (response.body && typeof response.body.cancel === 'function' && !response.bodyUsed) response.body.cancel().catch(function () {}); }
        catch (_) { /* already closed */ }
      }
      // The body as JSON; an empty body (No Content) is null.
      async function readJSON(response) {
        if (typeof response.text !== 'function') {
          try { return await response.json(); }
          catch (error) { if (response.status === 204) return null; throw error; }
        }
        var text = await response.text();
        if (text) return JSON.parse(text);
        // An empty body is null; a stand-in response may only answer json().
        try { return typeof response.json === 'function' ? await response.json() : null; } catch (_) { return null; }
      }
      // A plain object of the caller's headers: a Headers instance or a list
      // of [name, value] pairs has no own properties, so copying one as an
      // object would drop every header it carries.
      function plainHeaders(value) {
        var out = {};
        if (typeof Headers !== 'undefined' && value instanceof Headers) value.forEach(function (v, k) { out[k] = v; });
        else if (Array.isArray(value)) value.forEach(function (pair) { out[pair[0]] = pair[1]; });
        else Object.assign(out, value || {});
        return out;
      }
      function headerName(headers, name) {
        return Object.keys(headers).find(function (key) { return key.toLowerCase() === name.toLowerCase(); });
      }
      window.mvFetchJSON = async function (url, opts, action) {
        var own = opts || {};
        var options = Object.assign({ credentials: 'same-origin' }, own);
        OWN_OPTIONS.forEach(function (name) { delete options[name]; });
        var headers = plainHeaders(options.headers);
        if (!headerName(headers, 'Accept')) headers = Object.assign({ Accept: 'application/json' }, headers);
        var body = options.body;
        var typeName = headerName(headers, 'Content-Type');
        var declared = typeName && headers[typeName];
        var raw = body == null || typeof body === 'string' || (declared && !/json/i.test(declared)) || (typeof FormData !== 'undefined' && body instanceof FormData) ||
          (typeof Blob !== 'undefined' && body instanceof Blob) || (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) ||
          (typeof ArrayBuffer !== 'undefined' && body instanceof ArrayBuffer);
        if (!raw) {
          options.body = JSON.stringify(body);
          if (!typeName) headers['Content-Type'] = 'application/json';
        }
        options.headers = headers;
        var timer = null, timedOut = false, expired = null;
        if (own.timeout > 0) {
          var controller = new AbortController(), outer = own.signal;
          if (outer) {
            if (outer.aborted) controller.abort();
            else outer.addEventListener('abort', function () { controller.abort(); });
          }
          // The wait ends at the deadline even if the request ignores the abort.
          var expired = new Promise(function (_, reject) {
            timer = setTimeout(function () {
              timedOut = true; controller.abort();
              var late = new Error('The operation timed out.'); late.name = 'AbortError'; reject(late);
            }, own.timeout);
          });
          options.signal = controller.signal;
        }
        var response;
        try { response = await (expired ? Promise.race([fetch(url, options), expired]) : fetch(url, options)); }
        catch (cause) {
          clearTimeout(timer);
          var said = own.messages && (timedOut ? own.messages.timeout : own.messages.offline);
          var offline = new Error(said || window.mvErrorText(cause, action));
          // Same name as the cause (TypeError, AbortError), so passing this
          // error to mvErrorText or mvFieldErrors.fail gives the same words.
          offline.status = 0; offline.cause = cause; offline.name = (cause && cause.name) || 'Error';
          if (timedOut) offline.timedOut = true;
          throw offline;
        }
        var access = own.accessStatuses || [401, 403];
        var lost = typeof own.onAccess === 'function' && (access.indexOf(response.status) !== -1 || response.redirected === true);
        if (lost) {
          // The page clears what it showed privately before anything else,
          // and the refusal's body (often a sign-in page) is never read. A
          // redirect lands on the sign-in page: say so, as for a 401.
          clearTimeout(timer);
          var gone = fetchFailure({ status: response.ok ? 401 : response.status, headers: response.headers }, action, own);
          gone.status = response.status; gone.accessChanged = true;
          own.onAccess(gone);
          // A page that shows the server's own sentence reads the refusal's
          // detail only after it cleared, unless it has its own sentence for
          // this status; a redirect's sign-in page is never read.
          var named = own.messages && Object.prototype.hasOwnProperty.call(own.messages, response.status);
          if (own.serverDetail != null && !response.redirected && !response.ok && !named) {
            var refusal = null;
            try { refusal = await readJSON(response); } catch (_) { refusal = null; }
            var said = serverSentence(refusal && refusal.detail, own);
            if (said) { gone.message = said; gone.detail = said; }
          }
          release(response);
          throw gone;
        }
        if (own.raw && response.ok) { clearTimeout(timer); return response; }
        var payload = null, unreadable = false;
        try { payload = await readJSON(response); } catch (_) { payload = null; unreadable = true; }
        finally { clearTimeout(timer); }
        if (response.ok && !unreadable) return payload;
        if (!response.ok || unreadable) release(response);  // a refusal's or unreadable body is never left open
        var unread = unreadable && own.messages && own.messages.unreadable;
        if (response.ok || unread) {
          // Malformed success never counts as success, and is never shown.
          var bad = new Error(unread || window.mvErrorText({ name: 'SyntaxError' }, action));
          bad.status = response.ok ? 0 : response.status; bad.unreadable = true;
          throw bad;
        }
        var failure = fetchFailure({ status: response.status, detail: payload && payload.detail, headers: response.headers, payload: payload }, action, own);
        if (response.status === 409 && typeof own.onContextChange === 'function' && contextChanged(failure.detail, own)) {
          failure.contextChanged = true;
          own.onContextChange(failure);
        }
        throw failure;
      };
      // Two page-wide live regions (polite, and assertive for errors) that
      // exist before any message: base.html renders them, and a page without
      // them gets them made here, before the words are written into them. A region that appears, or gets its
      // role, in the same moment as its first words is often not read out,
      // so status lines speak through these instead of becoming regions
      // themselves. Each message clears both, then writes a moment later, so
      // a repeat of the same words is spoken again and only the latest of
      // quick messages is.
      var announceTimer = null;
      function announcer(id, live) {
        var region = document.getElementById(id);
        if (region || !document.body) return region;
        region = document.createElement('div');
        region.id = id; region.className = 'sr-only';
        region.setAttribute('role', live === 'assertive' ? 'alert' : 'status');
        region.setAttribute('aria-live', live);
        region.setAttribute('aria-atomic', 'true');
        document.body.appendChild(region);
        return region;
      }
      function announcers() {
        return { polite: announcer('mv-announce', 'polite'), alert: announcer('mv-announce-alert', 'assertive') };
      }
      window.mvAnnounce = function (text, opts) {
        var regions = announcers(), words = text == null ? '' : String(text);
        var target = opts && opts.error ? regions.alert : regions.polite;
        clearTimeout(announceTimer);
        if (regions.polite) regions.polite.textContent = '';
        if (regions.alert) regions.alert.textContent = '';
        if (!words || !target) return;
        announceTimer = setTimeout(function () { target.textContent = words; }, 100);
      };
      // One inline status line next to the control it reports on. Sets the
      // words at once (with the error style for an error) and, unless the
      // page made the element a live region itself, announces them through
      // mvAnnounce: politely, or at once for an error. Empty text clears it
      // and announces nothing.
      window.mvStatus = function (element, text, opts) {
        if (!element) return null;
        var error = !!(opts && opts.error);
        var words = text == null ? '' : String(text);
        var own = element.hasAttribute('aria-live') || (element.hasAttribute('role') && !element.hasAttribute('data-mv-status'));
        element.classList.toggle('mv-status--error', error);
        element.textContent = words;
        if (!own) {
          element.setAttribute('data-mv-status', '');
          if (words) window.mvAnnounce(words, { error: error });
        }
        return element;
      };
      // The one loading state for a region that is being filled. The region
      // is marked aria-busy at once, but the words appear only after `delay`
      // (300 ms), so a quick answer never flashes a loader; once shown they
      // stay at least `minVisible` (500 ms) so they can be read. A wait that
      // passes `timeout` (20 s) becomes the plain error, with Try again when
      // the caller passes `retry`. The page's own content is left in place.
      //   var wait = mvLoading(list, {text: 'Loading tasks…', action: 'load the tasks', retry: load});
      //   try { var rows = await mvFetchJSON(url); await wait.done(); render(rows); }
      //   catch (error) { wait.fail(error); }
      window.mvLoading = function (element, opts) {
        var o = opts || {}, shownAt = 0, settled = false, node = null;
        var delay = o.delay >= 0 ? o.delay : 300, minVisible = o.minVisible >= 0 ? o.minVisible : 500;
        if (element._mvLoading) element._mvLoading.cancel();
        var old = element.querySelector(':scope > [data-mv-loading-error]');
        if (old) old.remove();
        element.setAttribute('aria-busy', 'true');
        var showTimer = setTimeout(function () {
          node = window.mvEl('p', 'mv-loading', o.text || 'Loading…');
          node.setAttribute('data-mv-loading', '');
          element.appendChild(node); shownAt = Date.now();
        }, delay);
        var limit = setTimeout(function () {
          var late = new Error('The operation timed out.'); late.name = 'AbortError'; handle.fail(late);
        }, o.timeout > 0 ? o.timeout : 20000);
        function settle() {
          if (settled) return Promise.resolve(false);
          settled = true; clearTimeout(showTimer); clearTimeout(limit);
          if (element._mvLoading === handle) element._mvLoading = null;
          var left = node ? minVisible - (Date.now() - shownAt) : 0;
          function clear() { if (node) node.remove(); element.removeAttribute('aria-busy'); return true; }
          if (left <= 0) return Promise.resolve(clear());
          return new Promise(function (resolve) { setTimeout(function () { resolve(clear()); }, left); });
        }
        var handle = {
          active: function () { return !settled; },
          cancel: function () { settled = true; clearTimeout(showTimer); clearTimeout(limit); if (node) node.remove(); },
          done: function () { return settle().then(function () {}); },
          fail: function (failure) {
            return settle().then(function (mine) {
              if (!mine) return;
              var box = window.mvEl('p', 'mv-loading mv-loading--error');
              box.setAttribute('data-mv-loading-error', ''); box.setAttribute('role', 'alert');
              box.appendChild(document.createTextNode(window.mvErrorText(failure, o.action)));
              if (typeof o.retry === 'function') {
                var again = window.mvEl('button', 'btn btn--ghost', window.LightworkI18n ? window.LightworkI18n.text('Try again') : 'Try again');
                again.type = 'button';
                again.addEventListener('click', function () { box.remove(); o.retry(); });
                box.appendChild(document.createTextNode(' ')); box.appendChild(again);
              }
              element.appendChild(box);
            });
          },
        };
        element._mvLoading = handle;
        return handle;
      };
      // A stored value (status, kind, slug) as a readable label:
      // "pending_review" -> "Pending review", "ai_act" -> "AI Act".
      var WORDS = { ai: 'AI', api: 'API', id: 'ID', ids: 'IDs', url: 'URL', sso: 'SSO',
        dsar: 'DSAR', gdpr: 'GDPR', ccpa: 'CCPA', hipaa: 'HIPAA', soc2: 'SOC 2', pii: 'personal data',
        sla: 'SLA', mfa: 'MFA', eu: 'EU', us: 'US', uk: 'UK', llm: 'AI model', mcp: 'MCP',
        sha256: 'fingerprint', csv: 'CSV', pdf: 'PDF', iso: 'ISO', nist: 'NIST', dpia: 'DPIA',
        ropa: 'record of processing', cmp: 'consent banner', ok: 'OK' };
      window.mvHuman = function (value) {
        if (value === null || value === undefined) return '';
        var words = String(value).trim().replace(/[_-]+/g, ' ').split(/\s+/).filter(Boolean);
        if (!words.length) return '';
        var out = words.map(function (w) {
          var key = w.toLowerCase();
          return Object.prototype.hasOwnProperty.call(WORDS, key) ? WORDS[key] : key;
        }).join(' ');
        return out.charAt(0).toUpperCase() + out.slice(1);
      };
      window.mvWhen = function (ts) {
        // Return '' for missing/invalid timestamps rather than formatting the
        // Unix epoch: (ts || 0) would turn 0/null/undefined/NaN into 1/1/1970,
        // which then leaks into visible text and aria-labels.
        if (!ts || !isFinite(ts)) return '';
        return window.mvTimeAbsolute(ts);
      };
      // One shared time formatter for every timestamp people read. Servers
      // send an epoch (seconds) or an ISO string; the viewer sees it in their
      // own time zone. Convention (any page, any markup owner):
      //   <time data-mv-time="1790790000">fallback</time>
      //   data-mv-time-mode="relative" (default: "2 minutes ago", absolute on
      //   hover) | "absolute" ("30 Sep 2026, 17:15 BST") | "both" | "date"
      //   ("30 Sep 2026"; a "2026-09-30" value is a calendar date, not UTC midnight).
      // Elements added later are formatted by calling window.mvFormatTimes(root).
      // Each reader sees one style, their browser's regional setting: an en-US
      // browser reads "Oct 4, 2026, 2:01 PM EDT", an en-GB one "4 Oct 2026,
      // 19:01 BST"; a translated interface uses its own locale. The same
      // choice is made in lightwork-i18n.js (formatDate), so both agree.
      function mvBrowserLocale() {
        var wanted = [].concat(navigator.languages || [], navigator.language || []);
        for (var i = 0; i < wanted.length; i++) {
          try { if (wanted[i] && Intl.DateTimeFormat.supportedLocalesOf([wanted[i]]).length) return wanted[i]; } catch (e) {}
        }
        return 'en-GB';
      }
      function mvFormatLocale() {
        var i18n = window.LightworkI18n;
        return i18n && i18n.language && i18n.language !== 'en' ? (i18n.locale || i18n.language) : mvBrowserLocale();
      }
      // Phrases ("2 minutes ago") are words, so they stay in the interface
      // language even when the browser's regional style is another language.
      function mvPhraseLocale() {
        var locale = mvFormatLocale();
        return /^en\b/i.test(locale) || (window.LightworkI18n && window.LightworkI18n.language && window.LightworkI18n.language !== 'en') ? locale : 'en';
      }
      function mvParseTime(raw) {
        if (raw === null || raw === undefined || raw === '') return null;
        var n = Number(raw);
        var d = isFinite(n) ? new Date((n > 1e12 ? n : n * 1000)) : new Date(String(raw));
        return isNaN(d.getTime()) || d.getTime() <= 0 ? null : d;
      }
      // An optional IANA zone shows the time in that zone instead (a schedule's own
      // zone); the zone name is part of the text either way.
      window.mvTimeAbsolute = function (raw, zone) {
        var d = mvParseTime(raw);
        if (!d) return '';
        var options = { day: 'numeric', month: 'short', year: 'numeric', hour: 'numeric', minute: '2-digit', timeZoneName: 'short' };
        if (zone) options.timeZone = zone;
        try { return new Intl.DateTimeFormat(mvFormatLocale(), options).format(d); }
        catch (e) { return zone ? window.mvTimeAbsolute(raw) : d.toUTCString(); }
      };
      // A calendar day ("2026-10-04" or a moment) reads "4 Oct 2026"; an
      // accounting month ("2026-09") reads "September 2026".
      window.mvDateAbsolute = function (raw) {
        var parts = typeof raw === 'string' && /^(\d{4})-(\d{2})(?:-(\d{2}))?$/.exec(raw.trim());
        var d = parts ? new Date(Number(parts[1]), Number(parts[2]) - 1, Number(parts[3] || 1)) : mvParseTime(raw);
        if (!d || isNaN(d.getTime())) return '';
        try {
          return new Intl.DateTimeFormat(mvFormatLocale(), parts && !parts[3] ? { month: 'long', year: 'numeric' }
            : { day: 'numeric', month: 'short', year: 'numeric' }).format(d);
        } catch (e) { return d.toDateString(); }
      };
      // Money reads "$1,234.56" everywhere (the |money filter matches it):
      // two decimals with thousands separators, and a non-zero amount under a
      // cent reads "under $0.01". { decimals: 4 } is only for a labelled
      // per-unit price ("$0.0030 per 1K tokens"); { currency: 'EUR' } shows the
      // code ("EUR 75.00"). A missing or unreadable amount returns '' so the
      // caller can say why it is unknown instead of showing $0.00.
      window.mvMoney = function (value, options) {
        if (value === null || value === undefined || value === '' || typeof value === 'boolean') return '';
        var amount = Number(value);
        if (!isFinite(amount)) return '';
        var decimals = options && typeof options.decimals === 'number' ? options.decimals : 2;
        var currency = String((options && options.currency) || 'USD').toUpperCase();
        var i18n = window.LightworkI18n;
        var locale = i18n && i18n.language && i18n.language !== 'en' ? (i18n.locale || i18n.language) : 'en-US';
        function format(n) {
          try {
            return new Intl.NumberFormat(locale, { style: 'currency', currency: currency,
              currencyDisplay: currency === 'USD' ? 'symbol' : 'code',
              minimumFractionDigits: decimals, maximumFractionDigits: decimals }).format(n);
          } catch (e) { return (n < 0 ? '-' : '') + (currency === 'USD' ? '$' : currency + ' ') + Math.abs(n).toFixed(decimals); }
        }
        var smallest = Math.pow(10, -decimals);
        if (amount !== 0 && Math.abs(amount) < smallest / 2) return 'under ' + format(smallest);
        return format(amount || 0);
      };
      window.mvTimeRelative = function (raw) {
        var d = mvParseTime(raw);
        if (!d) return '';
        var diff = (d.getTime() - Date.now()) / 1000;
        var abs = Math.abs(diff), past = diff <= 0;
        // [seconds in one unit, unit, size of the next unit]. Each value is
        // counted in its own unit; one that rounds up to the next unit
        // ("60 minutes") is shown in that unit instead ("1 hour").
        var units = [[1, 'second', 60], [60, 'minute', 3600], [3600, 'hour', 86400], [86400, 'day', 604800],
          [604800, 'week', 2629800], [2629800, 'month', 31557600], [31557600, 'year', Infinity]];
        if (abs < 45) return past ? 'just now' : 'in a moment';
        var i = 0;
        while (Math.round(abs / units[i][0]) * units[i][0] >= units[i][2]) i++;
        var size = units[i][0], unit = units[i][1], value = Math.round(abs / size);
        if (typeof Intl !== 'undefined' && Intl.RelativeTimeFormat) {
          try { return new Intl.RelativeTimeFormat(mvPhraseLocale(), { numeric: 'auto' }).format(past ? -value : value, unit); } catch (e) {}
        }
        var word = value + ' ' + unit + (value === 1 ? '' : 's');
        return past ? word + ' ago' : 'in ' + word;
      };
      window.mvFormatTimes = function (root) {
        var scope = root && root.querySelectorAll ? root : document;
        Array.prototype.forEach.call(scope.querySelectorAll('[data-mv-time]'), function (el) {
          var raw = el.getAttribute('data-mv-time');
          var d = mvParseTime(raw);
          if (!d) return;
          var mode = el.getAttribute('data-mv-time-mode') || 'relative';
          var absolute = window.mvTimeAbsolute(raw);
          var relative = window.mvTimeRelative(raw);
          if (el.tagName === 'TIME' && !el.getAttribute('datetime')) el.setAttribute('dateTime', d.toISOString());
          if (mode === 'date') el.textContent = window.mvDateAbsolute(raw);
          else if (mode === 'absolute') { el.textContent = absolute; el.title = relative; }
          else if (mode === 'both') { el.textContent = absolute + ' (' + relative + ')'; }
          else { el.textContent = relative; el.title = absolute; }
          el.setAttribute('data-mv-time-done', mode);
        });
      };
      // The page's own timestamps, flash notices and reset times are formatted
      // once the full document is available (scripted harnesses stub it).
      var realDocument = typeof document.querySelectorAll === 'function' && typeof document.querySelector === 'function';
      if (realDocument) window.mvFormatTimes(document);
      // Relative labels drift; refresh them once a minute. Only when the page
      // has any: an idle timer would keep a scripted runtime from exiting.
      if (realDocument && document.querySelector('[data-mv-time]')) {
        setInterval(function () {
          Array.prototype.forEach.call(document.querySelectorAll('[data-mv-time-done="relative"]'), function (el) {
            el.textContent = window.mvTimeRelative(el.getAttribute('data-mv-time'));
          });
        }, 60000);
      }
      // "Resets at midnight UTC" is only meaningful next to the viewer's own
      // clock: <span data-mv-utc-midnight></span> becomes ", which is 01:00 for you".
      Array.prototype.forEach.call(realDocument ? document.querySelectorAll('[data-mv-utc-midnight]') : [], function (el) {
        try {
          var next = new Date(); next.setUTCHours(24, 0, 0, 0);
          var local = next.toLocaleTimeString(mvFormatLocale(), { hour: 'numeric', minute: '2-digit' });
          var zone = (Intl.DateTimeFormat().resolvedOptions().timeZone || '').replace(/_/g, ' ');
          if (next.getTimezoneOffset() !== 0) el.textContent = ', which is ' + local + ' in your time zone' + (zone ? ' (' + zone + ')' : '');
        } catch (e) {}
      });
      // A server-rendered "Saved." notice after a redirect also announces as a
      // toast, so feedback lands where the person is looking, not above the
      // fold. <div data-mv-toast="Workspace limit saved." ...>.
      // A page that reloads right after a change hands its toast to the next load.
      var FLASH = 'lightwork.flash-toast';
      window.mvToastAfterReload = function (message) {
        try { sessionStorage.setItem(FLASH, String(message)); } catch (e) { window.mvToast(message); }
      };
      function showInitialToasts() {
        Array.prototype.forEach.call(realDocument ? document.querySelectorAll('[data-mv-toast]') : [], function (el) {
          var text = el.getAttribute('data-mv-toast');
          if (text) window.mvToast(text, { error: el.getAttribute('data-mv-toast-error') === 'true' });
        });
        try {
          var flashed = sessionStorage.getItem(FLASH);
          if (flashed) { sessionStorage.removeItem(FLASH); window.mvToast(flashed); }
        } catch (e) {}
      }
      // Navigation and submit protection initialize before localization downloads;
      // initial announcements wait for their language helpers or honest fallback.
      if (document.readyState === 'loading' && !window.LightworkI18n) {
        document.addEventListener('DOMContentLoaded', showInitialToasts, {once: true});
      } else showInitialToasts();
    })();

    // Halt indicator + arm/clear via /api/v1/halt.
    (function() {
      const pill = document.getElementById('halt-pill');
      const label = document.getElementById('halt-label');
      if (!pill || !label) {
        // Shells without the pill (the chat shell) still show the stop banner,
        // read from the same status document and only when it verifies.
        const soloBanner = document.getElementById('halt-banner');
        if (!soloBanner) return;
        async function readSolo() {
          try {
            const r = await fetch('/api/v1/halt', { cache: 'no-store' });
            if (!r.ok) throw new Error('halt status ' + r.status);
            const body = await r.json();
            const armed = !!(body && body.active === true && (body.scope !== 'cluster' || body.cluster_halt === true));
            soloBanner.hidden = !armed;
            document.body.classList.toggle('halt-armed', armed);
          } catch (e) { soloBanner.hidden = true; }
        }
        readSolo();
        setInterval(readSolo, 15000);
        return;
      }
      const canHalt = pill.dataset.canHalt === 'true';
      function productText(source) { return window.LightworkI18n ? window.LightworkI18n.text(source) : source; }
      const configuredTimeout = Number(pill.dataset.haltTimeoutMs);
      const haltTimeoutMs = Number.isFinite(configuredTimeout) && configuredTimeout > 0
        ? Math.min(configuredTimeout, 10000)
        : 10000;
      // A failed read is not equivalent to a cleared stop.  Keep an explicit
      // unknown state so the shell can never invite a mutation based on a
      // fabricated answer.
      let haltState = 'unknown';
      // The shell learns its configured scope from the first complete status
      // response and then requires every later read to agree.  A scope change
      // needs a page reload; silently switching authorities in a live tab would
      // make the same control mean two different things.
      let haltScope = null;
      let pending = false;
      // Every status read owns a generation.  A later-started poll or the
      // post-mutation verification supersedes every older in-flight read, so a
      // slow interval request cannot repaint stale state over newer evidence.
      let refreshGeneration = 0;
      function knownState() {
        return haltState === 'armed' || haltState === 'clear';
      }
      // The red banner every page shows while work is stopped. The pill alone
      // is easy to miss; the banner names the state and offers the resume
      // action to people allowed to take it.
      const banner = document.getElementById('halt-banner');
      const chatControls = typeof document.querySelector === 'function'
        ? document.querySelector('form.composer[action="/chat/send"] fieldset.composer__controls')
        : null;
      const chatControlsInitiallyDisabled = !!(chatControls && chatControls.disabled);
      const chatStopNote = document.getElementById('chat-stop-note');
      let chatStopped = false;
      function renderChatStop(state) {
        if (state === 'armed' || state === 'partial') chatStopped = true;
        else if (state === 'clear') chatStopped = false;
        if (chatControls) chatControls.disabled = chatControlsInitiallyDisabled || chatStopped;
        if (chatStopNote) chatStopNote.hidden = !chatStopped;
      }
      function renderBanner(show) {
        if (!banner) return;
        banner.hidden = !show;
        document.body.classList.toggle('halt-armed', !!show);
        const resume = banner.querySelector('[data-halt-resume]');
        if (resume) resume.hidden = !canHalt;
      }
      if (banner) {
        const resume = banner.querySelector('[data-halt-resume]');
        if (resume) resume.addEventListener('click', function (ev) { ev.preventDefault(); pill.click(); });
      }
      function render(state, detail) {
        haltState = state;
        const armed = state === 'armed';
        const known = state === 'armed' || state === 'clear';
        pill.classList.toggle('armed', armed);
        pill.classList.toggle('unavailable', !known);
        const copy = detail || (armed
          ? (canHalt ? 'STOPPED — click to resume' : 'STOPPED')
          : state === 'clear'
            ? 'Emergency stop'
            : 'Stop status unavailable');
        // A late catalog translates the current verified state, never an older
        // pending label. Authority checks and status reads stay immediate.
        // The words are rewritten only when they change: the 15-second poll
        // must not repeat the same announcement from the live label.
        if (label.dataset.i18n !== copy) {
          label.dataset.i18n = copy;
          if (window.LightworkI18n) window.LightworkI18n.set(label, copy);
          else { label.textContent = copy; label.lang = 'en'; label.dir = 'ltr'; }
        }
        renderBanner(armed && !pending);
        renderChatStop(state);
        if (canHalt) {
          pill.setAttribute('aria-pressed', known ? (armed ? 'true' : 'false') : 'mixed');
        } else {
          pill.removeAttribute('aria-pressed');
        }
        pill.setAttribute('aria-disabled', (!canHalt || !known || pending) ? 'true' : 'false');
      }
      function renderVerifiedPayload(payload) {
        if (!payload || typeof payload.active !== 'boolean' ||
            (payload.scope !== 'local' && payload.scope !== 'cluster') ||
            (payload.scope === 'cluster' && typeof payload.cluster_halt !== 'boolean')) {
          render('unknown');
          return false;
        }
        if (haltScope === null) haltScope = payload.scope;
        if (payload.scope !== haltScope) {
          render('unknown', 'Stop settings changed — reload to verify status');
          return false;
        }
        if (haltScope === 'cluster' && payload.active !== payload.cluster_halt) {
          // `active` includes the local file while `cluster_halt` is the shared
          // authority.  Disagreement is a partial/unverified stop, not proof
          // that the configured cluster scope is stopped or clear.
          render('partial', 'Partial stop — some workers are not confirmed stopped');
          return false;
        }
        render(payload.active ? 'armed' : 'clear');
        return true;
      }
      async function requestHalt(options, readBody) {
        const controller = typeof AbortController === 'function'
          ? new AbortController()
          : null;
        const requestOptions = Object.assign({cache: 'no-store'}, options || {});
        if (controller) requestOptions.signal = controller.signal;
        let timer;
        const timeout = new Promise(function(_resolve, reject) {
          timer = setTimeout(function() {
            if (controller) controller.abort();
            reject(new Error('halt request timed out'));
          }, haltTimeoutMs);
        });
        const request = (async function() {
          const response = await fetch('/api/v1/halt', requestOptions);
          const body = readBody ? await readBody(response) : undefined;
          return {response: response, body: body};
        })();
        try {
          return await Promise.race([request, timeout]);
        } finally {
          clearTimeout(timer);
        }
      }
      render('unknown', 'Checking stop status…');
      async function refresh() {
        if (pending) return false;
        const generation = ++refreshGeneration;
        try {
          const result = await requestHalt({}, function(response) {
            return response.json();
          });
          if (generation !== refreshGeneration) return false;
          const r = result.response;
          if (!r.ok) throw new Error('halt status ' + r.status);
          return renderVerifiedPayload(result.body);
        } catch (e) {
          if (generation !== refreshGeneration) return false;
          // A stale known state is unsafe after any failed, non-OK, timed-out,
          // or invalid read.  Only a complete current response may re-enable
          // the mutation control.
          render('unknown');
          return false;
        }
      }
      pill.addEventListener('click', async function(ev) {
        ev.preventDefault();
        if (!canHalt) {
          mvToast(productText('You do not have permission to stop or resume this work.'), { error: true });
          return;
        }
        if (pending || !knownState()) {
          mvToast(productText('Emergency stop status is unavailable. Retry after the dashboard can verify it.'), { error: true });
          return;
        }
        const wasArmed = haltState === 'armed';
        let responseCompleted = false;
        try {
          let requestOptions;
          if (wasArmed) {
            pending = true;
            refreshGeneration += 1;
            render(haltState, 'Resuming…');
            requestOptions = {method: 'DELETE'};
          } else {
            const consequence = haltScope === 'cluster'
              ? 'Stop work across connected workers? Work covered by this emergency stop pauses at its next step and waits for an authorized resume.'
              : 'Stop work on this server? Work covered by this emergency stop pauses at its next step and waits for an authorized resume.';
            if (!(await mvConfirm(consequence, { productCopy: true, okText: 'Stop work' }))) return;
            pending = true;
            refreshGeneration += 1;
            render(haltState, 'Stopping…');
            requestOptions = {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({reason: 'manual via dashboard'}),
            };
          }
          const result = await requestHalt(requestOptions, async function(response) {
            if (response.ok) return null;
            try { return await response.json(); } catch (parseError) { return null; }
          });
          responseCompleted = true;
          const response = result.response;
          if (!response.ok) {
            // A failed arm may still have stopped this replica, and a failed
            // clear may still have changed one backend.  Do not display the
            // pre-request state as verified until a fresh read succeeds.
            render('unknown');
            mvToast(typeof mvErrorText === 'function'
              ? mvErrorText(response, 'change the emergency stop')
              : productText('Emergency stop change failed. Try again.'), { error: true });
          } else {
            // A 204 only acknowledges the mutation request.  It is not a
            // status document and cannot prove either local or cluster state.
            render('unknown', wasArmed
              ? 'Resume requested — checking work status…'
              : 'Stop requested — checking work status…');
          }
        } catch (e) {
          render('unknown');
          mvToast(productText('Emergency stop change failed. Lightwork is not responding. Check your connection and try again.'), { error: true });
        } finally {
          pending = false;
        }
        // A transport timeout has an ambiguous server outcome.  Do not let an
        // immediate read certify the old pre-request state; a later independent
        // poll must establish current truth after the request has settled.
        if (!responseCompleted) return;
        const verified = await refresh();
        // `refresh` renders every verified, partial, or unavailable outcome;
        // retaining its detail keeps scope disagreement distinguishable from
        // an ordinary transport outage.
        if (!verified) return;
      });
      pill.addEventListener('keydown', function(ev) {
        // role="button" must activate on Space; the native <a href>
        // already handles Enter. Stop Space from scrolling the page.
        if (canHalt && (ev.key === ' ' || ev.key === 'Spacebar')) {
          ev.preventDefault();
          pill.click();
        }
      });
      // The label turns into a polite live region only once the first read
      // has settled and the page has finished loading (the localization pass
      // rewrites the label at DOMContentLoaded): loading a page must not
      // announce "Emergency stop", while a later stop, resume or lost status
      // is still announced.
      const loaded = document.readyState === 'complete' ? Promise.resolve()
        : new Promise(function (resolve) { window.addEventListener('load', resolve, {once: true}); });
      Promise.all([refresh(), loaded]).then(function () { label.setAttribute('aria-live', 'polite'); });
      setInterval(refresh, 15000);
    })();

    // Shared goal-create form handler. The form appears on both the
    // overview (first run) and chat pages; submit via fetch so a
    // 400/403/429 shows the server message inline instead of a raw JSON
    // page. No-ops on pages without the form + its error region.
    (function() {
      const form = document.querySelector('form[action="/chat/send"]');
      const errBox = document.getElementById('goal-error');
      if (!form || !errBox) return;
      const btn = form.querySelector('button[type="submit"]');
      let authoringPending = false, startPending = false, unlockStart = null;
      // Back from the task page (a restored page): the form works again.
      window.addEventListener('pageshow', function (event) {
        if (event.persisted && unlockStart) unlockStart();
      });
      form.addEventListener('submit', async function(ev) {
        ev.preventDefault();
        // One submit makes one task: a second click or Enter while the first
        // is on its way is ignored, not sent again.
        if (authoringPending || startPending) return;
        errBox.style.display = 'none';
        const kindEl = form.querySelector('[name="authoring_kind"]');
        const kind = kindEl ? kindEl.value : 'goal';
        const accountSelection=(form.querySelector('[name="connection_references"]')||{}).value||'[]';
        if(kind!=='goal'&&accountSelection!=='[]'){
          var accountNotice='This draft has selected accounts. Run it as a task, or return to Templates to prepare a new reusable draft without private account selections.';
          if(window.LightworkI18n)window.LightworkI18n.set(errBox,accountNotice);else errBox.textContent=accountNotice;
          errBox.style.display='block';return;
        }

        const files = form.querySelector('input[type="file"]');
        // Stage an unsaved brief in the selected editor; never silently execute
        // a goal when the selected authoring action cannot accept attachments.
        if ((kind === 'flow' || kind === 'agent') && files && files.files.length) {
          errBox.textContent = 'Workflow and agent drafts do not accept attachments yet. Remove the files to open the editor, or choose Start a task to use them. Your text and files are still here.';
          errBox.style.display = 'block';
          return;
        }
        if ((kind === 'flow' || kind === 'agent') && !(files && files.files.length)) {
          const title = (form.querySelector('[name="title"]') || {}).value || '';
          const details = (form.querySelector('[name="description"]') || {}).value || '';
          const brief = title.trim() + (details.trim() ? '\n\n' + details : '');
          if (!brief) {
            errBox.textContent = 'Describe what you want Lightwork to draft.';
            errBox.style.display = 'block';
            return;
          }
          if (Array.from(brief).length > 8000) {
            errBox.textContent = 'Workflow briefs can contain up to 8,000 characters. Shorten the brief and try again; your text is still here.';
            errBox.style.display = 'block';
            return;
          }
          authoringPending = true;
          if (btn) { btn.disabled = true; btn.setAttribute('aria-busy', 'true'); }
          try {
            const contextResponse = await fetch('/api/v1/templates/draft-context', {credentials: 'same-origin', cache: 'no-store'});
            if (!contextResponse.ok) throw new Error('Could not verify your workspace. Your brief is still here; try again.');
            const contextData = await contextResponse.json();
            if (!contextData || typeof contextData.context !== 'string' || !contextData.context) {
              throw new Error('Could not verify your workspace. Your brief is still here; try again.');
            }
            if (title !== ((form.querySelector('[name="title"]') || {}).value || '') ||
                details !== ((form.querySelector('[name="description"]') || {}).value || '') ||
                kind !== (kindEl ? kindEl.value : 'goal') || (files && files.files.length)) {
              throw new Error('Your brief changed while the editor was opening. Review it and continue again.');
            }
            sessionStorage.setItem('lightwork.authoring-handoff', JSON.stringify({
              kind: kind, brief: brief, context: contextData.context, created_at: Date.now()
            }));
            window.location.href = kind === 'flow' ? '/flows/designer' : '/workflow-builder';
          } catch (e) {
            errBox.textContent = e.message || 'Could not open the editor. Your brief is still here; try again.';
            errBox.style.display = 'block';
          } finally {
            authoringPending = false;
            if (btn) { btn.disabled = false; btn.removeAttribute('aria-busy'); }
          }
          return;
        }
        if ((form.querySelector('[name="composer_mode"]') || {}).value === 'message') {
          const message = (form.querySelector('[name="title"]') || {}).value || '';
          const details = (form.querySelector('[name="description"]') || {}).value || '';
          const brief = message + (details.trim() ? '\n\n' + details : '');
          if (Array.from(brief).length > 16000) {
            errBox.textContent = 'Shorten your message and details to 16,000 characters or fewer. Your text is still here.';
            errBox.style.display = 'block';
            return;
          }
        }
        // Disabling the form below moves focus to the page body. A refused
        // send puts it back where the person was typing (WCAG 2.4.3).
        const typing = form.contains(document.activeElement) ? document.activeElement : form.querySelector('[name="title"]');
        if (btn) { btn.disabled = true; btn.setAttribute('aria-busy', 'true'); }
        startPending = true;
        const submittedForm = new FormData(form);
        const submittedControls = Array.from(form.querySelectorAll('input,textarea,select')).map(function (control) {
          const wasDisabled = control.disabled; control.disabled = true; return [control,wasDisabled];
        });
        unlockStart = function () {
          unlockStart = null; startPending = false;
          submittedControls.forEach(function (item) { item[0].disabled = item[1]; });
          if (btn) { btn.disabled = false; btn.removeAttribute('aria-busy'); }
        };
        try {
          const resp = await fetch(form.action, { method: 'POST', body: submittedForm });
          // The server answers a started task with a redirect to its page. If
          // that page was still being set up (a retryable 409 or 503), the
          // task did start: open it, never "Could not start" and a second try.
          if (resp.redirected && new URL(resp.url).pathname.startsWith('/chat/goal/') &&
              (resp.ok || resp.status === 409 || resp.status === 503)) {
            if (form.mvRecovery) await form.mvRecovery.clear();
            window.dispatchEvent(new CustomEvent('lightwork:composer-sent', {detail: {form: form, recoveryCleared: true}}));
            startPending = 'opening'; window.location.href = resp.url; return;
          }
          if (resp.ok && !resp.redirected) {
            if (form.mvRecovery) await form.mvRecovery.clear();
            window.dispatchEvent(new CustomEvent('lightwork:composer-sent', {detail: {form: form, recoveryCleared: true}}));
            window.location.reload(); return;
          }
          let serverDetail = '';
          try { const j = await resp.json(); if (j && typeof j.detail === 'string') serverDetail = j.detail; } catch (e) {}
          let detail = window.mvErrorText(resp, 'start the task');
          if (resp.status === 429) {
            const ra = parseInt(resp.headers.get('Retry-After') || '', 10);
            detail = 'Too many requests right now. ' + (ra > 0
              ? 'Try again in ' + ra + (ra === 1 ? ' second.' : ' seconds.')
              : 'Wait a moment and try again.');
          } else if (resp.status === 400 && /model route/i.test(serverDetail)) {
            detail = 'Could not start the task. An AI model needs to be set up first. Ask an administrator to finish setup in Settings.';
          } else if ((resp.status === 400 || resp.status === 422) && window.mvPlainDetail(serverDetail)) {
            // Messages such as length limits are written for people.
            detail = window.mvPlainDetail(serverDetail);
          }
          errBox.textContent = detail;
          if (resp.status === 400 && resp.headers.get('X-Lightwork-Task-Settings') === 'agent.max_steps') {
            const settingsLink = document.createElement('a');
            settingsLink.href = '/settings/all?id=agent.max_steps';
            settingsLink.className = 'btn btn--ghost';
            if (window.LightworkI18n) window.LightworkI18n.set(settingsLink, 'Review task settings');
            else settingsLink.textContent = 'Review task settings';
            errBox.append(document.createTextNode(' '), settingsLink);
          }
          errBox.style.display = 'block';
        } catch (e) {
          errBox.textContent = 'Lightwork is not responding. Check your connection and try again.';
          errBox.style.display = 'block';
        } finally {
          // While the task page opens, the form stays locked.
          if (startPending !== 'opening' && unlockStart) {
            unlockStart();
            const lost = !document.activeElement || document.activeElement === document.body;
            if (lost && typing && typing.isConnected && !typing.disabled && typeof typing.focus === 'function') typing.focus();
          }
        }
      });
    })();

    // A form that posts and reloads the page (<form data-mv-save>) says
    // "Saving…" the moment it is sent, so a slow server never looks like a
    // missed click. The page that loads next shows what happened.
    (function () {
      function say(status, text) {
        if (window.LightworkI18n && text) window.LightworkI18n.set(status, text); else status.textContent = text;
      }
      function clear(form, button) {
        var status = form.querySelector('[data-mv-save-status]');
        if (status) say(status, '');
        if (button) button.removeAttribute('aria-busy');
      }
      document.addEventListener('submit', function (event) {
        var form = event.target;
        if (!(form instanceof HTMLFormElement) || !form.hasAttribute('data-mv-save') || event.defaultPrevented) return;
        var button = event.submitter || null, status = form.querySelector('[data-mv-save-status]');
        // A button that only reads (formmethod="get", e.g. Preview) saves nothing.
        if (button && (button.getAttribute('formmethod') || '').toLowerCase() === 'get') return;
        if (!status) {
          status = document.createElement('span');
          status.className = 'muted';
          status.setAttribute('role', 'status');
          status.setAttribute('data-mv-save-status', '');
          form.appendChild(status);
        }
        if (form.getAttribute('data-mv-save') === 'background' && typeof window.fetch === 'function') {
          event.preventDefault();
          if (form._mvSaving) return;   // one save at a time; the first is still on its way
          say(status, 'Saving…');
          if (button) button.setAttribute('aria-busy', 'true');
          form._mvSaveButton = button;
          send(form, button, status);
          return;
        }
        say(status, 'Saving…');
        if (button) button.setAttribute('aria-busy', 'true');
        form._mvSaveButton = button;
        // A script that stops the submission after this point must not leave "Saving…".
        setTimeout(function () { if (event.defaultPrevented) clear(form, button); }, 0);
      });
      window.addEventListener('pageshow', function (event) {
        if (!event.persisted) return;
        Array.prototype.forEach.call(document.querySelectorAll('form[data-mv-save]'), function (form) {
          clear(form, form._mvSaveButton);
        });
      });

      // <form data-mv-save="background"> saves without leaving the page until
      // the save is done, so nothing typed is lost when it fails. The same
      // request as the plain form (same address, same fields, same-origin
      // cookies), asking for a plain JSON error instead of an error page:
      //   saved, with a next page  -> that page (it says "Saved.")
      //   saved, with a result     -> data-mv-save-show="id": the element with
      //                               that id is replaced by the answer's copy
      //   needs a fresh sign-in    -> the sign-in, which comes back to this page
      //                               (data-mv-keep restores what was typed)
      //   anything else            -> the form's error summary (mvFieldErrors),
      //                               every value kept; offline and an expired
      //                               sign-in say so in plain words
      // data-mv-save-what="save the limit" words the failure.
      var hooks = window.mvBackgroundSave = {navigate: function (url) { window.location.assign(url); }};
      function returnHere(link) {
        try {
          var url = new URL(link, window.location.href);
          if (url.origin !== window.location.origin) return null;
          if (url.searchParams.has('return_to')) url.searchParams.set('return_to', window.location.pathname + window.location.search);
          return url.pathname + url.search;
        } catch (_) { return null; }
      }
      function failed(form, button, status, failure, payload) {
        form._mvSaving = false;
        clear(form, button);
        var what = form.getAttribute('data-mv-save-what') || 'save this';
        var fields = window.mvFieldErrors, business = payload && window.mvBusinessError ? window.mvBusinessError(payload) : null;
        if (fields && business && business.field_errors) {
          var errors = Object.keys(business.field_errors).filter(function (name) { return form.elements[name]; })
            .map(function (name) { return {field: name, message: business.field_errors[name]}; });
          var kept = window.LightworkI18n ? window.LightworkI18n.text('What you entered is still here.') : 'What you entered is still here.';
          fields.show(form, errors, {message: errors.length ? '' : business.message + ' ' + kept});
        } else if (fields) {
          fields.fail(form, failure, what);
        } else if (window.mvFail) {
          window.mvFail(failure, what);
        }
      }
      function showResult(form, id, html) {
        var fresh = new DOMParser().parseFromString(html, 'text/html').getElementById(id);
        var here = document.getElementById(id);
        if (!fresh || !here) return false;
        var copy = document.importNode(fresh, true);
        here.replaceWith(copy);
        if (window.mvFormatTimes) window.mvFormatTimes(copy);
        var landing = copy.querySelector('[tabindex="-1"]') || copy;
        if (landing.focus) landing.focus();
        return true;
      }
      async function send(form, button, status) {
        form._mvSaving = true;
        var action = button && button.hasAttribute('formaction') ? button.formAction : form.action;
        var data = new FormData(form);
        if (button && button.name) data.append(button.name, button.value);
        var response, payload = null;
        try {
          response = await window.fetch(action, {method: 'POST', body: new URLSearchParams(data),
            credentials: 'same-origin', headers: {Accept: 'application/json'}});
        } catch (error) {
          return failed(form, button, status, error, null);
        }
        var fields = window.mvFieldErrors;
        if (response.ok) {
          if (fields) { fields.clear(form); fields.forget(form); }
          var show = form.getAttribute('data-mv-save-show');
          if (!response.redirected && show && showResult(form, show, await response.text())) {
            form._mvSaving = false;
            clear(form, button);
            form.reset();
            form.dispatchEvent(new CustomEvent('mv:saved', {bubbles: true}));
            return;
          }
          // The page the server sent us to shows "Saved."; a page drawn for
          // this request alone is drawn again from the same address.
          return response.redirected ? hooks.navigate(response.url) : window.location.reload();
        }
        try { payload = await response.clone().json(); } catch (_) { payload = null; }
        var reauthenticate = response.headers.get('X-Reauthenticate') || (payload && payload.reauthenticate);
        var signIn = response.status === 403 && reauthenticate && returnHere(reauthenticate);
        if (signIn) {
          say(status, 'Sign in again to continue…');
          return hooks.navigate(signIn);
        }
        failed(form, button, status, {status: response.status, detail: payload && payload.detail}, payload);
      }
    })();

    // Required fields say so beside their label: one small "Required" for
    // every [required] control, on load and for forms added later (dialogs,
    // rows built from data). The required attribute already tells assistive
    // technology, so the marker is aria-hidden. A label that already says it
    // (an asterisk or the word "required") is left as written.
    (function () {
      if (typeof document.querySelectorAll !== 'function' || !document.body) return;
      var CONTROLS = 'input[required], select[required], textarea[required]';
      function labelFor(control) {
        if (control.type === 'hidden') return null;
        if (control.type === 'radio') {
          var group = control.closest('fieldset');
          return group && group.querySelector('legend');
        }
        return control.labels && control.labels.length ? control.labels[0] : null;
      }
      // The label's own words, without the text of a field it wraps.
      function ownText(node) {
        var text = '';
        Array.prototype.forEach.call(node.childNodes, function (child) {
          if (child.nodeType === 3) text += child.nodeValue;
          else if (child.nodeType === 1 && !child.matches('input, select, textarea, button, datalist')) text += ownText(child);
        });
        return text;
      }
      function mark(control) {
        var label = labelFor(control);
        if (!label || label.querySelector('.mv-required') || /(?:^|\s)\*(?:\s|$)|\brequired\b/i.test(ownText(label))) return;
        var marker = document.createElement('span');
        marker.className = 'mv-required'; marker.setAttribute('aria-hidden', 'true');
        marker.setAttribute('data-mv-required', ''); marker.lang = 'en'; marker.textContent = 'Required';
        // Beside the words: inside the element holding them (<span>Person</span>),
        // else just before a field the label wraps, else after a checkbox's words.
        var field = label.contains(control) && !/^(checkbox|radio)$/.test(control.type) ? control : null;
        while (field && field.parentNode !== label) field = field.parentNode;
        var words = field && field.previousSibling;
        while (words && words.nodeType === 3 && !words.nodeValue.trim()) words = words.previousSibling;
        if (words && words.nodeType === 1 && words.textContent.trim() && !words.matches('input, select, textarea, button') &&
            !words.querySelector('input, select, textarea, button')) words.appendChild(marker);
        else if (field) label.insertBefore(marker, field);
        else label.appendChild(marker);
      }
      function unmark(control) {
        var label = labelFor(control);
        var marker = label && label.querySelector('[data-mv-required]');
        if (!marker) return;
        if (control.type === 'radio' && label.parentNode.querySelector('input[type="radio"][required]')) return;
        marker.remove();
      }
      function markWithin(root) {
        if (root.matches && root.matches(CONTROLS)) mark(root);
        if (root.querySelectorAll) Array.prototype.forEach.call(root.querySelectorAll(CONTROLS), mark);
      }
      // A label whose words were rewritten (a translation, a renamed field) gets its marker back.
      function relabel(node) {
        var label = node.nodeType === 1 && node.closest('label, legend');
        if (!label) return;
        var control = label.tagName === 'LEGEND' ? label.parentNode.querySelector('input[type="radio"][required]') : label.control;
        if (control && control.required) mark(control);
      }
      markWithin(document);
      if (typeof MutationObserver !== 'function') return;
      new MutationObserver(function (changes) {
        changes.forEach(function (change) {
          if (change.type === 'attributes') {
            if (change.target.required) mark(change.target); else unmark(change.target);
            return;
          }
          Array.prototype.forEach.call(change.addedNodes, function (node) { if (node.nodeType === 1) markWithin(node); });
          relabel(change.target);
        });
      }).observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['required'] });
    })();

    // Reveal invalid fields before native form validation attempts to focus
    // them, including fields nested inside more than one closed disclosure.
    document.addEventListener('invalid', function (event) {
      var field = event.target;
      if (!field || typeof field.closest !== 'function') return;
      var disclosure = field.closest('details');
      while (disclosure) {
        disclosure.open = true;
        disclosure = disclosure.parentElement && disclosure.parentElement.closest('details');
      }
    }, true);

    // One form-field error pattern (GOV.UK error summary). A form marked
    // data-mv-validate is checked on submit: each problem is written next to
    // its field (aria-invalid plus aria-describedby to the message) and listed
    // in a summary at the top of the form that takes focus and links to each
    // field. The page title starts with "Error: " while problems remain.
    // Nothing typed is cleared. A form marked data-mv-keep="name" also keeps
    // what was typed in this tab (sessionStorage) across a reload, a failed
    // request or a sign-in, until the page shows it was saved
    // (an element with data-mv-keep-done="name") or the script calls forget().
    //   mvFieldErrors.validate(form) -> true when there is nothing to fix
    //   mvFieldErrors.show(form, [{field, message}], {message}) -> list problems
    //   mvFieldErrors.fail(form, failure, action) -> a failed request, values kept
    //   mvFieldErrors.clear(form) / restore(form) / forget(form)
    // Extra checks: listen for 'mv:validate' on the form and call
    // event.detail.error(control, message). Field wording: data-error-required,
    // data-error-format, data-error-range and data-error-length on the control.
    // Template side: templates/_form_field.html (form_field, error_summary).
    (function () {
      if (typeof document.querySelectorAll !== 'function') return;
      var TITLE_PREFIX = 'Error: ';
      var KEEP_HOURS = 24;
      var SECRET = /(pass(word|phrase)?|secret|token|api[_-]?key|credential|private[_-]?key|authorization|cookie|otp|mfa[_-]?code)/i;
      function t(source, values) { return window.LightworkI18n ? window.LightworkI18n.text(source, values) : source.replace(/\{(\w+)\}/g, function (_m, k) { return values && values[k] != null ? values[k] : ''; }); }
      function controls(form) {
        return Array.prototype.filter.call(form.elements, function (c) {
          return c.matches && c.matches('input, select, textarea') && c.type !== 'hidden' && !c.disabled;
        });
      }
      function labelText(control) {
        var label = null;
        if (control.type === 'radio' || control.type === 'checkbox') {
          var group = control.closest('fieldset');
          if (control.type === 'radio' && group && group.querySelector('legend')) label = group.querySelector('legend');
        }
        if (!label && control.labels && control.labels.length) label = control.labels[0];
        var text = '';
        if (label) {
          var copy = label.cloneNode(true);
          Array.prototype.forEach.call(copy.querySelectorAll('.mv-required, .sr-only, input, select, textarea, button, [role="status"]'), function (n) { n.remove(); });
          text = copy.textContent;
        }
        if (!text.trim()) text = control.getAttribute('aria-label') || control.name || '';
        return text.replace(/\s+/g, ' ').replace(/\s*\((optional|required)\)\s*$/i, '').replace(/[:*]\s*$/, '').trim();
      }
      function lower(text) { return /^[A-Z][a-z]/.test(text) ? text.charAt(0).toLowerCase() + text.slice(1) : text; }
      // The message for one invalid control: the page's own words first, then
      // a written error another script already showed for it, then a plain default.
      function messageFor(control) {
        var v = control.validity, d = control.dataset || {}, label = lower(labelText(control));
        if (v.valueMissing && d.errorRequired) return d.errorRequired;
        if ((v.typeMismatch || v.patternMismatch || v.badInput) && d.errorFormat) return d.errorFormat;
        if ((v.rangeUnderflow || v.rangeOverflow || v.stepMismatch) && d.errorRange) return d.errorRange;
        if ((v.tooLong || v.tooShort) && d.errorLength) return d.errorLength;
        var shown = describedError(control);
        if (shown) return shown;
        if (v.valueMissing) {
          if (control.type === 'checkbox') return t('Tick the box to confirm: {label}', {label: labelText(control)});
          if (control.tagName === 'SELECT' || control.type === 'radio') return t('Choose {label}.', {label: label});
          return t('Enter {label}.', {label: label});
        }
        if (v.typeMismatch && control.type === 'email') return t('Enter a full email address. For example: name@company.com.');
        if (v.typeMismatch && control.type === 'url') return t('Enter a full web address, starting with https://.');
        if (v.badInput) return t('Enter {label} as a number.', {label: label});
        if (v.rangeUnderflow) return t('Enter {label} of at least {min}.', {label: label, min: control.min});
        if (v.rangeOverflow) return t('Enter {label} of no more than {max}.', {label: label, max: control.max});
        if (v.stepMismatch) return t('Check {label}: use at most two decimal places.', {label: label});
        if (v.tooLong) return t('Shorten {label} to {max} characters or fewer.', {label: label, max: control.maxLength});
        if (v.tooShort) return t('Make {label} at least {min} characters long.', {label: label, min: control.minLength});
        if (v.patternMismatch) return t('Check the format of {label}.', {label: label});
        return control.validationMessage || t('Check {label}.', {label: label});
      }
      function describedError(control) {
        var ids = (control.getAttribute('aria-describedby') || '').split(/\s+/);
        for (var i = 0; i < ids.length; i++) {
          var node = ids[i] && document.getElementById(ids[i]);
          if (node && !node.hidden && node.classList.contains('mv-form__err') && !node.hasAttribute('data-mv-field-error')) {
            var text = node.textContent.replace(/^\s*Error:\s*/, '').trim();
            if (text) return text;
          }
        }
        return '';
      }
      function target(control) {
        if (control.type === 'radio') {
          var first = control.form && control.form.querySelector('input[type="radio"][name="' + (window.CSS && CSS.escape ? CSS.escape(control.name) : control.name) + '"]');
          if (first) control = first;
        }
        if (!control.id) control.id = 'mvf-' + Math.random().toString(36).slice(2, 10);
        return control;
      }
      // The field's error slot: its own (id-error or data-mv-error-for), or a
      // written error another script already ties to it (aria-describedby).
      function existingSlot(control) {
        var slot = document.getElementById(control.id + '-error') ||
          (control.form && control.form.querySelector('[data-mv-error-for="' + control.id + '"]'));
        if (slot) return slot;
        var ids = (control.getAttribute('aria-describedby') || '').split(/\s+/);
        for (var i = 0; i < ids.length; i++) {
          var node = ids[i] && document.getElementById(ids[i]);
          if (node && node.classList.contains('mv-form__err')) return node;
        }
        return null;
      }
      function slotFor(control) {
        var slot = existingSlot(control);
        if (slot) return slot;
        slot = document.createElement('p');
        slot.className = 'mv-form__err mv-field__error'; slot.id = control.id + '-error'; slot.hidden = true;
        var anchor = control.closest('.mv-field') || (control.labels && control.labels[0] && control.labels[0].contains(control) ? control.labels[0] : control);
        if (anchor === control.closest('.mv-field')) anchor.appendChild(slot);
        else anchor.insertAdjacentElement('afterend', slot);
        return slot;
      }
      function describe(control, id, on) {
        var ids = (control.getAttribute('aria-describedby') || '').split(/\s+/).filter(function (x) { return x && x !== id; });
        if (on) ids.unshift(id);
        if (ids.length) control.setAttribute('aria-describedby', ids.join(' ')); else control.removeAttribute('aria-describedby');
      }
      function markField(control, message) {
        var slot = slotFor(control);
        slot.setAttribute('data-mv-field-error', '');
        slot.replaceChildren();
        var hidden = document.createElement('span'); hidden.className = 'sr-only'; hidden.textContent = t('Error:') + ' ';
        slot.append(hidden, document.createTextNode(message));
        slot.hidden = false;
        control.setAttribute('aria-invalid', 'true');
        describe(control, slot.id, true);
        var wrap = control.closest('.mv-field'); if (wrap) wrap.classList.add('mv-field--error');
      }
      function unmarkField(control) {
        var slot = existingSlot(control);
        if (slot && slot.hasAttribute('data-mv-field-error')) {
          slot.hidden = true; slot.replaceChildren(); slot.removeAttribute('data-mv-field-error');
          describe(control, slot.id, false);
        }
        if (control.getAttribute('aria-invalid') === 'true') control.removeAttribute('aria-invalid');
        var wrap = control.closest('.mv-field'); if (wrap) wrap.classList.remove('mv-field--error');
      }
      function summaryFor(form) {
        var box = form.querySelector('[data-mv-error-summary]');
        var before = form.previousElementSibling;
        if (!box && before && before.hasAttribute('data-mv-error-summary')) box = before;
        if (box) return box;
        box = document.createElement('div');
        box.className = 'mv-error-summary'; box.setAttribute('data-mv-error-summary', '');
        box.id = (form.id || 'mvf-' + Math.random().toString(36).slice(2, 10)) + '-errors';
        box.tabIndex = -1; box.hidden = true;
        form.insertBefore(box, form.firstChild);
        return box;
      }
      function setTitle(on) {
        var has = document.title.indexOf(TITLE_PREFIX) === 0;
        if (on && !has) document.title = TITLE_PREFIX + document.title;
        if (!on && has && !document.querySelector('[data-mv-error-summary]:not([hidden])')) document.title = document.title.slice(TITLE_PREFIX.length);
      }
      function renderSummary(form, problems, general) {
        var box = summaryFor(form);
        box.replaceChildren();
        box.setAttribute('tabindex', '-1');
        var titleId = box.id + '-title';
        var title = document.createElement('h2'); title.className = 'mv-error-summary__title'; title.id = titleId;
        title.textContent = problems.length ? t('There is a problem') : t('This was not saved');
        box.setAttribute('aria-labelledby', titleId);
        box.appendChild(title);
        if (general) { var p = document.createElement('p'); p.className = 'mv-error-summary__body'; p.textContent = general; box.appendChild(p); }
        if (problems.length) {
          var list = document.createElement('ul'); list.className = 'mv-error-summary__list';
          problems.forEach(function (problem) {
            var item = document.createElement('li'), link = document.createElement('a');
            link.href = '#' + problem.control.id; link.textContent = problem.message;
            item.appendChild(link); list.appendChild(item);
          });
          box.appendChild(list);
        }
        box.hidden = false;
        setTitle(true);
        var disclosure = form.closest('details');
        while (disclosure) { disclosure.open = true; disclosure = disclosure.parentElement && disclosure.parentElement.closest('details'); }
        box.focus();
        return box;
      }
      function clear(form) {
        controls(form).forEach(unmarkField);
        var box = form.querySelector('[data-mv-error-summary]') || (form.previousElementSibling && form.previousElementSibling.hasAttribute('data-mv-error-summary') ? form.previousElementSibling : null);
        if (box) { box.hidden = true; box.replaceChildren(); }
        setTitle(false);
      }
      function show(form, errors, opts) {
        opts = opts || {};
        controls(form).forEach(unmarkField);
        var seen = [], problems = [];
        (errors || []).forEach(function (e) {
          var c = typeof e.field === 'string' ? (document.getElementById(e.field) || form.elements[e.field]) : e.field;
          if (c && c.length && !c.tagName) c = c[0];
          if (!c || seen.indexOf(c) >= 0) return;
          c = target(c); seen.push(c);
          markField(c, e.message);
          problems.push({control: c, message: e.message});
        });
        if (!problems.length && !opts.message) { clear(form); return null; }
        return renderSummary(form, problems, opts.message || '');
      }
      function validate(form) {
        var problems = [], seenGroups = {};
        controls(form).forEach(function (c) {
          if (c.closest('[hidden]') && !c.closest('details')) return;   // a branch that is not in use
          if (c.type === 'radio') { if (seenGroups[c.name]) return; seenGroups[c.name] = true; }
          if (c.checkValidity()) return;   // fires 'invalid' so page handlers can word it first
          problems.push({field: c, message: messageFor(c)});
        });
        var extra = [];
        form.dispatchEvent(new CustomEvent('mv:validate', {detail: {error: function (control, message) { extra.push({field: control, message: message}); }}}));
        extra.forEach(function (e) { if (!problems.some(function (p) { return p.field === e.field; })) problems.push(e); });
        if (!problems.length) { clear(form); return true; }
        // Keep the page's field order in the summary.
        var order = controls(form);
        problems.sort(function (a, b) { return order.indexOf(a.field) - order.indexOf(b.field); });
        show(form, problems);
        return false;
      }
      function fail(form, failure, action) {
        var text = window.mvErrorText ? window.mvErrorText(failure, action) : 'Could not ' + action + '. Try again.';
        return show(form, [], {message: text + ' ' + t('What you entered is still here.')});
      }
      // Keeping what was typed, in this tab only. Hidden, password, file and
      // secret-looking fields are never kept.
      // Keyed by the form's name, not the address: a form posted to /users/invite
      // that shows its result there must clear the copy kept on /users.
      function keepKey(form) { return 'mv-keep:' + form.getAttribute('data-mv-keep'); }
      function keepable(c) {
        return !/^(password|file|hidden|submit|button|reset)$/.test(c.type) && !c.hasAttribute('data-mv-keep-off') &&
          !SECRET.test(c.name || '') && !SECRET.test(c.id || '') && c.autocomplete !== 'one-time-code';
      }
      function keyOf(c) { return c.name || c.id; }
      function save(form) {
        var values = {};
        controls(form).filter(keepable).forEach(function (c) {
          var k = keyOf(c); if (!k) return;
          if (c.type === 'checkbox' || c.type === 'radio') { values[k] = values[k] || []; if (c.checked) values[k].push(c.value); }
          else if (c.tagName === 'SELECT' && c.multiple) values[k] = Array.prototype.filter.call(c.options, function (o) { return o.selected; }).map(function (o) { return o.value; });
          else values[k] = c.value;
        });
        try { sessionStorage.setItem(keepKey(form), JSON.stringify({at: Date.now(), values: values})); } catch (_) {}
      }
      function stored(form) {
        try {
          var raw = JSON.parse(sessionStorage.getItem(keepKey(form)) || 'null');
          if (!raw || typeof raw.values !== 'object' || Date.now() - raw.at > KEEP_HOURS * 3600000) return null;
          return raw.values;
        } catch (_) { return null; }
      }
      function forget(form) {
        try { sessionStorage.removeItem(keepKey(form)); } catch (_) {}
        var note = form.querySelector('.mv-keep-note'); if (note) note.remove();
      }
      function restore(form) {
        var values = stored(form), changed = [];
        if (!values) return false;
        controls(form).filter(keepable).forEach(function (c) {
          var k = keyOf(c); if (!k || !(k in values)) return;
          var v = values[k], before = c.type === 'checkbox' || c.type === 'radio' ? c.checked : c.value;
          if (c.type === 'checkbox' || c.type === 'radio') c.checked = Array.isArray(v) && v.indexOf(c.value) >= 0;
          else if (c.tagName === 'SELECT' && c.multiple) Array.prototype.forEach.call(c.options, function (o) { o.selected = Array.isArray(v) && v.indexOf(o.value) >= 0; });
          else if (c.tagName !== 'SELECT' || Array.prototype.some.call(c.options, function (o) { return o.value === v; })) c.value = v;
          if ((c.type === 'checkbox' || c.type === 'radio' ? c.checked : c.value) !== before) changed.push(c);
        });
        // Pages react to the restored values; the stored copy is not rewritten meanwhile.
        form.__mvRestoring = true;
        try { changed.forEach(function (c) { c.dispatchEvent(new Event('change', {bubbles: true})); }); }
        finally { form.__mvRestoring = false; }
        if (changed.length) {
          var section = form.closest('details');
          while (section) { section.open = true; section = section.parentElement && section.parentElement.closest('details'); }
        }
        if (changed.length && !form.querySelector('.mv-keep-note')) {
          var note = document.createElement('p'); note.className = 'mv-keep-note'; note.setAttribute('role', 'status');
          note.appendChild(document.createTextNode(t('We kept what you typed here earlier. Check it, then save.') + ' '));
          var reset = document.createElement('button'); reset.type = 'button'; reset.className = 'btn btn--ghost';
          reset.textContent = t('Clear the form');
          reset.addEventListener('click', function () { form.reset(); clear(form); controls(form).forEach(function (c) { c.dispatchEvent(new Event('change', {bubbles: true})); }); forget(form); });
          note.appendChild(reset);
          var box = summaryFor(form);
          box.insertAdjacentElement('afterend', note);
        }
        return changed.length > 0;
      }
      function wireKeep(form) {
        if (form.__mvKeep) return; form.__mvKeep = true;
        var name = form.getAttribute('data-mv-keep');
        var done = document.querySelectorAll('[data-mv-keep-done]');
        for (var i = 0; i < done.length; i++) {
          if ((done[i].getAttribute('data-mv-keep-done') || '').split(/\s+/).indexOf(name) >= 0) { forget(form); return wireSave(form); }
        }
        restore(form);
        wireSave(form);
      }
      function wireSave(form) {
        form.addEventListener('input', function () { if (!form.__mvRestoring) save(form); });
        form.addEventListener('change', function () { if (!form.__mvRestoring) save(form); });
      }
      function wire(root) {
        Array.prototype.forEach.call((root || document).querySelectorAll('form[data-mv-validate]'), function (form) { form.noValidate = true; });
        Array.prototype.forEach.call((root || document).querySelectorAll('form[data-mv-keep]'), wireKeep);
        // Errors the server rendered: the summary takes focus once, on load.
        var shown = (root || document).querySelector('[data-mv-error-summary]:not([hidden])');
        if (shown && shown.querySelector('a, p')) { setTitle(true); shown.focus(); }
      }
      // A summary link moves focus into its field (opening any closed
      // section first) with the field's label in view.
      document.addEventListener('click', function (event) {
        var link = event.target && event.target.closest && event.target.closest('[data-mv-error-summary] a[href^="#"]');
        if (!link) return;
        var c = document.getElementById(decodeURIComponent(link.getAttribute('href').slice(1)));
        if (!c) return;
        event.preventDefault();
        var disclosure = c.closest('details');
        while (disclosure) { disclosure.open = true; disclosure = disclosure.parentElement && disclosure.parentElement.closest('details'); }
        var label = c.labels && c.labels[0];
        if (label && label.scrollIntoView) label.scrollIntoView({block: 'center'});
        c.focus();
      });
      // Runs before the page's own submit handlers (capture), so a confirm
      // dialog or a request never starts while a field still needs fixing.
      document.addEventListener('submit', function (event) {
        var form = event.target;
        if (!(form instanceof HTMLFormElement) || !form.hasAttribute('data-mv-validate')) return;
        // A button marked formnovalidate (e.g. Preview) submits without the check, as the browser would.
        if (event.submitter && event.submitter.formNoValidate) return;
        if (!validate(form)) { event.preventDefault(); event.stopImmediatePropagation(); }
      }, true);
      // A field that is being fixed loses its error at once; the summary stays until the next submit.
      function fixing(event) {
        var c = event.target;
        if (c && c.form && c.getAttribute && c.getAttribute('aria-invalid') === 'true' && c.form.hasAttribute('data-mv-validate') &&
            (!c.validity || c.validity.valid)) unmarkField(c);
      }
      document.addEventListener('input', fixing);
      document.addEventListener('change', fixing);
      window.mvFieldErrors = {validate: validate, show: show, fail: fail, clear: clear, restore: restore, forget: forget, wire: wire};
      wire(document);
    })();

    // Collapsible sidebar groups. Chat-first: groups start COLLAPSED so the
    // nav isn't a wall of every page — the group holding the active page is
    // always forced open, and any group the user pins open persists per-group
    // in localStorage. Progressive enhancement: with no JS the markup leaves
    // every group open (aria-expanded="true"), so nothing is hidden without JS.
    (function() {
      const KEY = 'mvk_nav_expanded';
      let expanded = null;
      try { expanded = JSON.parse(localStorage.getItem(KEY) || 'null'); } catch (e) {}
      // No remembered choice yet (a fresh sign-in): open the two groups a new
      // administrator needs first, so the rail is never ten closed headers.
      if (!expanded || typeof expanded !== 'object') expanded = { Operate: true, Admin: true };
      document.querySelectorAll('.navgrp__toggle').forEach(function(btn) {
        const grp = btn.getAttribute('data-grp');
        const hasActive = btn.parentElement.querySelector('a.active');
        // An area the role's preset opens (areas navigation) starts open
        // until the person closes it.
        const preset = btn.getAttribute('data-grp-open') === 'true' && expanded[grp] !== false;
        const open = !!expanded[grp] || !!hasActive || preset;
        btn.setAttribute('aria-expanded', open ? 'true' : 'false');
        btn.addEventListener('click', function() {
          const nowOpen = btn.getAttribute('aria-expanded') === 'true';
          btn.setAttribute('aria-expanded', nowOpen ? 'false' : 'true');
          if (nowOpen) expanded[grp] = false; else expanded[grp] = true;
          try { localStorage.setItem(KEY, JSON.stringify(expanded)); } catch (e) {}
        });
      });
    })();

    // Approvals badge: how many decisions wait for this person. The sidebar
    // renders the link only for people who can decide; the count is fetched
    // after the page has rendered, so it never slows a page, and stays hidden
    // at zero or when it cannot be read.
    (function() {
      const links = Array.from(document.querySelectorAll('a[data-approvals-badge]'));
      if (!links.length || typeof fetch !== 'function') return;
      function show(count) {
        links.forEach(function(link) {
          const badge = link.querySelector('.nav-count');
          const label = link.querySelector('.nav-label');
          if (!badge || !label) return;
          badge.hidden = !(count > 0);
          badge.textContent = count > 99 ? '99+' : String(count);
          badge.setAttribute('aria-hidden', 'true');
          if (count > 0) {
            const i18n = window.LightworkI18n, values = {page: label.textContent.trim(), count: count};
            link.setAttribute('aria-label', i18n ? i18n.text('{page}, {count} waiting', values)
              : values.page + ', ' + count + ' waiting');
          } else {
            link.removeAttribute('aria-label');
          }
        });
      }
      fetch('/api/v1/approvals/waiting-count', {credentials: 'same-origin', cache: 'no-store',
        headers: {Accept: 'application/json'}})
        .then(function(response) { return response.ok ? response.json() : null; })
        .then(function(data) { if (data && Number.isSafeInteger(data.waiting) && data.waiting >= 0) show(data.waiting); })
        .catch(function() {});
    })();

    // Feature-gated workbenches must not advertise executable controls while
    // their server capability is disabled. Templates expose only the final
    // boolean; no client value can enable a server-side feature.
    (function () {
      // A module-gate banner's Turn on button is the way out of a switched-off
      // page; disabling it (or marking an ancestor aria-disabled, which reads
      // as disabling everything inside) left an administrator no way to start.
      function markOff(container) {
        if (!container.querySelector('[data-module-gate]')) container.setAttribute('aria-disabled', 'true');
      }
      document.querySelectorAll('[data-feature-enabled="false"]').forEach(function (root) {
        markOff(root);
        root.querySelectorAll('form, fieldset').forEach(markOff);
        root.querySelectorAll('button, input, select, textarea').forEach(function (control) {
          if (control.closest('[data-module-gate]')) return;
          control.disabled = true;
          if (!control.title) {
            control.title = 'This feature is turned off. Ask your administrator to enable it.';
          }
        });
      });
    })();

    // Sidebar toggle. Wide screens: the hamburger collapses/expands the
    // persistent sidebar (preference persisted). Narrow screens: it opens the
    // off-canvas drawer, closed by the backdrop, Escape, or following a link.
    (function() {
      const body = document.body;
      const btn = document.getElementById('nav-toggle');
      const backdrop = document.getElementById('nav-backdrop');
      const sidebar = document.getElementById('sidebar');
      if (!btn) return;
      const KEY = 'mvk_sidebar_collapsed';
      const mobile = window.matchMedia('(max-width: 880px)');
      const covered = Array.from(document.querySelectorAll('main, body > footer')).map(function(element) {
        return {element: element, wasInert: element.hasAttribute('inert')};
      });
      const topbar = document.querySelector('.topbar');
      function syncHeaderHeight() {
        if (!topbar) return;
        const height = Math.ceil(topbar.getBoundingClientRect().height) + 'px';
        body.style.setProperty('--shell-topbar-h', height);
        // The root reads it too: scroll-padding-top keeps focused elements
        // and in-page link targets below the sticky bar (lightwork.css).
        document.documentElement.style.setProperty('--shell-topbar-h', height);
      }
      // Status messages, display fonts and phone wrapping can grow the header.
      // Position navigation beneath its real height instead of covering controls.
      if (topbar && typeof ResizeObserver === 'function') {
        new ResizeObserver(syncHeaderHeight).observe(topbar);
      } else {
        window.addEventListener('resize', syncHeaderHeight);
      }
      syncHeaderHeight();
      try { if (localStorage.getItem(KEY) === '1') body.classList.add('nav-collapsed'); } catch (e) {}
      function syncAria() {
        const shown = mobile.matches ? body.classList.contains('nav-open')
                                     : !body.classList.contains('nav-collapsed');
        btn.setAttribute('aria-expanded', shown ? 'true' : 'false');
        // The mobile backdrop covers page controls. Keep keyboard and assistive
        // technology users in the visible shell until the drawer closes.
        // Header controls remain reachable, including the emergency stop.
        covered.forEach(function(item) {
          const inert = item.wasInert || (mobile.matches && shown);
          item.element.inert = inert;
          item.element.toggleAttribute('inert', inert);
        });
        // A closed drawer is only translated off-screen on mobile, so it can
        // otherwise remain in the accessibility tree and keyboard tab order.
        // Use both the reflected property and the content attribute: the
        // latter is required by browser engines that do not expose HTMLElement
        // `.inert`, while aria-hidden gives assistive technology an explicit
        // state. The same state is harmless and accurate for desktop collapse.
        if (sidebar) {
          const hidden = !shown;
          sidebar.inert = hidden;
          sidebar.toggleAttribute('inert', hidden);
          if (hidden) {
            sidebar.setAttribute('aria-hidden', 'true');
            if (sidebar.contains(document.activeElement)) btn.focus();
          } else {
            sidebar.removeAttribute('aria-hidden');
          }
        }
      }
      function closeDrawer() { body.classList.remove('nav-open'); syncAria(); }
      btn.addEventListener('click', function() {
        if (mobile.matches) {
          body.classList.toggle('nav-open');
        } else {
          const collapsed = body.classList.toggle('nav-collapsed');
          try { localStorage.setItem(KEY, collapsed ? '1' : ''); } catch (e) {}
        }
        syncAria();
        if (mobile.matches && body.classList.contains('nav-open') && sidebar) {
          const first = sidebar.querySelector('a[href], button:not([disabled])');
          if (first) first.focus();
        }
      });
      if (backdrop) backdrop.addEventListener('click', closeDrawer);
      document.addEventListener('keydown', function(ev) { if (ev.key === 'Escape') closeDrawer(); });
      document.querySelectorAll('.sidebar a, .skip-link').forEach(function(a) { a.addEventListener('click', closeDrawer); });
      if (mobile.addEventListener) mobile.addEventListener('change', function() {
        // An open mobile drawer must not silently reopen after a desktop visit.
        if (!mobile.matches) body.classList.remove('nav-open');
        syncAria();
      });
      syncAria();
    })();

    (function () {
      var system = window.matchMedia('(prefers-color-scheme: dark)');
      var themeClass = Array.from(document.body.classList).find(function (name) { return name.startsWith('theme-'); });
      document.body.dataset.themePreference = themeClass ? themeClass.slice(6) : 'dark';
      window.mvApplyDisplayPreference = function (key, value) {
        if (key === 'text_size') {
          document.documentElement.dataset.textSize = value;
          document.documentElement.style.fontSize = value === 'larger' ? '125%' : value === 'large' ? '112.5%' : '';
          return;
        }
        if (['theme', 'font', 'density', 'glass'].indexOf(key) === -1) return;
        if (key === 'theme') { document.body.dataset.themePreference = value; if (value === 'system') value = system.matches ? 'dark' : 'light'; }
        Array.from(document.body.classList).forEach(function (name) { if (name.startsWith(key + '-')) document.body.classList.remove(name); });
        document.body.classList.add(key + '-' + value);
        // The browser's own chrome (phone address bar) follows the new canvas.
        var chrome = key === 'theme' && document.querySelector('meta[name="theme-color"]');
        var canvas = chrome && getComputedStyle(document.body).backgroundColor;
        if (canvas && canvas !== 'rgba(0, 0, 0, 0)' && canvas !== 'transparent') chrome.setAttribute('content', canvas);
        window.dispatchEvent(new CustomEvent('lightwork:appearance-changed', {detail:{key:key,value:value}}));
      };
      var size = document.querySelector('meta[name="lightwork-text-size"]');
      window.mvApplyDisplayPreference('text_size', size ? size.content : 'standard');
      window.mvApplyDisplayPreference('theme', document.body.dataset.themePreference);
      function sync() { if (document.body.dataset.themePreference === 'system') window.mvApplyDisplayPreference('theme', 'system'); }
      if (system.addEventListener) system.addEventListener('change', sync); else system.addListener(sync);
    })();

    // Preferences popover: close on outside-click and Escape (it is a native
    // <details>; choosing an option keeps both the page and popover open).
    (function () {
      var prefs = document.getElementById('prefs-menu');
      if (!prefs) return;
      var status = document.getElementById('prefs-status'), undo = document.getElementById('prefs-undo');
      var saving = false, previous = null;
      async function savePreference(key, value, select, isUndo) {
        if (saving) return;
        saving = true;
        var old = key === 'interface_language' ? (select.dataset.savedValue || '') : key === 'text_size' ? (document.documentElement.dataset.textSize || 'standard') :
          key === 'theme' ? (document.body.dataset.themePreference || 'dark') :
          Array.from(document.body.classList).find(function (name) { return name.startsWith(key + '-'); });
        if (old && old.startsWith(key + '-')) old = old.slice(key.length + 1);
        prefs.querySelectorAll('select, button, input').forEach(function (control) { control.disabled = true; });
        window.mvApplyDisplayPreference(key, value);
        if (status) window.LightworkI18n ? window.LightworkI18n.set(status, 'Saving…') : status.textContent = 'Saving…';
        try {
          var context = document.querySelector('meta[name="lightwork-preference-context"]');
          var revision = document.querySelector('meta[name="lightwork-preference-revision"]');
          var device = document.getElementById('prefs-device-only');
          var response = await fetch('/api/v1/preferences/display', {method: 'POST', credentials: 'same-origin',
            headers: {'Content-Type': 'application/json'}, body: JSON.stringify({key:key, value:value,
              context:context ? context.content : '', expected_revision:revision ? revision.content : null,
              device_only:!!(device && device.checked)})});
          var data = await response.json();
          if (!response.ok) throw response;
          if (revision && data.revision) revision.content = data.revision;
          previous = isUndo ? null : {key:key, value:old, select:select};
          if (undo) undo.hidden = !previous;
          if (key === 'interface_language') select.dataset.savedValue = value;
          var savedMessage = key === 'interface_language' ? 'Language saved. Open another page or reload after saving your draft.' : 'Saved. Your editor and unsaved work remain open.';
          if (status) window.LightworkI18n ? window.LightworkI18n.set(status, savedMessage) : status.textContent = savedMessage;
        } catch (failure) {
          window.mvApplyDisplayPreference(key, old);
          if (select) select.value = old;
          if (status) { var failureMessage = 'Appearance was not saved. The earlier appearance is restored; retry or refresh preferences after saving your work.'; if (window.LightworkI18n) window.LightworkI18n.set(status, failureMessage); else status.textContent = failureMessage; }
        } finally {
          saving = false; prefs.querySelectorAll('select, button, input').forEach(function (control) { control.disabled = false; });
        }
      }
      prefs.querySelectorAll('[data-ui-preference]').forEach(function (select) {
        select.addEventListener('change', function () {
          var key = select.getAttribute('data-ui-preference');
          if (key && (select.value || key === 'interface_language')) savePreference(key, select.value, select, false);
        });
      });
      if (undo) undo.addEventListener('click', function () {
        if (previous) { previous.select.value = previous.value; savePreference(previous.key, previous.value, previous.select, true); }
      });
      document.addEventListener('click', function (ev) {
        if (prefs.open && !prefs.contains(ev.target)) prefs.open = false;
      });
      document.addEventListener('keydown', function (ev) {
        if (ev.key === 'Escape' && prefs.open) {
          prefs.open = false;
          var s = prefs.querySelector('summary'); if (s) s.focus();
        }
      });
    })();

    // "Turned off" versus "not allowed": the server marks a refusal because a
    // feature is off with X-Lightwork-Reason: feature-off (feature_gate.py).
    // mvFeatureOff(failure) reads it from a fetch Response, a Headers-carrying
    // error or a page-supplied {feature: {...}}; mvShowFeatureOff renders the
    // module-gate notice in place, with Turn on for whoever may turn it on.
    (function () {
      function lowerFirst(text) {
        return /^[A-Z][a-z]/.test(text) ? text.charAt(0).toLowerCase() + text.slice(1) : text;
      }
      window.mvFeatureOff = function (failure) {
        if (!failure) return null;
        if (failure.feature && typeof failure.feature === 'object') return failure.feature;
        var h = failure.headers;
        if (!h) return null;
        var get = typeof h.get === 'function' ? function (k) { return h.get(k) || ''; }
          : function (k) { return h[k] || h[k.toLowerCase()] || ''; };
        if (get('X-Lightwork-Reason') !== 'feature-off') return null;
        var label = '';
        try { label = decodeURIComponent(get('X-Lightwork-Feature-Label')); } catch (_) { label = ''; }
        return { section: get('X-Lightwork-Feature'), label: label,
                 switchable: get('X-Lightwork-Feature-Switch') === 'module' };
      };
      window.mvFeatureOffText = function (off) {
        var name = off && off.label ? off.label : '';
        var admin = document.body && document.body.getAttribute('data-global-admin') === '1';
        return (name ? name + ' is turned off.' : 'This feature is turned off.') + ' ' +
          (admin ? 'You can turn it on in Settings.'
            : 'Ask an administrator to turn ' + (name ? 'on ' + lowerFirst(name) : 'it on') + '.');
      };
      window.mvShowFeatureOff = function (element, failure, action) {
        var off = window.mvFeatureOff(failure);
        if (!element || !off) return false;
        var prefix = action ? 'Could not ' + action + '. ' : '';
        if (!off.section || !off.switchable || !off.label) {
          element.textContent = prefix + window.mvFeatureOffText(off);
          return true;
        }
        // A span: the notice lands inside the page's own status line.
        var gate = document.createElement('span');
        gate.className = 'mg-banner';
        gate.setAttribute('data-module-gate', off.section);
        gate.setAttribute('data-module-label', off.label);
        gate.setAttribute('data-mg-inline', '1');
        var head = document.createElement('strong');
        head.textContent = prefix + off.label + ' is turned off.';
        var actions = document.createElement('span');
        actions.className = 'mg-actions mg-admin-only';
        var button = document.createElement('button');
        button.type = 'button'; button.className = 'btn btn--primary mg-on';
        button.textContent = 'Turn on ' + lowerFirst(off.label);
        actions.appendChild(button);
        var note = document.createElement('span');
        note.className = 'mg-actions muted mg-nonadmin-note';
        note.setAttribute('role', 'note');
        note.textContent = 'Ask an administrator to turn on ' + lowerFirst(off.label) + '.';
        var err = document.createElement('span');
        err.className = 'mg-err'; err.setAttribute('role', 'alert'); err.setAttribute('aria-live', 'assertive');
        gate.append(head, actions, note, err);
        element.replaceChildren(gate);
        return true;
      };
    })();

    // Module-gate banners (_module_gate.html): one delegated handler turns a
    // disabled governance module on in-app via /api/v1/features/modules.
    // Failures are LOUD -- the exact server reason lands in the banner's
    // role="alert" line (a quiet failure here reads as "I clicked Turn on
    // and nothing happened", a real field complaint).
    (function () {
      document.addEventListener('click', function (ev) {
        var btn = ev.target.closest && ev.target.closest('.mg-on');
        if (!btn) return;
        var gate = btn.closest('[data-module-gate]');
        if (!gate) return;
        var err = gate.querySelector('.mg-err');
        var section = gate.getAttribute('data-module-gate');
        btn.disabled = true;
        if (err) err.textContent = '';
        fetch('/api/v1/features/modules', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ section: section, enabled: true }),
        }).then(function (r) {
          if (r.status === 403) {
            var denied = new Error('Only an administrator can turn this on. Ask yours.');
            denied.plain = true; throw denied;
          }
          if (!r.ok) throw r;
          if (gate.hasAttribute('data-mg-inline')) {
            // An in-place notice (mvShowFeatureOff) keeps what the person typed:
            // no reload. Other notices for the same module are now stale.
            document.querySelectorAll('[data-module-gate]').forEach(function (other) {
              if (other !== gate && other.getAttribute('data-module-gate') === section) other.hidden = true;
            });
            gate.replaceChildren(document.createTextNode(
              (gate.getAttribute('data-module-label') || 'It') + ' is on now. Try again.'));
            return;
          }
          location.reload();   // re-render with the module live
        }).catch(function (e) {
          if (err) err.textContent = (e && e.plain) ? e.message : window.mvErrorText(e, 'turn this on');
          btn.disabled = false;
        });
      });
    })();

// Bulk work on an admin list: filter the list, select every matching
// row, act on all of them after one confirmation that states the count, then
// read a change report row by row and undo it when each change can be undone.
// All controls are native checkboxes, inputs and buttons, so it works by
// keyboard; Ctrl+A (Cmd+A) inside the list selects every matching row.
//   var bulk = window.mvBulk({
//     list,                 // the element holding the rows
//     rows,                 // selector; each row has data-bulk-id and data-bulk-label
//     noun, nouns,          // "request", "requests"
//     filter,               // true: a filter box that matches row text
//     actions: [{label, verb, danger, button?, title?, note?, preview(items)?,
//                ask(items) -> extra | null,        // optional details first
//                run(item, extra) -> {undo?, note?}, // one row; throw to refuse
//                                                    // ({bulkReason} for page-written words)
//                after(report)}]                     // optional page update
//   });
//   bulk.refresh()          // after the page renders its rows again
window.mvBulk = function (opts) {
  'use strict';
  var list = opts.list;
  if (!list) return null;
  var noun = opts.noun || 'item', nouns = opts.nouns || noun + 's';
  var uid = 'mv-bulk-' + Math.random().toString(36).slice(2, 8);
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function counted(n) { return n + ' ' + (n === 1 ? noun : nouns); }
  function joined(names) {
    var shown = names.slice(0, 10);
    var more = names.length - shown.length;
    if (more > 0) return shown.join(', ') + ' and ' + more + ' more';
    if (shown.length < 2) return shown.join('');
    return shown.slice(0, -1).join(', ') + ' and ' + shown[shown.length - 1];
  }
  var bar = el('div', 'mv-bulk');
  bar.setAttribute('role', 'region');
  bar.setAttribute('aria-label', 'Change several ' + nouns + ' at once');
  var filterInput = null;
  if (opts.filter === true) {
    var filterLabel = el('label', 'mv-bulk__filter', 'Filter ' + nouns + ' ');
    filterInput = el('input', 'input');
    filterInput.type = 'search'; filterInput.autocomplete = 'off';
    filterLabel.appendChild(filterInput);
    bar.appendChild(filterLabel);
  }
  var allLabel = el('label', 'mv-bulk__all');
  var allBox = el('input'); allBox.type = 'checkbox';
  var allText = el('span');
  allLabel.append(allBox, document.createTextNode(' '), allText);
  var countLine = el('span', 'mv-bulk__count muted');
  countLine.setAttribute('role', 'status'); countLine.setAttribute('aria-live', 'polite');
  bar.append(allLabel, countLine);
  var buttons = (opts.actions || []).map(function (action) {
    var b = el('button', action.danger ? 'btn btn--danger' : 'btn', action.button || action.label + ' selected');
    b.type = 'button';
    b.addEventListener('click', function () { act(action); });
    bar.appendChild(b);
    return b;
  });
  var clear = el('button', 'btn btn--ghost', 'Clear selection'); clear.type = 'button';
  bar.appendChild(clear);
  var report = el('section', 'mv-bulk__report panel');
  report.tabIndex = -1; report.hidden = true;
  report.setAttribute('role', 'region'); report.setAttribute('aria-label', 'What changed');
  var anchor = opts.before || (list.closest('table') || list);
  anchor.parentNode.insertBefore(bar, anchor);
  anchor.parentNode.insertBefore(report, anchor);

  function rows() { return Array.prototype.slice.call(list.querySelectorAll(opts.rows)); }
  function pickOf(row) { return row.querySelector('input[data-bulk-pick]'); }
  function matching() { return rows().filter(function (row) { return !row.hidden; }); }
  function selected() { return matching().filter(function (row) { var p = pickOf(row); return p && p.checked; }); }
  function itemOf(row) { return {id: row.getAttribute('data-bulk-id'), label: row.getAttribute('data-bulk-label') || row.getAttribute('data-bulk-id'), row: row}; }
  function sync() {
    var shown = matching(), chosen = selected().length;
    allText.textContent = 'Select all ' + shown.length + ' matching';
    allBox.checked = shown.length > 0 && chosen === shown.length;
    allBox.indeterminate = chosen > 0 && chosen < shown.length;
    allBox.disabled = !shown.length;
    countLine.textContent = chosen + ' selected';
    buttons.forEach(function (b) { b.disabled = busy || !chosen; });
    clear.disabled = !chosen;
  }
  function decorate() {
    var table = list.closest('table');
    var head = table && table.querySelector('thead tr');
    if (head && !head.querySelector('th[data-bulk-head]')) {
      var th = el('th', '', 'Select'); th.scope = 'col'; th.setAttribute('data-bulk-head', '');
      head.insertBefore(th, head.firstChild);
    }
    rows().forEach(function (row, index) {
      if (pickOf(row)) return;
      var item = itemOf(row);
      var box = el('input'); box.type = 'checkbox'; box.setAttribute('data-bulk-pick', '');
      box.id = uid + '-' + index + '-' + String(item.id).replace(/[^A-Za-z0-9_-]/g, '');
      var label = el('label', 'sr-only', 'Select ' + item.label); label.htmlFor = box.id;
      box.addEventListener('change', sync);
      if (row.tagName === 'TR') {
        var cell = el('td', 'mv-bulk__cell'); cell.append(box, label);
        row.insertBefore(cell, row.firstChild);
      } else {
        var wrap = el('div', 'mv-bulk__pick'); wrap.append(box, label);
        row.insertBefore(wrap, row.firstChild);
      }
    });
    sync();
  }
  function applyFilter() {
    var words = filterInput ? filterInput.value.trim().toLowerCase() : '';
    rows().forEach(function (row) {
      var text = (row.getAttribute('data-bulk-label') + ' ' + row.textContent).toLowerCase();
      row.hidden = !!words && text.indexOf(words) === -1;
      // Nothing out of view stays selected: a bulk change only reaches what the person can see.
      if (row.hidden && pickOf(row)) pickOf(row).checked = false;
    });
    sync();
  }
  if (filterInput) filterInput.addEventListener('input', applyFilter);
  allBox.addEventListener('change', function () {
    var on = allBox.checked;
    matching().forEach(function (row) { var p = pickOf(row); if (p) p.checked = on; });
    sync();
  });
  clear.addEventListener('click', function () {
    rows().forEach(function (row) { var p = pickOf(row); if (p) p.checked = false; });
    sync(); allBox.focus();
  });
  list.addEventListener('keydown', function (event) {
    if (!(event.ctrlKey || event.metaKey) || event.altKey || String(event.key).toLowerCase() !== 'a') return;
    var t = event.target;
    if (t && t.closest && t.closest('input:not([type="checkbox"]), textarea, select, [contenteditable="true"]')) return;
    event.preventDefault();
    matching().forEach(function (row) { var p = pickOf(row); if (p) p.checked = true; });
    sync();
  });
  var busy = false;
  function failureText(failure, action) {
    // A page that already wrote the reason for people passes it as bulkReason.
    if (failure && typeof failure.bulkReason === 'string' && failure.bulkReason) return failure.bulkReason;
    var plain = failure && typeof window.mvPlainDetail === 'function' ? window.mvPlainDetail(failure.detail) : '';
    if (plain) return plain;
    var text = window.mvErrorText ? window.mvErrorText(failure, action) : 'It could not be changed.';
    return text.replace(/^Could not [^.]*\.\s*/, '') || text;
  }
  function showReport(action, results, undone) {
    report.replaceChildren();
    var done = results.filter(function (r) { return r.ok; });
    var refused = results.length - done.length;
    var title = undone != null ? 'Undone: ' + undone
      : (action.title || action.verb) + ': ' + done.length + ' done' + (refused ? ', ' + refused + ' not changed' : '');
    report.appendChild(el('h3', 'mv-bulk__title', title));
    var ul = el('ul', 'mv-bulk__lines');
    results.forEach(function (r) {
      ul.appendChild(el('li', '', r.item.label + ' — ' + (r.ok ? (r.note || 'done') : 'not changed: ' + r.reason)));
    });
    report.appendChild(ul);
    var undoable = done.filter(function (r) { return typeof r.undo === 'function'; });
    if (undone == null && done.length && undoable.length === done.length) {
      var undo = el('button', 'btn', 'Undo these changes'); undo.type = 'button';
      undo.addEventListener('click', async function () {
        undo.disabled = true;
        var back = 0, failed = [];
        for (var i = 0; i < undoable.length; i++) {
          try { await undoable[i].undo(); back += 1; }
          catch (failure) { failed.push(undoable[i].item.label + ': ' + failureText(failure, 'undo it')); }
        }
        showReport(action, results, back);
        if (failed.length) report.appendChild(el('p', 'mv-bulk__failed', 'Not undone: ' + failed.join('; ')));
        if (action.after) action.after({action: action, results: results, undone: back});
        report.focus();
      });
      report.appendChild(undo);
    }
    var close = el('button', 'btn btn--ghost', 'Close report'); close.type = 'button';
    close.addEventListener('click', function () { report.hidden = true; allBox.focus(); });
    report.appendChild(close);
    report.hidden = false;
    report.focus();
  }
  async function act(action) {
    if (busy) return;
    var items = selected().map(itemOf);
    if (!items.length) return;
    // action.preview(items): what the change would affect, from the record.
    var foresee = '';
    if (action.preview) { try { foresee = (await action.preview(items)) || ''; } catch (_) { foresee = ''; } }
    var message = action.verb + ' ' + counted(items.length) + '? ' + joined(items.map(function (i) { return i.label; })) + '.' +
      (foresee ? ' ' + foresee : '') + (action.note ? ' ' + action.note : '');
    var ok = window.mvConfirm ? await window.mvConfirm(message, {okText: action.verb + ' ' + counted(items.length), danger: !!action.danger})
      : window.confirm(message);
    if (!ok) return;
    var extra = {};
    if (action.ask) { extra = await action.ask(items); if (extra == null) return; }
    busy = true; sync();
    countLine.textContent = action.verb + ': working on ' + counted(items.length) + '…';
    var results = [];
    for (var i = 0; i < items.length; i++) {
      try {
        var outcome = (await action.run(items[i], extra)) || {};
        results.push({item: items[i], ok: true, undo: outcome.undo, note: outcome.note});
        var pick = pickOf(items[i].row); if (pick) pick.checked = false;
      } catch (failure) {
        results.push({item: items[i], ok: false, reason: failureText(failure, action.verb.toLowerCase() + ' it')});
      }
    }
    busy = false; sync();
    showReport(action, results, null);
    if (action.after) action.after({action: action, results: results});
  }
  decorate();
  if (filterInput) applyFilter();
  return {refresh: function () { decorate(); if (filterInput) applyFilter(); }, bar: bar, report: report, selected: function () { return selected().map(itemOf); }};
};

// Request references and idempotency keys are protocol plumbing, not something
// a person should type. Inputs marked data-auto-reference are hidden by their
// pages and filled here: one fresh reference per operation, kept unchanged
// while the same operation is retried, replaced as soon as any other field in
// the same form or section changes (that is a new operation).
(function () {
  'use strict';
  function fresh() {
    if (window.crypto && typeof window.crypto.randomUUID === 'function') return window.crypto.randomUUID();
    var bytes = new Uint8Array(16), out = '';
    if (window.crypto && window.crypto.getRandomValues) window.crypto.getRandomValues(bytes);
    else for (var j = 0; j < bytes.length; j++) bytes[j] = Math.floor(Math.random() * 256);
    for (var i = 0; i < bytes.length; i++) out += ('0' + bytes[i].toString(16)).slice(-2);
    return out;
  }
  function scopeOf(input) {
    return input.closest('form, fieldset, section, .panel, .card') || document.body;
  }
  var refs = Array.prototype.slice.call(document.querySelectorAll('[data-auto-reference]'));
  if (!refs.length) return;
  refs.forEach(function (input) { if (!input.value) input.value = fresh(); });
  function renew(ev) {
    var t = ev.target;
    // Only a named field of the operation counts as a change; a record
    // picker's own search box and lists live inside the form but are not
    // part of what gets submitted, and the picker refuses to apply a
    // selection when the draft changed underneath it.
    if (!t || !t.name || !t.hasAttribute || t.hasAttribute('data-auto-reference')) return;
    refs.forEach(function (input) { if (scopeOf(input).contains(t)) input.value = fresh(); });
  }
  // 'input' only: a 'change' event also fires when focus leaves an edited
  // field, which would renew the reference on the click that submits it.
  document.addEventListener('input', renew, true);
})();

// Shared reveal helper respects the person's motion setting on every workspace.
window.mvReveal = function (element, options) {
  if (!element) return;
  var opts = Object.assign({block: 'nearest'}, options || {});
  opts.behavior = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth';
  element.scrollIntoView(opts);
  // Only explicit reveal actions use this helper, never background polling.
  if (!element.matches('input, button, select, textarea, a[href], [tabindex]')) element.tabIndex = -1;
  element.focus({preventScroll: true});
};

// The Copilot's scripts (lightwork-product-operations.js, then
// lightwork-copilot.js) are not part of the page's first download: on a slow
// phone link they took bandwidth from the stylesheet and the first paint.
// They load once the page is idle, or at once when someone opens the Copilot
// first (its button, or any [data-copilot-toggle]); that open waits for them
// and then happens. A selection a page makes meanwhile is kept for them in
// window.LightworkCopilotEarlySelection.
(function () {
  'use strict';
  var fab = document.getElementById('mv-copilot-fab');
  if (!fab || !fab.dataset.copilotSrc || !fab.dataset.operationsSrc) return;
  var state = 'idle', pending = null;
  document.addEventListener('lightwork:copilot-selection', function (event) {
    window.LightworkCopilotEarlySelection = event.detail || null;
  });
  function ready() {
    state = 'ready'; fab.removeAttribute('aria-busy');
    if (pending) { var opener = pending; pending = null; opener.click(); }
  }
  function loaded() { return state === 'ready' || fab.dataset.copilotReady === 'true'; }
  function load() {
    if (state !== 'idle' || loaded()) return;
    state = 'loading';
    var scripts = [fab.dataset.operationsSrc, fab.dataset.copilotSrc].map(function (src) {
      var script = document.createElement('script');
      script.src = src; script.async = false;   // in order, like the deferred tags they replace
      document.head.appendChild(script);
      return script;
    });
    var last = scripts[scripts.length - 1];
    last.addEventListener('load', ready);
    last.addEventListener('error', function () { state = 'idle'; pending = null; fab.removeAttribute('aria-busy'); });
  }
  window.mvLoadCopilot = load;
  document.addEventListener('click', function (event) {
    if (loaded()) return;
    var target = event.target instanceof Element ? event.target : null;
    var opener = target && target.closest('#mv-copilot-fab, [data-copilot-toggle]');
    if (!opener) return;
    event.preventDefault(); event.stopImmediatePropagation();
    pending = opener; fab.setAttribute('aria-busy', 'true');
    load();
  }, true);
  function whenIdle() {
    if (typeof window.requestIdleCallback === 'function') window.requestIdleCallback(load, {timeout: 3000});
    else setTimeout(load, 1500);
  }
  if (document.readyState === 'complete') whenIdle(); else window.addEventListener('load', whenIdle, {once: true});
})();

// Phones: the top bar's controls need two 44 px rows (109 px), too much of a
// small screen to cover while reading. Scrolling down tucks the bar away;
// scrolling up, the top of the page, a focus inside it or an open menu or
// drawer shows every control again (lightwork.css: body.topbar-tucked).
(function () {
  'use strict';
  var bar = document.querySelector('.topbar');
  if (!bar || typeof window.matchMedia !== 'function') return;
  var phone = window.matchMedia('(max-width: 560px)');
  var body = document.body, last = window.scrollY || 0, queued = false;
  function tuck(on) { body.classList.toggle('topbar-tucked', on); }
  function held() {
    return !phone.matches || body.classList.contains('nav-open') || bar.contains(document.activeElement) ||
      !!bar.querySelector('[aria-expanded="true"], details[open]');
  }
  function update() {
    queued = false;
    var y = window.scrollY || 0;
    if (y <= 0 || held()) { tuck(false); last = y; return; }
    if (Math.abs(y - last) < 8) return;   // jitter and momentum ends change nothing
    tuck(y > last);
    last = y;
  }
  window.addEventListener('scroll', function () {
    if (queued) return;
    queued = true;
    (window.requestAnimationFrame || setTimeout)(update);
  }, {passive: true});
  bar.addEventListener('focusin', function () { tuck(false); });
  // Shift+Tab heads back towards the bar: show it before focus arrives, so
  // the browser does not scroll the page to reach a control out of view.
  document.addEventListener('keydown', function (event) { if (event.key === 'Tab' && event.shiftKey) tuck(false); }, true);
  if (typeof phone.addEventListener === 'function') phone.addEventListener('change', function () { if (!phone.matches) tuck(false); });
})();
