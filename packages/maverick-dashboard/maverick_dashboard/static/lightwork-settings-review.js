/* One reviewed catalog path for edits, profile imports, presets and rollback. */
(function () {
  'use strict';
  async function call(path, body) {
    try {
      return await window.mvFetchJSON(path, {method: body ? 'POST' : 'GET', cache: 'no-store', body: body, plainDetail: true}, 'review this change');
    } catch (error) {
      error.data = error.payload || {};  // a conflict lists what changed
      if (error.status && !window.mvPlainDetail(error.detail)) error.message = 'This change could not be reviewed. Your draft is kept. Try again.';
      throw error;
    }
  }
  function shown(value) { return typeof value === 'string' ? value : JSON.stringify(value); }
  function pickReview(plan, changes) {
    return new Promise(function (resolve) {
      var dialog = document.createElement('dialog'); dialog.className = 'settings-review panel';
      dialog.setAttribute('aria-label','Review setting changes');
      var heading = document.createElement('h2'); heading.textContent = 'Review setting changes'; dialog.appendChild(heading);
      var intro = document.createElement('p'); intro.textContent = 'These are organization settings. Clear a requested field to keep its current value. Dependent preset changes are listed automatically; excluding a preset excludes its dependent changes.'; dialog.appendChild(intro);
      var chosen = new Map();
      changes.forEach(function (change) {
        var item = plan.items.find(function (row) { return row.id === change.id; });
        var label = document.createElement('label'), box = document.createElement('input'); box.type = 'checkbox'; box.checked = true;
        chosen.set(change.id,box); label.appendChild(box); label.appendChild(document.createTextNode(' Include ' + (item ? item.label : change.id)));
        dialog.appendChild(label); dialog.appendChild(document.createElement('br'));
      });
      plan.items.forEach(function (item) {
        var section = document.createElement('section'), title = document.createElement('h3'); title.textContent = item.label + (item.automatic ? ' (dependent change)' : ''); section.appendChild(title);
        var detail = document.createElement('p'); detail.textContent = item.scope + ': ' + item.source + ' to ' + item.resulting_source + '. ' + item.timing + '. Affects: ' + item.affected + '. Area: ' + item.area + '.'; section.appendChild(detail);
        var before = document.createElement('pre'); before.textContent = 'Before: ' + shown(item.before) + '\nAfter: ' + shown(item.after); section.appendChild(before); dialog.appendChild(section);
      });
      plan.warnings.forEach(function (warning) { var p = document.createElement('p'); p.textContent = warning.label + ': ' + warning.warning; dialog.appendChild(p); });
      var error = document.createElement('p'); error.setAttribute('role','status'); dialog.appendChild(error);
      var cancel = document.createElement('button'); cancel.type = 'button'; cancel.className = 'btn btn--ghost'; cancel.textContent = 'Keep editing';
      var apply = document.createElement('button'); apply.type = 'button'; apply.className = 'btn'; apply.textContent = 'Use reviewed changes';
      var focus = document.activeElement;
      function done(result) { dialog.close(); dialog.remove(); if (focus && focus.isConnected) focus.focus(); resolve(result); }
      cancel.addEventListener('click',function () { done(null); });
      apply.addEventListener('click',async function () {
        var selected = changes.filter(function (change) { return chosen.get(change.id).checked; });
        if (!selected.length) { done(null); return; }
        if (selected.length !== changes.length) {
          apply.disabled = true;
          try {
            var next = await window.LightworkSettingsCatalog.review(selected, plan.revision);
            dialog.close(); dialog.remove(); resolve(await pickReview(next,selected));
          } catch (failure) { error.textContent = failure.message; apply.disabled = false; }
          return;
        }
        done({changes:selected,revision:plan.revision,token:plan.token,operation:plan.operation,context:plan.context});
      });
      dialog.addEventListener('cancel',function (event) { event.preventDefault(); done(null); });
      dialog.appendChild(cancel); dialog.appendChild(apply); document.body.appendChild(dialog); dialog.showModal(); cancel.focus();
    });
  }
  window.mvReviewSettings = async function (changes, revision) {
    var plan;
    try { plan = await window.LightworkSettingsCatalog.review(changes, revision); }
    catch (failure) {
      if (failure.status !== 409 || !failure.data.conflicts) throw failure;
      var text = failure.data.conflicts.map(function (item) { return item.label + ': ' + item.current + ' (' + item.source + ')'; }).join('\n');
      if (!(await window.mvConfirm('Settings changed. Your draft is kept. Review current values:\n' + text + '\nCompare your draft against this configuration?',{okText:'Review changes'}))) return null;
      plan = await window.LightworkSettingsCatalog.review(changes, failure.data.revision);
    }
    return pickReview(plan, changes);
  };
  async function saveExternal(changes, revision, status) {
    var reviewed = await window.mvReviewSettings(changes,revision); if (!reviewed) return;
    try {
      var saved = await window.LightworkSettingsCatalog.save(reviewed), result = saved.data;
      if (!saved.response.ok || !result.original || (!result.original.confirmed && result.original.state !== 'approval')) throw new Error(result.message || (result.original && result.original.message) || 'The original save is unconfirmed. Read its original result; your draft is kept.');
      if (!result.quorum) document.dispatchEvent(new CustomEvent('lightwork:settings-saved', {detail: {ids: result.changed || []}}));
      status.textContent = result.quorum ? result.message : 'Settings saved. Reload this page when your other drafts are saved to see their current values.';
    } catch (failure) {
      throw failure;
    }
  }
  var panel = document.getElementById('settings-tools'); if (!panel) return;
  var status = panel.querySelector('[data-tools-status]'), busy = false;
  panel.addEventListener('click',async function (event) {
    var button = event.target.closest('button'); if (!button || busy) return;
    busy = true; button.disabled = true;
    try {
      if (button.hasAttribute('data-profile-export')) {
        var selected = Array.from(document.querySelectorAll('[data-setting-id]')).filter(function (row) { return row.querySelector('[data-profile-select]:checked'); }).map(function (row) { return row.dataset.settingId; });
        var exported = await call('/api/v1/settings/profiles/export',{ids:selected});
        var url = URL.createObjectURL(new Blob([JSON.stringify(exported,null,2)],{type:'application/json'}));
        var a = document.createElement('a'); a.href = url; a.download = 'lightwork-preferences-profile.json'; a.click(); setTimeout(function () { URL.revokeObjectURL(url); },1000);
        status.textContent = Object.keys(exported.settings).length + ' supported preferences exported. Credentials, policy documents and non-portable settings were excluded.';
      } else if (button.hasAttribute('data-profile-import')) {
        var file = panel.querySelector('[data-profile-file]').files[0];
        if (!file || file.size > 256000) throw new Error('Choose a profile file smaller than 256 KB.');
        var prepared = await call('/api/v1/settings/profiles/import',{profile:JSON.parse(await file.text())});
        await saveExternal(prepared.changes,prepared.revision,status);
      } else if (button.hasAttribute('data-presets')) {
        var presets = await call('/api/v1/settings/presets'), host = panel.querySelector('[data-preset-items]'); host.replaceChildren();
        presets.presets.forEach(function (preset) {
          var row = document.createElement('div'), text = document.createElement('p'); text.textContent = preset.label + ': ' + preset.tradeoff + ' ' + (preset.drift.length ? preset.drift.length + ' fields differ from this profile.' : 'This profile matches current settings.');
          var apply = document.createElement('button'); apply.type='button'; apply.className='btn btn--ghost'; apply.textContent='Review ' + preset.label; apply.disabled=!preset.available;
          apply.addEventListener('click',async function (e) { e.stopPropagation(); apply.disabled=true; try { await saveExternal(preset.changes,presets.revision,status); } catch (failure) { status.textContent=failure.message; } finally { apply.disabled=!preset.available; } });
          row.appendChild(text);row.appendChild(apply);host.appendChild(row);
        }); status.textContent='Presets loaded for comparison. Nothing has been changed.';
      } else if (button.hasAttribute('data-history')) {
        var history = await call('/api/v1/settings/history'), list = panel.querySelector('[data-history-items]'); list.replaceChildren();
        history.items.forEach(function (item) {
          var row=document.createElement('li'), text=document.createElement('p'); text.textContent=item.label + ' - ' + item.actor + ' - ' + item.at;
          var detail=document.createElement('pre');detail.textContent='Before: ' + shown(item.before) + '\nAfter: ' + shown(item.after) + '\nRevision: ' + (item.before_revision || 'not recorded on legacy entries') + ' to ' + (item.after_revision || 'not recorded');
          row.appendChild(text);row.appendChild(detail);
          if(item.restorable){var restore=document.createElement('button');restore.type='button';restore.className='btn btn--ghost';restore.textContent='Review restore';restore.addEventListener('click',async function(e){e.stopPropagation();restore.disabled=true;try{await saveExternal([{id:item.id,value:item.restore_value}],history.revision,status);}catch(failure){status.textContent=failure.message;}finally{restore.disabled=false;}});row.appendChild(restore);}
          list.appendChild(row);
        });status.textContent=history.coverage;
      }
    } catch (failure) { status.textContent = failure.message || 'The request could not be completed. No automatic retry was made.'; }
    finally { busy=false;button.disabled=false; }
  });
})();
