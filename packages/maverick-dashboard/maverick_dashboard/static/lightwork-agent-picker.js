/* Agent Factory: "Start from a specialist" searches as you type.
   The roster has 2,000+ specialists, so the page no longer ships it as one
   picker list: each search asks /agents/picker (the page's own permission and
   department scope) for the best matches. An ARIA combobox with a listbox:
   focus stays in the field, Down and Up move through the matches, Enter opens
   the highlighted specialist (or the one named exactly), Escape closes the
   list. Choosing a specialist opens its editor, as before. */
(function () {
  'use strict';
  var input = document.getElementById('agent-picker');
  var list = document.getElementById('agent-picker-list');
  if (!input || !list) return;
  var status = document.getElementById('agent-picker-status');
  var open = document.getElementById('agent-picker-open');
  var showAll = document.getElementById('agent-show-needs-setup');
  var source = input.getAttribute('data-picker-src') || '/agents/picker';
  var items = [], active = -1, shownFor = null, timer = null, latest = 0;

  function say(text) { window.mvStatus(status, text); }
  function toast(text) { if (typeof window.mvToast === 'function') window.mvToast(text, {error: true}); else say(text); }
  function plural(count, one, many) { return count + ' ' + (count === 1 ? one : many); }
  function withSetup() { return !!(showAll && showAll.checked); }

  function setActive(index) {
    active = index;
    Array.prototype.forEach.call(list.children, function (option, position) {
      option.setAttribute('aria-selected', position === index ? 'true' : 'false');
    });
    var option = index >= 0 ? list.children[index] : null;
    if (option) {
      input.setAttribute('aria-activedescendant', option.id);
      if (typeof option.scrollIntoView === 'function') option.scrollIntoView({block: 'nearest'});
    } else {
      input.removeAttribute('aria-activedescendant');
    }
  }
  function setOpen(on) {
    on = on && items.length > 0;
    list.hidden = !on;
    input.setAttribute('aria-expanded', on ? 'true' : 'false');
    if (!on) setActive(-1);
  }
  function choose(item) {
    input.value = item.label;
    setOpen(false);
    window.location.href = '/agents?name=' + encodeURIComponent(item.name);
  }
  function describe(data) {
    var shown = data.items.length;
    if (!shown) {
      return withSetup() ? 'No agents or specialists match. Try another word.'
        : 'No ready agents or specialists match. Choose "Show those that need setup" to include the rest.';
    }
    if (data.total > shown) return shown + ' of ' + plural(data.total, 'match', 'matches') + '. Keep typing to narrow the list.';
    return plural(shown, 'match', 'matches') + '.';
  }
  function render(data, query) {
    items = data.items;
    shownFor = query + '\n' + withSetup();
    list.replaceChildren();
    items.forEach(function (item, position) {
      var option = document.createElement('li');
      option.id = 'agent-picker-option-' + position;
      option.className = 'af-combo__option';
      option.setAttribute('role', 'option');
      option.setAttribute('aria-selected', 'false');
      var label = document.createElement('span');
      label.textContent = item.label;
      option.appendChild(label);
      if (item.readiness) {
        var note = document.createElement('span');
        note.className = 'af-combo__note';
        note.textContent = item.readiness;
        option.appendChild(note);
      }
      option.addEventListener('click', function () { choose(item); });
      list.appendChild(option);
    });
    setOpen(document.activeElement === input);
    say(describe(data));
  }
  async function fetchMatches(query) {
    var params = new URLSearchParams({q: query});
    if (withSetup()) params.set('setup', '1');
    var data = await window.mvFetchJSON(source + '?' + params.toString(), {}, 'search the specialists');
    if (!data || !Array.isArray(data.items)) throw new Error('unreadable');
    return data;
  }
  async function search(query) {
    var ticket = ++latest;
    try {
      var data = await fetchMatches(query);
      if (ticket === latest) render(data, query);
      return data;
    } catch (failure) {
      if (ticket === latest) {
        items = []; setOpen(false);
        say(window.mvErrorText ? window.mvErrorText(failure, 'search the agents and specialists') : 'Agents and specialists could not be searched. Try again.');
      }
      return null;
    }
  }
  function current() { return input.value.trim(); }
  function exact(found, text) {
    var wanted = text.toLocaleLowerCase();
    for (var i = 0; i < found.length; i += 1) {
      if (found[i].label.toLocaleLowerCase() === wanted || found[i].name === text) return found[i];
    }
    return null;
  }
  // Open the specialist the field names exactly (the Open button, or Enter
  // with no match highlighted), asking the server when needed.
  async function openNamed() {
    var text = current();
    var match = text ? exact(items, text) : null;
    if (!match && text) {
      var data = await search(text);
      match = data ? exact(data.items, text) : null;
    }
    if (match) choose(match);
    else toast('Choose an agent or specialist from the list, or show those needing setup.');
  }

  input.addEventListener('input', function () {
    clearTimeout(timer);
    if (!current()) {  // an empty field closes the list; Down opens the first matches
      latest += 1; items = []; shownFor = null; setOpen(false); say('');
      return;
    }
    timer = setTimeout(function () { search(current()); }, 150);
  });
  input.addEventListener('keydown', function (event) {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      if (list.hidden) {
        var wanted = current() + '\n' + withSetup();
        if (items.length && shownFor === wanted) { setOpen(true); setActive(event.key === 'ArrowDown' ? 0 : items.length - 1); }
        else search(current()).then(function (data) { if (data && data.items.length && document.activeElement === input) setActive(0); });
        return;
      }
      var step = event.key === 'ArrowDown' ? 1 : -1;
      setActive(active < 0 ? (step > 0 ? 0 : items.length - 1) : (active + step + items.length) % items.length);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      if (!list.hidden && active >= 0 && items[active]) choose(items[active]);
      else openNamed();
    } else if (event.key === 'Escape' && !list.hidden) {
      event.preventDefault();
      event.stopPropagation();
      setOpen(false);
    }
  });
  // Pressing on the list (a match or its scroll bar) keeps focus in the field.
  list.addEventListener('mousedown', function (event) { event.preventDefault(); });
  input.addEventListener('blur', function () { setOpen(false); });
  if (open) open.addEventListener('click', openNamed);
  if (showAll) showAll.addEventListener('change', function () {
    if (current() || !list.hidden) search(current());
  });
})();
