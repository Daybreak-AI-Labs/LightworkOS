/* Comment threads and @mentions (templates/_comments.html, NOT-4).
   Each [data-comments-kind] block loads its thread from /api/v1/comments,
   posts a comment with the people it mentions, and lets the author delete a
   comment with a 10-second Undo. The mention list comes from the server and
   holds only people who can open the item. */
(function () {
  'use strict';
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function when(ts) {
    return window.mvTimeRelative ? window.mvTimeRelative(ts) : new Date(ts * 1000).toLocaleString();
  }
  function setup(root) {
    if (root.dataset.commentsReady) return;
    root.dataset.commentsReady = '1';
    var kind = root.dataset.commentsKind, id = root.dataset.commentsId;
    var list = root.querySelector('.mv-comments__list');
    var form = root.querySelector('.mv-comments__form');
    var body = root.querySelector('.mv-comments__body');
    var who = root.querySelector('.mv-comments__who');
    var add = root.querySelector('.mv-comments__add');
    var mentioned = root.querySelector('.mv-comments__mentioned');
    var status = root.querySelector('.mv-comments__status');
    var chosen = [], people = [], loaded = false;
    function say(text, error) { if (window.mvStatus) window.mvStatus(status, text, {error: !!error}); else status.textContent = text; }
    function showMentions() {
      mentioned.textContent = chosen.length ? 'Will notify: ' + chosen.map(function (p) { return p.label; }).join(', ') : '';
    }
    function render(thread) {
      list.replaceChildren();
      if (!thread.comments.length) {
        var empty = window.mvEmpty ? window.mvEmpty('No comments yet',
          thread.can_comment ? 'Write the first one below. Mention someone to let them know.' : 'Sign in with your own account to comment.', null, {compact: true})
          : el('p', 'muted', 'No comments yet.');
        var li = el('li', 'mv-comments__empty'); li.appendChild(empty); list.appendChild(li);
      }
      thread.comments.forEach(function (c) {
        var item = el('li', 'mv-comments__item'); item.id = 'comment-' + c.id; item.tabIndex = -1;
        var head = el('p', 'mv-comments__meta');
        head.append(el('strong', '', c.author), document.createTextNode(' · ' + when(c.created_at)));
        if (c.mentions.length) head.appendChild(document.createTextNode(' · mentioned ' + c.mentions.join(', ')));
        item.append(head, el('p', 'mv-comments__text', c.body));
        if (c.mine) {
          var del = el('button', 'btn btn--ghost btn--danger mv-comments__delete', 'Delete comment');
          del.type = 'button';
          del.addEventListener('click', function () { remove(c, item); });
          item.appendChild(del);
        }
        list.appendChild(item);
      });
      people = thread.people || [];
      who.replaceChildren(el('option', '', people.length ? 'Choose a person' : 'Nobody else can open this'));
      who.firstChild.value = '';
      people.forEach(function (p) { var o = el('option', '', p.label); o.value = p.principal; who.appendChild(o); });
      who.disabled = add.disabled = !people.length;
      form.hidden = !thread.can_comment;
      loaded = true;
      var target = window.location.hash && root.querySelector(window.location.hash.replace(/[^#\w-]/g, ''));
      if (target && window.mvReveal) window.mvReveal(target);
    }
    function load() {
      say('Loading comments…');
      return window.mvFetchJSON('/api/v1/comments?kind=' + encodeURIComponent(kind) + '&id=' + encodeURIComponent(id),
        {}, 'load the comments').then(function (thread) { render(thread); say(''); })
        .catch(function (failure) { say(window.mvErrorText(failure, 'load the comments'), true); });
    }
    function remove(comment, item) {
      item.hidden = true;
      window.mvUndo('Comment deleted.', {
        action: 'delete the comment',
        run: function (keepalive) {
          return fetch('/api/v1/comments/' + encodeURIComponent(comment.id), {method: 'DELETE', credentials: 'same-origin', keepalive: keepalive});
        },
        undo: function () { item.hidden = false; },
        done: function () { item.remove(); }
      });
    }
    add.addEventListener('click', function () {
      var person = people.find(function (p) { return p.principal === who.value; });
      if (!person || chosen.some(function (p) { return p.principal === person.principal; })) return;
      chosen.push(person);
      body.value = (body.value ? body.value.replace(/\s*$/, ' ') : '') + '@' + person.label + ' ';
      showMentions(); body.focus();
    });
    form.addEventListener('submit', function (event) {
      event.preventDefault();
      var text = body.value.trim();
      if (!text) { say('Write a comment before posting it.', true); body.focus(); return; }
      var button = form.querySelector('[type="submit"]'); button.disabled = true;
      // A mention whose name was removed from the text is not sent.
      var mentions = chosen.filter(function (p) { return text.indexOf('@' + p.label) !== -1; }).map(function (p) { return p.principal; });
      window.mvFetchJSON('/api/v1/comments', {method: 'POST', body: {kind: kind, id: id, body: text, mentions: mentions}}, 'post the comment')
        .then(function (thread) {
          body.value = ''; chosen = []; showMentions(); render(thread);
          say(mentions.length ? 'Comment posted. ' + mentions.length + (mentions.length === 1 ? ' person was' : ' people were') + ' notified.' : 'Comment posted.');
        })
        .catch(function (failure) { say(window.mvErrorText(failure, 'post the comment'), true); })
        .finally(function () { button.disabled = false; });
    });
    if (root.tagName === 'DETAILS') {
      root.addEventListener('toggle', function () { if (root.open && !loaded) load(); });
      if (root.open) load();
    } else {
      load();
    }
  }
  function boot() { document.querySelectorAll('[data-comments-kind]').forEach(setup); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
  window.mvComments = {boot: boot};
})();
