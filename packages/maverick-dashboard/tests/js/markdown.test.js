"use strict";
const {test} = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), {JSDOM} = require("jsdom");
const file = path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-markdown.js"), source = fs.readFileSync(file, "utf8");

function fixture(html) {
  const dom = new JSDOM(html || "<main></main>", {url: "https://lightwork.example/chat/goal/1", runScripts: "outside-only"});
  dom.window.eval(source);
  return dom.window;
}
function html(window, text) {
  const div = window.document.createElement("div");
  div.appendChild(window.lwMarkdown.render(text, window.document));
  return div.innerHTML;
}

test("headings, paragraphs and soft breaks render as a chat client would", t => {
  const window = fixture(); t.after(() => window.close());
  const out = html(window, "# Plan\n\nFirst line\nsecond line\n\n### Detail\n\nDone.");
  assert.equal(out, "<h2>Plan</h2><p>First line<br>second line</p><h4>Detail</h4><p>Done.</p>");
});

test("lists nest, keep their start number, and render task boxes", t => {
  const window = fixture(); t.after(() => window.close());
  const out = html(window, "3. Research\n   - competitors\n   - pricing\n4. Write\n\n- [x] shipped\n- [ ] pending");
  assert.equal(out,
    '<ol start="3"><li>Research<ul><li>competitors</li><li>pricing</li></ul></li><li>Write</li></ol>' +
    '<ul><li class="task"><input type="checkbox" disabled="" aria-label="done"> shipped</li>' +
    '<li class="task"><input type="checkbox" disabled="" aria-label="not done"> pending</li></ul>');
  assert.ok(window.document.createElement("div").appendChild(window.lwMarkdown.render("- a\n- b", window.document)));
});

test("fenced and inline code stay literal text, including angle brackets", t => {
  const window = fixture(); t.after(() => window.close());
  const out = html(window, "Use `a <b>` here.\n\n```python\nprint('<script>x</script>')\n```");
  assert.equal(out, "<p>Use <code>a &lt;b&gt;</code> here.</p><pre><code class=\"language-python\">print('&lt;script&gt;x&lt;/script&gt;')</code></pre>");
});

test("emphasis, strike and links render; unsafe links and raw HTML become text", t => {
  const window = fixture(); t.after(() => window.close());
  assert.equal(html(window, "**bold** and *em* and _em_ and ~~gone~~"),
    "<p><strong>bold</strong> and <em>em</em> and <em>em</em> and <del>gone</del></p>");
  assert.equal(html(window, "See [docs](https://example.com/a) or /goals or <https://x.io>"),
    '<p>See <a href="https://example.com/a" rel="noopener noreferrer" target="_blank">docs</a> or /goals or <a href="https://x.io" rel="noopener noreferrer" target="_blank">https://x.io</a></p>');
  assert.equal(html(window, "[evil](javascript:alert(1)) and [rel](/goals/3)"),
    '<p>evil and <a href="/goals/3">rel</a></p>');
  assert.equal(html(window, "<img src=x onerror=alert(1)> <b>raw</b>"),
    "<p>&lt;img src=x onerror=alert(1)&gt; &lt;b&gt;raw&lt;/b&gt;</p>");
  assert.equal(html(window, "![diagram](https://cdn.example/x.png)"),
    '<p><a href="https://cdn.example/x.png" rel="noopener noreferrer" target="_blank">diagram</a></p>');
  assert.equal(window.document.querySelectorAll("img, script").length, 0);
});

test("links cannot use backslashes to escape the current origin", t => {
  const window = fixture(); t.after(() => window.close());
  for (const href of ["/\\evil.example/path", "https:\\evil.example", "/path\\evil"]) {
    assert.equal(window.lwMarkdown.safeHref(href), null);
  }
  assert.equal(window.lwMarkdown.safeHref("/goals/3"), "/goals/3");
  assert.equal(window.lwMarkdown.safeHref("https://example.com/a"), "https://example.com/a");
});

test("tables, block quotes and rules render", t => {
  const window = fixture(); t.after(() => window.close());
  assert.equal(html(window, "| Channel | Cost |\n|:--|--:|\n| Email | $0 |\n| Ads | $500 |"),
    '<table><thead><tr><th scope="col" style="text-align: left;">Channel</th><th scope="col" style="text-align: right;">Cost</th></tr></thead>' +
    '<tbody><tr><td style="text-align: left;">Email</td><td style="text-align: right;">$0</td></tr><tr><td style="text-align: left;">Ads</td><td style="text-align: right;">$500</td></tr></tbody></table>');
  assert.equal(html(window, "> quoted\n> **line**\n\n---\n\nafter"), "<blockquote><p>quoted<br><strong>line</strong></p></blockquote><hr><p>after</p>");
});

test("upgrade() renders every data-markdown element in place and drops the marker", t => {
  const window = fixture('<main><div id="result" class="prose" data-markdown>## Summary\n\n- one\n- two</div><pre id="raw">## keep</pre></main>');
  t.after(() => window.close());
  window.lwMarkdown.upgrade(window.document);
  const el = window.document.getElementById("result");
  assert.equal(el.innerHTML, "<h3>Summary</h3><ul><li>one</li><li>two</li></ul>");
  assert.equal(el.hasAttribute("data-markdown"), false);
  assert.equal(el.className, "prose");
  assert.equal(window.document.getElementById("raw").textContent, "## keep");
});

test("plain text without markdown survives with its line structure", t => {
  const window = fixture(); t.after(() => window.close());
  assert.equal(html(window, "Line one\nLine two\n\nPara two"), "<p>Line one<br>Line two</p><p>Para two</p>");
  assert.equal(html(window, ""), "");
  assert.equal(html(window, null), "");
});
