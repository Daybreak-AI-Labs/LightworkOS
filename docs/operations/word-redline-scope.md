# Word redline scope and review outcomes

The privacy paper-review writer applies complete paragraph replacements with
real Word tracked insertions/deletions, author and date. It does not expand a
clause-sized anchor into a replacement of a larger paragraph: a proposal must
include the entire existing paragraph and the entire intended replacement. The
`ClauseEdit.scope` field defaults to `paragraph`; other scopes are visibly
unsupported, and edits within a single run of text are not supported.

An exact normalized paragraph match must be unique. Repeated clauses require a
`ParagraphLocation` with the SHA-256 of the original package and its zero-based
paragraph index in `word/document.xml`. A location still requires an exact full
anchor. Editing a different source version produces `stale_source`; it never
rebinds an old location to the new document. For synthesized documents the
location digest identifies the generated, unedited XML and the result is labeled
as reconstructed. Applied outcomes include the source digest and location.

The current writer supports split plain text runs and preserves paragraph
properties, including numbering and paragraph attributes. It refuses targets
with hyperlinks, bookmarks, character formatting, fields, previous revisions,
tabs or other unsupported inline structures. An untouched paragraph and all
other package parts retain their original content. Rejected proposals stay in
`unmatched`, with a per-edit reason in `edit_results`; the API, review memo and
upload result surface the need for manual review. Duplicate proposed edits to
one paragraph do not silently count as two applied changes.

Native Word and LibreOffice rendering and their accept/reject behavior are not
qualified. No reviewed document is automatically published or sent.
Archive/decompression bounds and the operator review workflow still apply.
