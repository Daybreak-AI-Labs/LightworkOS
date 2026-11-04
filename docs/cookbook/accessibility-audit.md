# Recipe: HTML accessibility audit

Audit an HTML template/page for the common, high-impact a11y issues.

## Goal text

```
Audit <PATH/TO/page.html or template> for accessibility:
  1. Check the high-impact rules: images without alt, inputs without labels,
     buttons/links without accessible names, missing lang on <html>, heading
     order skips, color-only meaning, and non-focusable interactive elements.
  2. For each issue: the element, the rule it breaks (WCAG ref), and the fix.
  3. Apply the safe, unambiguous fixes (alt="", labels, aria-label) and leave
     the judgment calls (color contrast values) as flagged TODOs.
Output the findings table + the diff.
```

## Tools used

`read_file`, `apply_patch`.

## Expected runtime

~1-2 min. Budget-cap $1.
