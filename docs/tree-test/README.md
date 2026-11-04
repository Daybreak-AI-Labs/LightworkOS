# Tree test: classic sidebar vs job-named areas

Lightwork has two sidebars. **Classic** (the default) lists pages in their
functional groups. **Areas** puts every page in one of nine job-named areas (Home, Work,
Agents, Rules & safety, Privacy, Risk & compliance, Evidence & audit, Costs &
value, Settings), plus the Ask button and the account and help menus. Areas
stays off (`[dashboard] navigation = "classic"`) until people have shown,
in a tree test, that they find things faster with it.

A tree test shows people a bare text menu, without the product's design, and
asks where they would go to do a task. It measures the structure and the
labels alone. This kit has everything needed to run one; it ships without
results.

## What is in this folder

| File | What it is |
|---|---|
| `classic-tree.txt`, `classic-tree.csv` | The classic tree, exported from the page registry |
| `areas-tree.txt`, `areas-tree.csv` | The areas tree, exported from the same registry |
| `tasks.csv` | 61 tasks: 15 or 16 for each of Employee, Approver, Privacy officer and Admin, each with its correct page addresses |
| `answers-classic.csv`, `answers-areas.csv` | Each task's correct node(s) in each tree |
| `results-template.csv` | One row per task, tree and role, for the results |

The `.txt` files are tab-indented, one node per line: paste them into a
tree-testing tool such as Optimal Workshop Treejack ("paste your tree").
The `.csv` files have one row per leaf (Level 1, Level 2, Level 3, Address)
for tools that import a spreadsheet.

Regenerate everything after the registry changes (a test fails until you do):

```
python -m maverick_dashboard.nav_tree --export classic > docs/tree-test/classic-tree.txt
python -m maverick_dashboard.nav_tree --export classic --format csv > docs/tree-test/classic-tree.csv
python -m maverick_dashboard.nav_tree --export areas > docs/tree-test/areas-tree.txt
python -m maverick_dashboard.nav_tree --export areas --format csv > docs/tree-test/areas-tree.csv
python -m maverick_dashboard.nav_tree --export classic --answers docs/tree-test/tasks.csv > docs/tree-test/answers-classic.csv
python -m maverick_dashboard.nav_tree --export areas --answers docs/tree-test/tasks.csv > docs/tree-test/answers-areas.csv
```

`--role admin|operator|auditor|viewer` exports the tree one built-in role
sees out of the box, if you want each group to see only its own pages.

**One bias to know about.** The classic export lists every page under its
group, including pages that the classic sidebar folds away (they are reachable
only from other pages or by search). That makes the classic tree look
easier than the product is. If areas still wins, the result is safe.

## Study design

- **Two studies per role, different people.** Run the classic tree and the
  areas tree as separate studies with separate participants
  (between-subjects), so nobody learns one tree from the other.
- **Recruit 15 to 20 people per role per tree** (so 30 to 40 per role in
  all). Recruit real or likely users: employees who give work to Lightwork,
  people who approve, privacy officers, and administrators. Screen out
  anyone who has used Lightwork's sidebar in the last three months.
- **Give each person 8 to 10 of their role's tasks**, in random order. Keep
  every task in the study so each one is seen by at least 10 people.
- Allow one "skip" per task. Do not show the correct answer afterwards.
- In the tool, mark every node listed in `answers-<tree>.csv` as correct.
  When a task lists more than one, any of them counts.

## Facilitator script (unmoderated, shown on screen)

1. "Thank you for helping. We are testing how a product's menu is organised,
   not testing you. There are no wrong answers."
2. "You will see a list of menu labels. For each task, click through the
   menu to where you would expect to do it, then choose *I'd find it here*."
3. "Go with your first instinct. If you can't decide, choose your best
   guess. You can skip a task if you really have no idea."
4. "This takes about 10 minutes."
5. After the tasks: "Was anything confusing? Which labels were unclear?"
   (free text, optional).

For moderated sessions, read the same words, stay silent during each task,
and note where the person hesitates or goes back.

## What to measure

- **Success rate**: the share of people who ended on a correct node.
- **Directness**: the share of successful people who got there without
  going back up the tree.
- **Time**: the median seconds per task.
- **First click**: the top-level label chosen first; a wrong first click
  shows a label problem even when people recover.

Report each per task, per role and per tree. With 15 to 20 people, give each
success rate with a 95% confidence interval (adjusted Wald); differences
smaller than the intervals are not differences.

## Recommended bar for switching areas on

This is guidance for the decision, not a rule the product enforces:

1. On the **areas** tree, overall task success is **at least 70%** for every
   role, and **no task is below 50%**.
2. Areas is **better than classic** overall for every role (higher success,
   and not lower directness), and no task does markedly worse on areas than
   on classic.
3. Any task that misses the bar gets its labels or placement fixed in the
   registry (`ui_visibility.PAGE_AREAS` and `AREAS`), and that role is tested
   again with new people before switching.

When the bar is met, an administrator can set `[dashboard] navigation =
"areas"` in Settings > All settings or with the setup wizard. Until then,
`navigation_personal = true` lets volunteers try it for themselves in Your
preferences.

## Results

Copy `results-template.csv`, add one row per study, tree, role and task, and
keep the tool's raw export beside it. Write down the date, the tool, how
people were recruited, and how many started and finished.
