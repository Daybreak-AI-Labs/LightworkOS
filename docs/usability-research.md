# Usability research: the in-product survey, moderated sessions and the tree test

This guide is for whoever runs Lightwork's usability measurement each quarter
(a researcher, designer or product manager acting as facilitator). It covers
three instruments and keeps the method the same every quarter, so changes in
the numbers mean real changes in the product:

1. the optional **in-product survey** (System Usability Scale each quarter, and
   one ease question after a few common tasks);
2. **moderated task sessions** with five or more people per role;
3. a **tree test** of the sidebar and page finder.

No results are recorded in this guide. Results live in the product (People >
Ease-of-use results) and in your session notes.

## 1. The in-product survey

Turn it on in **Settings > All settings > Privacy > Ask people how easy
Lightwork is to use**, or answer "yes" to the same question in `maverick init`.
It writes `[analytics] usability_survey = true` and is **off by default**.

What people see:

- **System Usability Scale (SUS).** Each signed-in person is offered the ten
  standard statements at most **once a quarter** (calendar quarters, UTC). It is
  a panel at the top of the page, never a dialog, and never takes focus. One
  **Not now** hides it for the rest of the quarter. People may say which role
  best describes their work (administrator, employee, approver, privacy,
  executive) or leave it blank.
- **Single Ease Question (SEQ).** After a person finishes one of these top tasks,
  one question asks "Overall, how difficult or easy was this task to
  complete?" on a 1 (very difficult) to 7 (very easy) scale, at most once a
  quarter per task:

  | Task | Persona | When it is asked |
  |---|---|---|
  | Get a finished result from a task you gave Lightwork | Employee | The task page saw the task finish |
  | Approve or reject a request | Approver | A decision was recorded on Approvals |
  | Change a setting | Administrator | All settings saved at least one change |
  | Invite a colleague | Administrator | An invitation link was created |

Privacy. Answers stay in this installation (`~/.maverick/usability-survey.json`,
readable only by the Lightwork account) and are never sent anywhere. A stored
answer holds the chosen role, the quarter and the answers, never a name or
account. To avoid asking a person twice, the file keeps a keyed one-way hash of
the account with the quarter it was asked in; reports never use it.

Results. **People > Ease-of-use results** (`/users/usability-survey`, global
administrators) shows, for the current quarter, the SUS mean per role and the
SEQ mean per task with a 95% confidence interval. A role or task with fewer than
**5 answers** shows "Not enough answers yet" and only its count. Add
`?quarter=2026-Q3` to see an earlier quarter.

### Scoring

SUS (Brooke 1996): each answer is 1 (strongly disagree) to 5 (strongly agree).
For statements 1, 3, 5, 7 and 9 take the answer minus 1; for statements 2, 4, 6,
8 and 10 take 5 minus the answer. Add the ten values and multiply by 2.5 to get
a score from 0 to 100. A SUS score is not a percentage.

SEQ (Sauro and Dumas 2009): the answer itself, 1 to 7.

Confidence interval: mean ± t × (sample standard deviation ÷ √n), with the
two-sided 95% Student t value for n − 1 degrees of freedom, clipped to the ends
of the scale.

Targets: SUS at least 80.3 for every role, with at least 30 answers per role
each quarter; SEQ mean at least 6.0 per task; task completion at least 90% (from
moderated sessions, below). For reference, the average SUS across 500 published
studies is 68, and the average SEQ is about 5.5.

## 2. Moderated task sessions

Run these each quarter with the same tasks and script. Five people per role
find most problems; recruit more if you want task-completion rates with
narrow intervals.

### Set-up

- A practice workspace with realistic but synthetic data (never live
  production data), and an account per participant with the role they use at
  work.
- Screen and audio recording with the participant's written consent. Say what
  is recorded, who sees it and when it is deleted.
- One facilitator and, if possible, one note-taker. The facilitator does not
  help with the task; the note-taker records times and observations.
- At least one session per quarter with a person who uses a screen reader,
  screen magnification or keyboard only, recruited and paid like everyone else.

### Script (read aloud)

> Thank you for helping. We are testing Lightwork, not you: if something is
> hard, that is what we need to learn. Please think aloud as you go — say what
> you are looking for and what you expect to happen. I will not be able to help
> during the tasks, but I will answer questions at the end. You can stop at any
> time. Is it all right to record the screen and your voice?

Before each task: read the task card aloud and hand it over. After each task:
ask the Single Ease Question ("Overall, how difficult or easy was this task to
complete?", 1 to 7). After all tasks: the ten SUS statements on paper or a form,
then an open conversation ("What was most confusing? What would you change?").

### Task cards (same every quarter)

| # | Role | Task card | Success when |
|---|---|---|---|
| 1 | Administrator | "You have just installed Lightwork. Connect the AI service your company uses with the key on this card." | The provider shows its key as saved |
| 2 | Administrator | "A new colleague, sam@example.test, joins today. Give them access so they can run work." | An invite link exists for that address with the Operator role |
| 3 | Administrator | "Stop any one task from spending more than $5." | The spending-per-task limit reads $5 |
| 4 | Employee | "Ask Lightwork to summarise this week's open approvals, and copy the answer." | The participant has the finished answer copied |
| 5 | Employee | "Change the time your daily summary arrives to 9 in the morning." | My work shows 9:00 |
| 6 | Approver | "A request is waiting for you. Decide whether it should go ahead, and say why if you reject it." | A decision is recorded |
| 7 | Privacy | "Someone asked for a copy of their data. Find the request and see when it is due." | The participant states the due date |
| 8 | Executive | "Find out how much Lightwork has spent this month." | The participant states the amount |

### What to record per task

- **Completion**: 1 if the success condition was met without help, otherwise 0
  (a hint from the facilitator counts as 0).
- **Time on task**: from handing over the card to the success condition, or to
  giving up.
- **SEQ**: the 1–7 answer.
- **Observations**: where the person hesitated, went the wrong way or said
  something was unclear, with the screen and time.

### Scoring the sessions

- Completion rate per task with an adjusted-Wald 95% interval (add 2 successes
  and 2 failures before computing the interval).
- Time on task: report the geometric mean for completed attempts (task times
  are skewed).
- SEQ mean per task and SUS per participant, scored as in section 1.
- List each problem once, with how many participants hit it and its severity:
  4 prevents the task, 3 causes a long delay or a wrong result, 2 causes
  hesitation, 1 is cosmetic.

## 3. Tree test of the navigation

A tree test checks whether people can find things in the sidebar and page
finder without the rest of the visual design.

Use the [tree-test kit](tree-test/README.md) as the authoritative protocol:

1. Compare the exported classic and areas trees in separate studies with
   different people. Recruit 15–20 people per role per tree.
2. Use the kit's 61 tasks (15 or 16 per role). Give each participant 8–10 of
   their role's tasks in random order, ensuring every task is seen by at
   least 10 people. Use the supplied answer keys.
3. Record success, directness, time and first click per task, role and tree,
   with confidence intervals for success rates.
4. Before enabling areas, require at least 70% overall success for each role,
   no task below 50%, and improvement over classic without lower directness
   or a materially worse task. Fix and retest failures with new participants.

## Sources

- Brooke, J. (1996). "SUS: A 'quick and dirty' usability scale." In P. W.
  Jordan, B. Thomas, B. A. Weerdmeester and I. L. McClelland (eds.), *Usability
  Evaluation in Industry*, 189–194. London: Taylor & Francis. (The ten
  statements and the scoring method.)
- Sauro, J. and Dumas, J. S. (2009). "Comparison of three one-question,
  post-task usability questionnaires." *Proceedings of CHI 2009*, 1599–1608.
  (The Single Ease Question.)
- MeasuringU, "Measuring Usability with the System Usability Scale (SUS)",
  https://measuringu.com/sus/ — average score 68; above 80.3 is the top 10%.
- MeasuringU, "10 Things to Know About the Single Ease Question (SEQ)",
  https://measuringu.com/seq10/ — average SEQ around 5.5.
- MeasuringU, "What Is a Good Task-Completion Rate?",
  https://measuringu.com/task-completion/ — average completion 78%.
