# Use Lightwork

This guide follows the screens in an installed Lightwork workspace. Your menu
shows the areas your role can use; an administrator can also turn features on or
off for the workspace. If a button or page is unavailable, the screen should
explain what access or setup is missing. Start at **Get started** (`/start`) if
this is your first visit.

## Take a piece of work from request to result

1. Open **Chat** (`/chat`) and describe the outcome you need. Add the source
   material, constraints, intended audience, and what a useful answer must
   contain. Use **Add details** for longer instructions and **Attach files**
   when the work depends on documents. An attached file is available to the
   task; attaching it alone does not prove the worker read or used it.
2. Leave **What should Lightwork create?** on **Run this task** for a one-off
   request. **Draft a workflow** and **Draft an agent** create drafts for you
   to review; they do not silently put a new process into service. If you need
   a spending boundary, open **Check budget before starting** and review the
   task limit shown below the composer before pressing **Start task**.
3. The conversation opens at `/chat/goal/<task number>`. Watch the current
   status and work log. If Lightwork asks a question, answer it in that
   conversation; a task waiting for your answer cannot move on by itself. You
   can add guidance or request **Stop** while work is open. Stop takes effect
   after the current step; it does not undo changes already made elsewhere.
4. When the task finishes, read the saved answer and check it against your
   request and source material. The answer menu provides **Copy answer**,
   **Print conversation**, and, when permitted, **Download answer**. **More**
   includes full-history export and **Review share link** for an eligible
   finished result. Check the exact content and expiry before creating a link:
   anyone holding it can read the reviewed content until it expires or you
   revoke it. A forwarded or downloaded copy cannot be recalled.

**Tasks** (`/goals`) is the place to find work that is running, paused, failed,
or waiting for attention. A failed or paused task is not a finished result.
Open it to read the reason and the next available action; **Try again** is
shown when a new attempt is allowed. **Results** (`/deliverables`) lists your
finished tasks with saved answers, plus work awaiting sign-off. Open a result
to review its full conversation before using it outside Lightwork. If no
result appears, check **Tasks** for its current state rather than assuming it
has finished. Older finished work can be reached with the page controls in
**Results**.

You can ask **Copilot** for your running tasks, what needs your approval, or
why a selected task failed. It uses the access you have in the current
workspace. For a decision or a saved answer, open the linked task or review
page and confirm the current record there.

## Make a decision when work pauses

Open **Approvals** (`/approvals`) for requests assigned or available to your
review role. Read the proposed action, what it changes, and the before/after
preview. Choose **Approve**, **Reject**, or **Send back for changes**; the
review screen asks for confirmation or a note where needed. A flow request
uses **Review and decide** to open that run's current approval card. The run
checks your access and the exact proposed operation again when you decide.

If an approval says its details need a fresh review, do not approve an old
card. Refresh or request a new one. Some employee content needs a separate,
exact content-access review before you can read it; that access does not grant
permission to vote. If the page says some flow approvals could not be
checked, inspect the linked runs or refresh. An empty visible list in that
state is not proof that every approval is clear.

## Reuse a good process

Open **Workflows** (`/workflows`) to see three different kinds of saved work:

| If you need | Use | What to expect |
| --- | --- | --- |
| A reusable task instruction | **New workflow** | Build a template, then use it from Chat or arrange a schedule or trigger when those features are available. |
| Connected steps with decisions or repetition | **New flow** | Use the visual designer, review each step and its required inputs, then inspect the run. A flow approval step pauses for a person. |
| Instructions for an agent you build | An **agent playbook** | It guides the agent; a sentence telling it to seek review does **not** create a flow approval gate. |

The **Workflows** list shows saved flows, templates, and playbooks. **Edit** opens
the relevant builder; **Use** starts a template in Chat. A flow can be turned
off or deleted from **More** after review. If flows are turned off, the page
shows who can enable them. Ask Copilot to explain the steps while you are in
the designer, but check the saved definition and the run before relying on it.

## Choose a specialist or create an agent

A **specialist** is one of Lightwork's own built-in job specialists. Anything
else, such as an agent built in your workspace or an outside agent you connect,
is an **agent**. A specialist you have tailored is still a specialist, marked
**Customized**.

**Agent Factory** (`/agents`) shows the available agents and specialists and
their job cards. Choose an existing specialist first when its remit fits the
work. You can use **Hire from a job description** to find a match, **Set up an
agent for your business** to review a draft, or **New custom agent** to create
one. The instructions, model, and allowed actions of an agent or specialist
determine what it can attempt; workspace permissions, spending limits, and
approvals still apply. Saving an agent or specialist does not prove that it can reach every external
system or that its output is correct. Run a bounded real task and review the
result before making it part of a repeatable process.

## Connect a service and control access

An administrator uses **Connections** (`/connections`) to connect an account
by signing in or to save a service key. For a key-based connection, choose a
service, give the connection a recognizable name, and use **Save & test** to
check it. The key is encrypted when saved and is not shown again. Review **Who
can use it, and other settings** before sharing it with the workspace or named
people. Sign-in-based connections appear on the same page.

A saved connection is not permission for every workflow to use it. The
workflow must select the connection, and the person's access and product
controls still apply. A successful connection check confirms the check it
performed at that time, not every future service call. If a workflow cannot
reach a service, return to **Connections**, inspect its current status, test
it, and then retry the original work from its own page. The page flags tools
that are unavailable in Enterprise mode even when a connection is saved.

## Manage people, settings, and recovery

Administrators use **Users** (`/users`) to invite people and assign roles.
Start someone with the least role they need and review department access
before giving wider authority. Administrator access to settings does not by
itself open another employee's private task text; use the separate content
access review when appropriate.

In **Settings** (`/settings`), use the named sections for appearance, models,
connections, features, access, and maintenance. Each section saves on its own;
check the confirmation before leaving. **All settings** (`/settings/all`)
contains the remaining controls. Review **Spending per task** and the model
choice before starting costly work. **Check readiness**, **Run health check**,
and **Check services** help identify missing setup. **Your notifications**
lets a named person choose private task alerts; the shared organization alert
channel is a separate setting. **Activity log** shows who changed a setting,
but its change record does not show the old and new values.

**Workspace recovery** (`/workspace/recovery`) is an administrator area and
is off unless enabled. Create and download a recovery key, keep it separately,
then create a snapshot, use **Check snapshot**, and **Download snapshot** to
keep an off-device copy. Use **Test restore safely** and read its saved report
before depending on a copy. A snapshot
can contain sensitive workspace data and is not itself encrypted. It does not
replace a separate copy of shared encryption keys or a plan for outside
services. Restoring the live workspace requires the dedicated recovery mode
and a fresh, reviewed safety copy; the ordinary dashboard cannot silently
replace live work. A successful temporary test checks files and storage
integrity, not every business outcome or external action.

If you are stuck, use **Help** (`/help`) to prepare a redacted support report,
and include the task or page link, the visible state, and what you expected to
happen. Do not paste secret keys or another person's private work into a
support request.
