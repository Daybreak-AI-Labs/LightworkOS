Plan a multi-step learning curriculum and write it to a file.

Goal: Produce a personalized 8-week curriculum for learning Rust, written to `curriculum.md` in the workspace.

The curriculum must:

1. Open with a one-paragraph diagnostic: what kind of background the learner has and what gaps the plan addresses.
2. Break into 8 weekly modules. Each module has:
   - Topic title and 1-line objective
   - 2-4 concrete resources (book chapters, free online courses, RustLings exercises, documentation pages with URLs)
   - 1 implementation project (small but real, with a success criterion)
   - 1 self-check question
3. End with a `Capstone` section: a 2-week project the learner builds after week 8 that integrates everything.
4. Include a `Realistic Time Commitment` section that estimates hours/week.

Multi-agent decomposition the orchestrator should consider:
  - A researcher gathers current best-in-class Rust resources (the Rust Book, RustLings, Jon Gjengset's videos, etc.)
  - A writer drafts each week.
  - An analyst checks for gaps and progression -- does Week 3 build on Week 2? Are async and ownership in the right order?
  - A revisor re-runs if the analyst finds gaps.

Success criteria:
  - `curriculum.md` exists.
  - Contains exactly 8 weekly modules + a Capstone + a Realistic Time Commitment.
  - Each module has all four required sub-sections.
  - Total length 1500-3000 words.
  - At least 12 URLs to specific resources.

This stresses long-horizon planning AND multi-agent coordination AND revision loops -- the long-horizon work Lightwork targets.

Budget: $4, 40 minutes wall-clock.
