---
name: ml-paper-summary
triggers:
  - summarize this paper
  - explain the key contribution of
  - tldr this arxiv
  - what does this research show
tools_needed:
  - read_file
  - write_file
  - spawn_subagent
---

# What this skill does

Summarize an ML / AI research paper at three levels of depth so the
reader can pick the one that matches their time budget.

# Steps

1. Read the paper (PDF, markdown, or text via `read_file`).
2. Spawn a sub-agent with role=analyst to extract:
   - The problem being addressed
   - Prior work / baseline
   - The proposed method (in ONE sentence)
   - Results table -- what beat what, by how much
   - Limitations the authors acknowledge
   - Limitations they DON'T acknowledge
3. Write three nested summaries:
   - **30-second**: 2-3 sentences. What and why.
   - **3-minute**: 4-6 paragraphs. Add method + key result + caveat.
   - **30-minute**: structured, with the actual tables and one or two
     equations preserved.
4. End with FINAL: the 30-second + a pointer to the file with all three.

# Notes

- The honest limitations section is the most valuable -- spend a sub-
  agent's full budget on it.
- If the paper has a GitHub link, check whether claimed results are
  reproducible from the public code.
- Avoid AI-speak: "leverages", "furthermore", "in conclusion". Plain.
