Compare the architecture of three open-source AI agent frameworks: OpenClaw (https://github.com/openclaw/openclaw), Hermes Agent (https://github.com/NousResearch/hermes-agent), and AutoGen (https://github.com/microsoft/autogen). Specifically:

1. Spawn a researcher for each framework. Each researcher should fetch the repo's README and AGENTS.md (or equivalent), identify the core agent loop, the sandboxing/execution backend(s), the skill/plugin model, and the safety story.
2. Have an analyst synthesize the three reports into a comparative table showing: language, agent loop style, sandbox backends, skill model, safety/guardrails, multi-channel support, long-horizon features (persistence, budget caps, recovery), and notable strengths and weaknesses.
3. A writer produces the final deliverable: a markdown file `report.md` in the workspace containing the table plus a 2-3 paragraph summary of where each framework shines.
4. The orchestrator verifies the report covers all three frameworks, the table is complete (no "unknown" cells for the core columns), and the file is at least 500 words.

Success criteria:
  - `report.md` exists in the workspace.
  - Contains a markdown table with the columns above.
  - At least 500 words total.
  - All three frameworks have non-empty rows.

Budget: $2, 20 minutes wall-clock.
