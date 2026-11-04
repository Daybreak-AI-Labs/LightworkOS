---
name: prompt-injection-review
triggers:
  - prompt injection
  - llm security
  - jailbreak review
tools_needed:
  - knowledge_search
---
# What this skill does

Reviews an LLM-backed application (agent, RAG, chatbot, tool-using assistant) for prompt-injection and jailbreak risk. Produces a structured review enumerating the untrusted-input attack surface, ranked injection scenarios, and concrete mitigations mapped to each entry point. Output is a recommendation document, not a code change.

# Steps

1. Inventory every place untrusted content reaches the model: user messages, retrieved documents/RAG chunks, tool/function call results, web-fetched pages, file contents, email/ticket bodies, and upstream agent output. For each, note whether it is concatenated into the system prompt, a user turn, or a tool result.
2. For each surface, enumerate concrete attack scenarios grounded in the real app — direct jailbreak, indirect injection via retrieved/fetched data, tool-output poisoning, system-prompt leak, and exfiltration via tool calls (e.g. attacker text instructing the agent to send data outward). Do not invent surfaces the app does not have; mark anything you could not confirm in the codebase as "unverified — needs confirmation."
3. Use knowledge_search to pull current guidance (OWASP LLM Top 10, vendor hardening notes) and map each scenario to a named risk class and a mitigation: input/output separation and delimiting, least-privilege tool scoping, allow-listed actions, human-in-the-loop for irreversible/outbound actions, content provenance tagging, and output filtering. Cite each source.
4. Rank scenarios by likelihood x impact, then report: attack-surface table, ranked scenarios, mitigation per scenario, and residual risk. State assumptions (threat model, trust boundaries) and hand off as a recommendation for a human to prioritize.

# Notes

Output is wrong if it asserts a control exists without grounding it in the actual code/config, or if it treats RAG/tool output as trusted. Indirect injection (poisoned retrieved data) is the most-missed surface — always check it. Never claim the app is "secure"; report residual risk. All mitigations are recommendations: do not auto-apply guardrail changes, loosen tool permissions, or disable filters — a human owns those decisions. Not for general code-quality review or for non-LLM input validation (use a standard appsec pass instead).
