---
name: llm-prompt-design
triggers:
  - prompt design
  - prompt engineering
  - llm prompt
tools_needed:
  - knowledge_search
---
# What this skill does

Designs and hardens a production prompt for a specific LLM task. Produces a structured prompt (role, task, constraints, output schema), few-shot examples drawn from real cases, and explicit handling for the failure modes that task is prone to — refusals, malformed output, missing inputs, and injection. The deliverable is a copy-pasteable prompt plus the rationale for each section, not prose advice about prompting.

# Steps

1. Establish the task contract with knowledge_search: the exact input(s), the required output format (free text / JSON schema / enum), success criteria, hard constraints (tone, length, must-not-do), and the target model/role. Pull real example inputs from the knowledge base; do not fabricate examples that misrepresent the data.
2. Draft the prompt with a clear spine — role/persona, the task statement, enumerated constraints, and a precise output contract (give the literal JSON schema or label set when structured). Keep instructions imperative and ordered by priority so the model resolves conflicts predictably.
3. Add 2-4 few-shot examples grounded in real cases, including at least one edge/negative case (ambiguous input, missing field, out-of-scope request) showing the exact desired output. Specify the escape hatch: what the model emits when it cannot comply (e.g. a fixed `{"error": "..."}` or an explicit refusal string) so callers can parse failure.
4. Harden against the task's failure modes: pin output format to reduce drift, isolate untrusted user content from instructions (delimit and label it) to blunt prompt injection, and note any safety boundary. Hand off the prompt with a short eval suggestion and flag assumptions (model, temperature) that need confirmation.

# Notes

The prompt is wrong if the output contract is vague (callers can't parse it), if examples leak fabricated facts the model will imitate, or if untrusted user text shares the same channel as instructions (injection risk). Treat the prompt as a draft to be measured: recommend pairing it with llm-eval-design before trusting it in production, and never let a prompt alone gate an irreversible action — a human or a downstream check approves those. Not for choosing between models (use llm-eval-design) or for RAG context assembly (use rag-pipeline-design).
