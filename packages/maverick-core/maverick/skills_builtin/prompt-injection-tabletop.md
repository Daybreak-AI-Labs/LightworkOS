---
name: prompt-injection-tabletop
triggers:
  - prompt-injection tabletop
  - agent injection exercise
  - test injection response
  - injection drill
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Drives a tabletop exercise for prompt-injection-as-supply-chain — a poisoned document leads to a tool call leads to data exfiltration — mapping each stage to OWASP LLM Top 10 and MITRE ATLAS, comparing the expected Shield / quarantine response to the actual one, and logging the gaps. The goal class is "rehearse and stress-test the agent's defenses against indirect prompt injection" on paper before it happens for real.

# Steps

1. Read the agent architecture and current defenses with read_file (Shield rules, tool-permission model, quarantine/isolation behavior) and pick a concrete injection scenario: e.g. an attacker plants instructions in a document the agent will ingest, aiming to trigger an unauthorized tool call and exfiltrate secrets.
2. Walk the kill chain stage by stage: ingestion of poisoned content, the injected instruction overriding intent, the malicious tool invocation, and the exfil attempt. Map each stage to the relevant OWASP LLM Top 10 category and MITRE ATLAS technique via knowledge_search.
3. At each stage, state the EXPECTED control response (Shield should flag/strip the injected instruction; the budget/permission gate should block the unscoped tool; egress redaction should catch the secret) and compare it to what the system would ACTUALLY do today.
4. Log every gap where the expected control is missing or weaker than assumed, rate it by exploitability and impact, and produce a prioritized remediation list and an updated detection idea for each gap.

# Notes

Indirect injection is a supply-chain problem: the malicious instruction rides in on trusted-looking data (a document, a web page, a tool result), so defenses that only inspect the user's direct prompt miss it entirely — the tabletop must trace content from untrusted sources all the way to actions. Assuming the Shield catches everything is the failure this exercise exists to expose; test the assumption, do not assert it. Map to OWASP LLM and MITRE ATLAS so findings are communicable and comparable. This is a paper exercise that produces a gap log and remediation plan; it must NOT actually execute an exfiltration or attack against live systems.
