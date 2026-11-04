---
name: rag-pipeline-design
triggers:
  - rag
  - retrieval augmented
  - rag design
tools_needed:
  - knowledge_search
---
# What this skill does

Designs a retrieval-augmented-generation pipeline end to end: how source documents are chunked and indexed, how queries retrieve and rerank context, and how the generation step is grounded so answers cite sources and refuse when context is missing. Produces a concrete design naming the chunking strategy, embedding/index choice, retrieval parameters, and the grounding/citation contract — not a generic "use a vector DB" sketch.

# Steps

1. Characterize the corpus and queries with knowledge_search: document types and sizes, update frequency, expected query shapes (lookup vs synthesis), latency budget, and freshness needs. Record corpus scale and any access/permission constraints; do not assume a clean homogeneous corpus if you can't confirm it.
2. Design ingestion: chunking strategy (semantic/structural vs fixed-size with overlap) sized to the content, metadata to attach (source id, section, timestamp, ACL), and the embedding model + index. Specify how updates and deletes propagate so the index doesn't serve stale or removed documents.
3. Design retrieval: top-k, similarity metric, optional hybrid (dense + keyword/BM25) and a rerank stage, plus query transforms (rewrite/expansion) if queries are terse. Define the context budget — how many chunks fit the model window and how they are ordered and deduplicated.
4. Design grounded generation: a prompt that answers only from retrieved context, cites source ids inline, and returns an explicit "not found" when retrieval is empty or low-confidence. Hand off the design with an eval suggestion (retrieval hit-rate plus faithfulness/citation checks), and state assumptions and the safety boundary.

# Notes

The pipeline is wrong if it lets the model answer from parametric memory instead of retrieved context (hallucination/no citations), if chunking splits answers across boundaries so retrieval misses them, or if document ACLs aren't carried into the index (a user retrieves content they shouldn't see — treat this as a hard boundary, not an optimization). Grounding must fail closed: empty/low-confidence retrieval returns "not found," it does not guess. Recommend measuring with rag-pipeline-aware evals (use llm-eval-design) before trusting answers. Not for prompt-only tasks with no external corpus (use llm-prompt-design) or for monitoring a deployed system (use ml-monitoring-design).
