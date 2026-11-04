---
name: idp-pipeline-design
triggers:
  - design an idp pipeline
  - document extraction
  - ocr pipeline
tools_needed:
  - knowledge_search
---
# What this skill does

Designs an intelligent document-processing (IDP) pipeline for a defined document class: ingestion, classification, OCR/extraction, validation, human-in-the-loop review, and structured output to a downstream system. Produces a stage-by-stage design with field schemas, confidence thresholds, and HITL gates.

# Steps

1. Profile the document class from real samples — layout type (structured form, semi-structured invoice, unstructured letter), languages, volume, and quality (scans vs native PDF). Pull any existing field dictionary or downstream schema via knowledge_search. Note sample size and tag traits you inferred rather than observed.
2. Design the pipeline stages in order: ingest/normalize, classify (route by doc type), extract (OCR + key-value/table extraction), and define the target field schema with type, required/optional, and source location per field.
3. Define validation and HITL gates: per-field confidence thresholds, cross-field business rules (totals reconcile, dates plausible, format/checksum), and lookup validations against master data. Route low-confidence or rule-failing extractions to a human review queue; specify what the reviewer sees and corrects, and how corrections feed back.
4. Specify outputs and operations: structured payload + schema to the downstream system, exception/reject handling, retention/PII handling, and accuracy/STP-rate metrics with a target. Report the design, the assumed thresholds (to be tuned on a labeled set), and data-protection boundaries; recommend a pilot before full rollout.

# Notes

The design is wrong when confidence thresholds are stated as final rather than starting points — they must be calibrated on a labeled holdout set, so present them as tunable. Never design straight-through processing with no HITL gate for documents that drive financial or legal action; a human must clear low-confidence and rule-failing cases. Account for PII early — extracted document data is frequently sensitive and may carry residency/retention constraints. Skip this skill for a one-off handful of documents where manual entry is cheaper than building a pipeline. Accuracy claims are unverified until measured on real samples.
