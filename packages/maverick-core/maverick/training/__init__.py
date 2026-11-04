"""Governed training and specialist-model improvement for Lightwork.

The package holds the trajectory donation flywheel, a learned what-to-keep
gate and process-reward training, plus the governance contracts around them.

Layout:

  __init__.py     (this file)
  schema.py       Klear-AgentForge-compatible trajectory schema
  ingest.py       Read donated trajectories from outbox + dedup + label
  export_texts.py Export proposer_texts.jsonl (raw transcripts from the
                  world model) for real-text DPO; keyed to ingest's ids.
  prm_train.py    Train an AgentPRM head from labeled trajectories
                  (arxiv:2511.08325 protocol; torch MLP head).
  prm_linear.py   Train a torch-free linear AgentPRM head (plain JSON,
                  CPU-only) loadable by maverick.prm.LinearPRM.
  rlaif.py        RLAIF / DPO loop on the proposer using verifier
                  rewards as the signal.
  environments.py Vendor-neutral deterministic tasksets, data boundaries,
                  and held-out evaluation contracts.
  specialist_models.py Evidence-labelled deployment-candidate catalog.
  qualification.py Exact artifact/runtime/hardware qualification policy.
  receipts.py     Tenant-private, externally verifiable training receipts.

The vendor-neutral environment, data-admission, qualification and receipt
layers are default-off. PRM_TRAIN implements the AgentPRM head trainer (torch optional
extra); RLAIF implements the preference-pair / DPO data pipeline (load_klear,
build_preference_pairs, reward + confidence scoring). Real specialist training
still requires customer-authorized data, a sealed holdout, GPU execution, and
human promotion authority; those facts are never inferred from this package
being installed.
"""

__all__ = [
    "environments",
    "export_texts",
    "ingest",
    "prm_linear",
    "prm_train",
    "qualification",
    "receipts",
    "rlaif",
    "schema",
    "specialist_models",
]
