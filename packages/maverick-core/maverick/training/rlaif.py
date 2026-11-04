"""RLAIF / DPO loop on the proposer using verifier rewards as the signal.

This is the third stage of the training flywheel (after ``ingest`` and
``prm_train``). The idea, in one line: the *verifier* is the AI feedback
in "RL from AI Feedback" — instead of asking a human which of two
proposer attempts is better, we ask "which attempt did the verifier
reward more?" and use that as the DPO preference label.

Pipeline
--------
1. ``ingest`` writes Klear-format JSONL (one row per trajectory) with a
   ``terminal_reward`` (the verifier's final score) and a
   ``meta.verifier_confidence``.
2. This module groups trajectories by ``task_family`` and, within a
   group, pairs a higher-reward attempt (``chosen``) against a
   lower-reward attempt (``rejected``) whenever the reward gap is wide
   enough to be a trustworthy preference signal.
3. Those pairs feed a textbook DPO objective that nudges the proposer
   toward the ``chosen`` continuations and away from the ``rejected``
   ones.

Operator usage::

    python -m maverick.training.rlaif \\
        --data trajectories.jsonl \\
        --base-model <hf-id-or-path> \\
        --out ./proposer_dpo \\
        [--beta 0.1 --epochs 1 --lr 5e-7 --min-margin 0.5 --max-pairs 32]

Honest limitations
------------------
* The pure pair-construction (``load_klear`` / ``build_preference_pairs``)
  is unit-tested and has no heavy dependencies.
* The actual ``train`` loop LAZILY imports ``torch`` + ``transformers``
  and requires a GPU plus a real base model. It is NOT exercised by the
  test suite — see ``train``'s docstring.
* Klear rows do NOT carry the raw proposer text (the ``messages`` array
  is hashed/structural to avoid leaking PII). Real DPO needs the actual
  prompt/response token strings, which live operator-side. An operator who
  holds those logs supplies them via a ``--text-sidecar`` (id -> text map,
  see ``load_text_sidecar``/``attach_pair_texts``); with
  ``--require-real-text`` the loop trains ONLY on real text and refuses the
  stand-in. Without a sidecar it falls back to a *structural* sequence
  string from message ``role``/``type``/``name`` (``trajectory_to_text``),
  logging a one-time warning — enough to wire the plumbing, not to trust the
  result.

The kernel never imports this module's heavy deps; ``torch`` /
``transformers`` are optional and only touched inside ``train``.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from heapq import heappop, heappush
from pathlib import Path

log = logging.getLogger(__name__)
_warned_structural = False

# ---------------------------------------------------------------------------
# Pure, unit-testable helpers (no torch / transformers).
# ---------------------------------------------------------------------------


def load_klear(path: str | Path) -> list[dict]:
    """Read a Klear-format JSONL file (one trajectory per line).

    Blank lines and lines that fail to parse as JSON are skipped so a
    truncated final write doesn't abort a long training run.
    """
    rows: list[dict] = []
    with Path(path).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def trajectory_to_text(row: dict) -> str:
    """Reconstruct a structural sequence string for a trajectory row.

    LIMITATION (read this before trusting the output): Klear rows store
    ``messages`` as a *hashed/structural* summary (role + action type +
    tool name + observation hash) precisely so raw observations never
    enter the training corpus. Real DPO needs the actual proposer
    prompt/response *text*, which is operator-side data not present here.

    As a documented stand-in we join the structural fields into a single
    line per message, e.g. ``planner/think | observer/tool_call:grep``.
    This is enough to (a) keep chosen/rejected attempts distinguishable
    and (b) wire the DPO plumbing end-to-end, but an operator running
    real RLAIF MUST replace this with the raw text join from their own
    proposer logs.
    """
    parts: list[str] = []
    for m in row.get("messages", []) or []:
        role = m.get("role", "") or ""
        atype = m.get("type", "") or ""
        name = m.get("name", "") or ""
        token = f"{role}/{atype}"
        if name:
            token += f":{name}"
        if m.get("error"):
            token += "!err"
        parts.append(token)
    return " | ".join(parts)


# ---------------------------------------------------------------------------
# Real proposer-text resolution (operator-side; the donated corpus is PII-safe
# by design, so raw text comes from an operator side-channel keyed by id).
# ---------------------------------------------------------------------------


def load_text_sidecar(path: str | Path) -> dict[str, str]:
    """Load an operator-supplied map ``trajectory_id -> raw proposer text``.

    The donated/ingested Klear corpus deliberately stores hashed/structural
    messages (no raw observations) to keep it PII-free. An operator who HOLDS
    the raw proposer logs supplies them here, out-of-band, so real DPO can run
    on real text without ever putting that text in the shared corpus.

    Accepts either a JSON object ``{"<id>": "<text>", ...}`` or JSONL of
    ``{"id": "<id>", "text": "<text>"}`` rows. Malformed lines are skipped.
    """
    raw = Path(path).expanduser().read_text(encoding="utf-8")
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    # Prefer the JSONL-records form first: a SINGLE {"id","text"} line is also
    # valid JSON-as-a-whole, so checking the object form first would misread one
    # record as an {id: text} map. Records form = every line is an object with
    # an "id" and a string "text".
    recs: list[dict] = []
    jsonl_ok = bool(lines)
    for ln in lines:
        try:
            rec = json.loads(ln)
        except json.JSONDecodeError:
            jsonl_ok = False
            break
        if isinstance(rec, dict) and "id" in rec and isinstance(rec.get("text"), str):
            recs.append(rec)
        else:
            jsonl_ok = False
            break
    if jsonl_ok and recs:
        return {str(r["id"]): r["text"] for r in recs}
    # Object form: the whole file is a {id: text} map.
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            return {str(k): str(v) for k, v in obj.items() if isinstance(v, str)}
    except json.JSONDecodeError:
        pass
    # Lenient JSONL: skip malformed lines, keep {"id","text"} rows.
    out: dict[str, str] = {}
    for ln in lines:
        try:
            rec = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue
        rid, txt = rec.get("id"), rec.get("text")
        if rid is not None and isinstance(txt, str):
            out[str(rid)] = txt
    return out


def row_text(
    row: dict, sidecar: dict[str, str] | None = None, *, text_field: str = "text",
) -> str | None:
    """Resolve the REAL proposer text for a trajectory row, or None.

    Precedence: operator ``sidecar[id]`` > an inline ``row[text_field]`` string
    (if the operator chose to embed it) > a join of per-message ``content`` /
    ``text`` fields (likewise opt-in). Returns None when no real text exists,
    so callers can decide whether to drop the pair or fall back to the
    structural stand-in. NEVER returns the stand-in itself.
    """
    rid = row.get("id")
    if sidecar and rid is not None:
        hit = sidecar.get(str(rid))
        if isinstance(hit, str) and hit.strip():
            return hit
    inline = row.get(text_field)
    if isinstance(inline, str) and inline.strip():
        return inline
    parts = [
        str(m.get("content") or m.get("text") or "")
        for m in (row.get("messages") or [])
    ]
    parts = [p for p in parts if p.strip()]
    return "\n".join(parts) if parts else None


def attach_pair_texts(
    pairs: list[dict], rows_by_id: dict[str, dict], *,
    sidecar: dict[str, str] | None = None, text_field: str = "text",
    require_real: bool = False,
) -> tuple[list[dict], int]:
    """Populate ``chosen_text``/``rejected_text`` on pairs from real text.

    Returns ``(kept_pairs, dropped)``. When ``require_real`` is set, any pair
    missing real text for EITHER attempt is dropped (so the DPO loop never
    trains that pair on the structural stand-in); otherwise the text is
    attached when available and the pair is kept regardless. Input pairs are
    not mutated -- copies are returned.
    """
    kept: list[dict] = []
    dropped = 0
    for p in pairs:
        ct = row_text(rows_by_id.get(p.get("chosen_id"), {}) or {}, sidecar,
                      text_field=text_field)
        rt = row_text(rows_by_id.get(p.get("rejected_id"), {}) or {}, sidecar,
                      text_field=text_field)
        if require_real and (not ct or not rt):
            dropped += 1
            continue
        q = dict(p)
        if ct:
            q["chosen_text"] = ct
        if rt:
            q["rejected_text"] = rt
        kept.append(q)
    return kept, dropped


def build_preference_pairs(
    rows: list[dict],
    *,
    min_margin: float = 0.5,
    max_pairs_per_group: int = 32,
) -> list[dict]:
    """Build DPO (chosen, rejected) preference pairs from verifier rewards.

    The verifier's ``terminal_reward`` IS the AI feedback: within a
    ``task_family`` group, any attempt that out-scored another by at
    least ``min_margin`` becomes a (chosen, rejected) pair. Pairing only
    happens *within* a family so we never compare apples (a SWE task) to
    oranges (a research task).

    Args:
        rows: Klear-format trajectory dicts (see ``load_klear``).
        min_margin: Minimum ``terminal_reward`` gap for a pair to count.
            Gaps below this are treated as noise and dropped.
        max_pairs_per_group: Cap on pairs emitted per ``task_family`` to
            avoid the O(n^2) blowup of all-vs-all pairing. We keep the
            ``max_pairs_per_group`` widest-margin pairs (largest, most
            confident preferences first).

    Verifier confidence handling:
        ``meta.verifier_confidence`` is folded into each pair as a
        ``weight`` = mean of the two attempts' confidences (in [0, 1],
        defaulting to 1.0 when absent). It is ALSO the tie-breaker for
        the per-group cap: among pairs with equal reward margin, the
        higher-confidence pair is kept. A DPO trainer can multiply each
        pair's loss by ``weight`` so low-confidence verifier judgements
        contribute proportionally less.

    Returns:
        A list of dicts, each::

            {
              "task_family", "chosen_id", "rejected_id",
              "chosen_reward", "rejected_reward", "margin", "weight",
            }

        sorted by descending ``margin`` then descending ``weight``.
    """
    # Group by task_family, skipping rows with a missing/empty family.
    groups: dict[str, list[dict]] = {}
    for r in rows:
        fam = r.get("task_family")
        if not fam:  # None or "" -> can't trust cross-family comparisons.
            continue
        groups.setdefault(fam, []).append(r)

    if max_pairs_per_group <= 0:
        return []

    pairs: list[dict] = []
    for fam, members in groups.items():
        if len(members) < 2:
            continue

        # Sort once by reward so each high-reward row can be paired with
        # progressively lower-reward rows.  A max-heap over those per-row
        # streams lets us keep only the configured cap instead of building
        # and sorting every all-vs-all candidate for large task families.
        ranked = sorted(
            ((_reward(member), member) for member in members),
            key=lambda item: (-item[0], _confidence(item[1])),
        )
        heap: list[tuple[float, float, int, int]] = []
        last = len(ranked) - 1
        for i, (high_reward, high) in enumerate(ranked[:-1]):
            low_reward, low = ranked[last]
            margin = high_reward - low_reward
            if margin < min_margin:
                continue
            weight = (_confidence(high) + _confidence(low)) / 2.0
            heappush(heap, (-margin, -weight, i, last))

        group_pairs: list[dict] = []
        while heap and len(group_pairs) < max_pairs_per_group:
            _neg_margin, _neg_weight, i, j = heappop(heap)
            high_reward, high = ranked[i]
            low_reward, low = ranked[j]
            group_pairs.append(_preference_pair(fam, high, low, high_reward, low_reward))

            next_j = j - 1
            if next_j <= i:
                continue
            next_low_reward, next_low = ranked[next_j]
            next_margin = high_reward - next_low_reward
            if next_margin < min_margin:
                continue
            next_weight = (_confidence(high) + _confidence(next_low)) / 2.0
            heappush(heap, (-next_margin, -next_weight, i, next_j))

        pairs.extend(group_pairs)

    pairs.sort(key=lambda p: (p["margin"], p["weight"]), reverse=True)
    return pairs


def _reward(row: dict) -> float:
    """Terminal reward for sorting and margin calculations."""
    return float(row.get("terminal_reward", 0.0) or 0.0)


def _preference_pair(
    fam: str,
    chosen: dict,
    rejected: dict,
    chosen_reward: float,
    rejected_reward: float,
) -> dict:
    """Create one verifier-reward preference pair."""
    conf_c = _confidence(chosen)
    conf_r = _confidence(rejected)
    return {
        "task_family": fam,
        "chosen_id": chosen.get("id"),
        "rejected_id": rejected.get("id"),
        "chosen_reward": chosen_reward,
        "rejected_reward": rejected_reward,
        "margin": chosen_reward - rejected_reward,
        "weight": (conf_c + conf_r) / 2.0,
    }


def _confidence(row: dict) -> float:
    """Verifier confidence for a row, clamped to [0, 1], default 1.0."""
    meta = row.get("meta") or {}
    try:
        c = float(meta.get("verifier_confidence", 1.0))
    except (TypeError, ValueError):
        return 1.0
    return max(0.0, min(1.0, c))


def resolve_pair_text(
    pair: dict, key: str, *, rows_by_id: dict[str, dict] | None = None,
    text_sidecar: dict[str, str] | None = None, require_real_text: bool = False,
    allow_structural_fallback: bool = True,
) -> str:
    """The text for one side of a pair: cached ``{key}_text`` > real text via
    ``row_text`` > structural stand-in (only when allowed). Raises if real text
    is required but absent. Shared by the full-param and LoRA training paths."""
    cached = pair.get(f"{key}_text")
    if cached:
        return cached
    rid = pair.get(f"{key}_id")
    real = row_text((rows_by_id or {}).get(rid, {}) or {}, text_sidecar)
    if real:
        return real
    if require_real_text or not allow_structural_fallback:
        raise ValueError(
            f"no real proposer text for {key} attempt {rid!r}; supply a "
            "--text-sidecar (or unset --require-real-text to train on the "
            "structural stand-in)."
        )
    global _warned_structural
    if not _warned_structural:
        log.warning(
            "RLAIF: training on the STRUCTURAL STAND-IN text (no real proposer "
            "text supplied); pass --text-sidecar for real DPO."
        )
        _warned_structural = True
    if rows_by_id is None:
        raise ValueError("rows_by_id required to recover text")
    return trajectory_to_text(rows_by_id[rid])


def pairs_to_dpo_rows(
    pairs: list[dict], *, rows_by_id: dict[str, dict] | None = None,
    text_sidecar: dict[str, str] | None = None, require_real_text: bool = False,
    allow_structural_fallback: bool = True,
) -> list[dict]:
    """Resolve each pair to ``{"chosen", "rejected", "weight"}`` text rows for a
    DPO loop. Pure + testable (no torch). With ``require_real_text`` a pair
    lacking real text for either side is skipped rather than raising."""
    rows: list[dict] = []
    for p in pairs:
        try:
            chosen = resolve_pair_text(
                p, "chosen", rows_by_id=rows_by_id, text_sidecar=text_sidecar,
                require_real_text=require_real_text,
                allow_structural_fallback=allow_structural_fallback)
            rejected = resolve_pair_text(
                p, "rejected", rows_by_id=rows_by_id, text_sidecar=text_sidecar,
                require_real_text=require_real_text,
                allow_structural_fallback=allow_structural_fallback)
        except ValueError:
            if require_real_text:
                continue
            raise
        rows.append({"chosen": chosen, "rejected": rejected,
                     "weight": float(p.get("weight", 1.0))})
    return rows


# ---------------------------------------------------------------------------
# DPO training loop (heavy deps lazily imported; GPU + real model required).
# ---------------------------------------------------------------------------


def train(
    pairs: list[dict],
    base_model: str,
    out_dir: str | Path,
    *,
    rows_by_id: dict[str, dict] | None = None,
    text_sidecar: dict[str, str] | None = None,
    require_real_text: bool = False,
    allow_structural_fallback: bool = True,
    beta: float = 0.1,
    epochs: int = 1,
    lr: float = 5e-7,
    lora: bool = False,
    bits: int = 0,
    lora_r: int = 16,
    lora_alpha: int = 32,
    lora_dropout: float = 0.05,
) -> int:
    """Run a minimal, textbook DPO loop over the preference pairs.

    Two backends, same DPO math: full-parameter (default; both policy and a
    frozen reference held in memory -- only feasible for small base models), or
    -- when ``lora`` or ``bits`` is set -- a QLoRA path (4-/8-bit base + LoRA
    adapters, reference recovered by DISABLING the adapter so only ONE model is
    held) that fits 7B-30B on a single GPU. The QLoRA path needs the optional
    ``peft``/``bitsandbytes``/``accelerate`` deps (the [training] extra).

    REQUIRES a GPU and a real causal-LM ``base_model`` (HF id or path).
    This function is NOT covered by the unit tests — only the missing-dep
    path is. ``torch`` and ``transformers`` are imported lazily here so
    the kernel never depends on them.

    DPO objective (Rafailov et al., arxiv:2305.18290), per pair::

        L = -log sigmoid( beta * (
                (logp_pi(chosen)  - logp_ref(chosen))
              - (logp_pi(rejected) - logp_ref(rejected)) ) )

    where ``pi`` is the model being trained and ``ref`` is a frozen copy
    of the base model. ``beta`` is the KL temperature. Each pair's loss
    is scaled by its verifier-confidence ``weight``.

    Args:
        pairs: Output of ``build_preference_pairs``.
        base_model: HF model id or local path for both policy and ref.
        out_dir: Directory to save the fine-tuned proposer.
        rows_by_id: Mapping of trajectory id -> Klear row, used to
            recover the (structural stand-in) text for each attempt. If
            None, ``pairs`` must already carry ``chosen_text`` /
            ``rejected_text`` keys.
        beta, epochs, lr: Standard DPO hyperparameters.

    Returns:
        0 on success, 1 if the heavy deps are missing.
    """
    if lora or bits:
        return _train_dpo_lora(
            pairs, base_model, out_dir, rows_by_id=rows_by_id,
            text_sidecar=text_sidecar, require_real_text=require_real_text,
            allow_structural_fallback=allow_structural_fallback,
            beta=beta, epochs=epochs, lr=lr, bits=(bits or 4),
            lora_r=lora_r, lora_alpha=lora_alpha, lora_dropout=lora_dropout,
        )
    try:
        import torch
        import torch.nn.functional as F
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError:
        print(
            "RLAIF/DPO training needs torch + transformers, which are "
            "optional. Install them with:\n"
            "    python -m pip install -e './packages/maverick-core[training]'",
            file=sys.stderr,
        )
        return 1

    if not pairs:
        print("no preference pairs to train on; nothing to do.", file=sys.stderr)
        return 0

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    device = "cuda" if torch.cuda.is_available() else "cpu"

    tokenizer = AutoTokenizer.from_pretrained(base_model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    policy = AutoModelForCausalLM.from_pretrained(base_model).to(device)
    ref = AutoModelForCausalLM.from_pretrained(base_model).to(device)
    ref.eval()
    for p in ref.parameters():
        p.requires_grad_(False)

    opt = torch.optim.AdamW(policy.parameters(), lr=lr)

    def seq_logp(model, text: str):
        """Sum of token log-probs of ``text`` under ``model``."""
        ids = tokenizer(text, return_tensors="pt").input_ids.to(device)
        logits = model(ids).logits[:, :-1, :]
        targets = ids[:, 1:]
        logp = F.log_softmax(logits, dim=-1)
        token_logp = logp.gather(-1, targets.unsqueeze(-1)).squeeze(-1)
        return token_logp.sum()

    def text_for(pair: dict, key: str) -> str:
        return resolve_pair_text(
            pair, key, rows_by_id=rows_by_id, text_sidecar=text_sidecar,
            require_real_text=require_real_text,
            allow_structural_fallback=allow_structural_fallback)

    policy.train()
    for epoch in range(epochs):
        total = 0.0
        for pair in pairs:
            chosen_text = text_for(pair, "chosen")
            rejected_text = text_for(pair, "rejected")
            pi_c = seq_logp(policy, chosen_text)
            pi_r = seq_logp(policy, rejected_text)
            with torch.no_grad():
                ref_c = seq_logp(ref, chosen_text)
                ref_r = seq_logp(ref, rejected_text)
            logits = beta * ((pi_c - ref_c) - (pi_r - ref_r))
            loss = -F.logsigmoid(logits) * float(pair.get("weight", 1.0))
            opt.zero_grad()
            loss.backward()
            opt.step()
            total += loss.item()
        print(
            f"epoch {epoch + 1}/{epochs}: mean DPO loss "
            f"{total / len(pairs):.4f}",
            file=sys.stderr,
        )

    policy.save_pretrained(out_dir)
    tokenizer.save_pretrained(out_dir)
    print(f"saved DPO-tuned proposer -> {out_dir}", file=sys.stderr)
    return 0


def _train_dpo_lora(
    pairs: list[dict], base_model: str, out_dir: str | Path, *,
    rows_by_id=None, text_sidecar=None, require_real_text=False,
    allow_structural_fallback=True, beta=0.1, epochs=1, lr=1e-4, bits=4,
    lora_r=16, lora_alpha=32, lora_dropout=0.05,
) -> int:
    """QLoRA DPO: a 4-/8-bit base + LoRA adapters, with the reference logp
    recovered by DISABLING the adapter -- so only ONE model is resident, which
    is what lets 7B-30B fit a single GPU. Same DPO objective as ``train``.

    Operator-side and GPU-only: NOT exercised by the test suite (the pure data
    mapping ``pairs_to_dpo_rows`` and the missing-dep path are). Saves a small
    LoRA ADAPTER to ``out_dir`` (merge with the base at serving time, or load
    base+adapter). Needs the [training] extra (peft / bitsandbytes / accelerate).
    """
    try:
        import torch
        import torch.nn.functional as F
        from peft import (
            LoraConfig,
            get_peft_model,
            prepare_model_for_kbit_training,
        )
        from transformers import (
            AutoModelForCausalLM,
            AutoTokenizer,
            BitsAndBytesConfig,
        )
    except ImportError:
        print(
            "QLoRA DPO needs torch + transformers + peft + bitsandbytes "
            "(+ a GPU). Install them with:\n"
            "    python -m pip install -e './packages/maverick-core[training]'",
            file=sys.stderr,
        )
        return 1

    rows = pairs_to_dpo_rows(
        pairs, rows_by_id=rows_by_id, text_sidecar=text_sidecar,
        require_real_text=require_real_text,
        allow_structural_fallback=allow_structural_fallback)
    if not rows:
        print("no preference pairs to train on; nothing to do.", file=sys.stderr)
        return 0
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not torch.cuda.is_available():
        print("WARNING: no CUDA -- QLoRA on CPU is impractically slow.",
              file=sys.stderr)

    compute_dtype = torch.bfloat16
    if bits == 4:
        quant = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=compute_dtype)
    elif bits == 8:
        quant = BitsAndBytesConfig(load_in_8bit=True)
    else:
        quant = None

    tokenizer = AutoTokenizer.from_pretrained(base_model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoModelForCausalLM.from_pretrained(
        base_model, quantization_config=quant, device_map="auto",
        torch_dtype=compute_dtype)
    if quant is not None:
        model = prepare_model_for_kbit_training(
            model, use_gradient_checkpointing=True)
    model = get_peft_model(model, LoraConfig(
        r=lora_r, lora_alpha=lora_alpha, lora_dropout=lora_dropout,
        bias="none", task_type="CAUSAL_LM", target_modules="all-linear"))
    model.print_trainable_parameters()
    opt = torch.optim.AdamW(
        (p for p in model.parameters() if p.requires_grad), lr=lr)

    def seq_logp(text: str):
        ids = tokenizer(text, return_tensors="pt").input_ids.to(model.device)
        logits = model(ids).logits[:, :-1, :]
        targets = ids[:, 1:]
        logp = F.log_softmax(logits, dim=-1)
        return logp.gather(-1, targets.unsqueeze(-1)).squeeze(-1).sum()

    model.train()
    for epoch in range(epochs):
        total = 0.0
        for row in rows:
            pi_c = seq_logp(row["chosen"])
            pi_r = seq_logp(row["rejected"])
            # Reference = the SAME base with LoRA disabled (no second model).
            with torch.no_grad(), model.disable_adapter():
                ref_c = seq_logp(row["chosen"])
                ref_r = seq_logp(row["rejected"])
            logits = beta * ((pi_c - ref_c) - (pi_r - ref_r))
            loss = -F.logsigmoid(logits) * float(row.get("weight", 1.0))
            opt.zero_grad()
            loss.backward()
            opt.step()
            total += loss.item()
        print(f"epoch {epoch + 1}/{epochs}: mean DPO loss {total / len(rows):.4f}",
              file=sys.stderr)

    model.save_pretrained(out_dir)        # LoRA adapter
    tokenizer.save_pretrained(out_dir)
    print(f"saved DPO LoRA adapter -> {out_dir} (load base + adapter, or merge)",
          file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="python -m maverick.training.rlaif",
        description="RLAIF/DPO loop on the proposer using verifier rewards.",
    )
    ap.add_argument(
        "--data", required=True, type=Path,
        help="Klear-format JSONL of trajectories (from training.ingest).",
    )
    ap.add_argument(
        "--base-model", required=True,
        help="HF model id or local path for the proposer to fine-tune.",
    )
    ap.add_argument(
        "--out", required=True, type=Path,
        help="Output directory for the DPO-tuned proposer.",
    )
    ap.add_argument("--beta", type=float, default=0.1,
                    help="DPO KL temperature (default 0.1).")
    ap.add_argument("--epochs", type=int, default=1,
                    help="Number of passes over the pairs (default 1).")
    ap.add_argument("--lr", type=float, default=5e-7,
                    help="AdamW learning rate (default 5e-7).")
    ap.add_argument("--min-margin", type=float, default=0.5,
                    help="Min reward gap for a preference pair (default 0.5).")
    ap.add_argument("--max-pairs", type=int, default=32,
                    help="Max pairs per task_family (default 32).")
    ap.add_argument("--reward-model", default=None,
                    help="Optional learned reward-model JSON (from "
                         "`maverick reward-model train`). When set, preference "
                         "pairs the model disagrees with are downweighted "
                         "(label-noise mitigation).")
    ap.add_argument("--disagree-penalty", type=float, default=0.5,
                    help="Weight multiplier for pairs the reward model "
                         "disagrees with (default 0.5).")
    ap.add_argument("--text-sidecar", default=None, type=Path,
                    help="Operator JSON/JSONL mapping trajectory id -> raw "
                         "proposer text. Real DPO trains on this instead of the "
                         "structural stand-in; the donated corpus stays PII-free.")
    ap.add_argument("--require-real-text", action="store_true",
                    help="Refuse the structural stand-in: drop any pair lacking "
                         "real proposer text and exit non-zero if none remain.")
    ap.add_argument("--text-field", default="text",
                    help="Row key holding inline raw text, if embedded "
                         "(default 'text').")
    ap.add_argument("--lora", action="store_true",
                    help="Use the QLoRA path (4-bit base + LoRA adapters, ref "
                         "via adapter-disable) so 7B-30B fit one GPU. Required "
                         "for any base model bigger than ~3B.")
    ap.add_argument("--bits", type=int, default=0, choices=[0, 4, 8],
                    help="Quantize the base to 4/8-bit (implies --lora; 0=off, "
                         "full-param). 4 is the QLoRA default.")
    ap.add_argument("--lora-r", type=int, default=16, help="LoRA rank.")
    ap.add_argument("--lora-alpha", type=int, default=32, help="LoRA alpha.")
    ap.add_argument("--lora-dropout", type=float, default=0.05,
                    help="LoRA dropout.")
    return ap


def index_trajectories(rows: list[dict]) -> dict[str, dict]:
    """Refuse colliding legacy IDs instead of silently training on another run."""
    result = {}
    for row in rows:
        identity = row.get("id")
        if not isinstance(identity, str) or not identity:
            raise ValueError("Training trajectory has no identity; re-ingest the corpus")
        if identity in result:
            raise ValueError("Duplicate training trajectory identity; re-ingest legacy donations and export the matching sidecar")
        result[identity] = row
    return result


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    rows = load_klear(args.data)
    rows_by_id = index_trajectories(rows)
    pairs = build_preference_pairs(
        rows,
        min_margin=args.min_margin,
        max_pairs_per_group=args.max_pairs,
    )
    print(
        f"built {len(pairs)} preference pairs from {len(rows)} trajectories",
        file=sys.stderr,
    )
    # Real proposer text: attach from the operator side-channel so DPO trains on
    # real prompt/response text, not the structural stand-in. With
    # --require-real-text, pairs lacking real text are dropped and we refuse to
    # train if none remain (before importing torch, so the operator gets a clear
    # error rather than a heavy-dep failure).
    sidecar = load_text_sidecar(args.text_sidecar) if args.text_sidecar else None
    if sidecar is not None or args.require_real_text:
        before = len(pairs)
        pairs, dropped = attach_pair_texts(
            pairs, rows_by_id, sidecar=sidecar, text_field=args.text_field,
            require_real=args.require_real_text,
        )
        with_text = sum(
            1 for p in pairs if p.get("chosen_text") and p.get("rejected_text"))
        print(f"real proposer text: {with_text}/{before} pair(s) have it"
              + (f"; dropped {dropped} without it" if dropped else ""),
              file=sys.stderr)
        if args.require_real_text and not pairs:
            print("no preference pairs have real proposer text; supply "
                  "--text-sidecar. Refusing to train on the structural stand-in.",
                  file=sys.stderr)
            return 1
    # Optional: cross-check the verifier's labels with a learned reward model and
    # downweight pairs the two signals don't corroborate. Off unless --reward-model.
    if args.reward_model:
        from .reward_model import PreferenceRewardModel, reweight_pairs_with_model
        try:
            rm_model = PreferenceRewardModel.load(args.reward_model)
        except (OSError, ValueError) as e:
            print(f"reward model load failed ({e}); proceeding unweighted",
                  file=sys.stderr)
        else:
            rep = reweight_pairs_with_model(
                pairs, rows_by_id, rm_model, disagree_penalty=args.disagree_penalty)
            print(
                f"reward-model cross-check: {rep['agreement_rate']:.0%} agreement "
                f"with the verifier ({rep['agree']}/{rep['scored']} scored comparisons); "
                f"{rep['abstained']} comparisons abstained unchanged; "
                f"{rep['disagree']} disagreements downweighted",
                file=sys.stderr,
            )
    return train(
        pairs,
        base_model=args.base_model,
        out_dir=args.out,
        rows_by_id=rows_by_id,
        text_sidecar=sidecar,
        require_real_text=args.require_real_text,
        beta=args.beta,
        epochs=args.epochs,
        lr=args.lr,
        lora=args.lora,
        bits=args.bits,
        lora_r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
    )


if __name__ == "__main__":
    sys.exit(main())
