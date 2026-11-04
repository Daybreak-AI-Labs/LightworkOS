# Self-learning training runbook

Everything needed to train and *prove* the self-learning loop, end to end. The
loop has three rungs — all wired and tested; this page is how you actually run
them.

| Rung | What it does | Hardware |
|---|---|---|
| **L1** dream consolidation | LLM rewrites recurring failures into transferable lessons | CPU (uses your configured LLM) |
| **L2** learned step PRM | a learned per-step signal scores every agent step | **CPU** (no GPU) |
| **L3** DPO fine-tune | nudges the proposer toward verifier-preferred attempts | **GPU** |
| proof harness | reproducible A/B that the learning actually helped | CPU |

## 0. Prerequisite: produce training data (the real gate)

Neither your laptop nor the cloud can manufacture this — it comes from **real
runs**. Turn on donation, then use Lightwork normally:

```toml
# ~/.maverick/config.toml
[telemetry]
donate_trajectories = true     # off by default; writes scrubbed records to ~/.maverick/outbox/
donate_min_entropy = 0         # capture EVERY successful run, not just swarm-disagreement ones
donate_text = true             # needed for DPO: keeps raw draft text in the records (see below)
# donate_min_confidence = 0.75 # (default) verifier-confidence floor; lower to capture more
```

```bash
maverick start "…a real goal…"     # run a bunch; high-confidence runs (verifier ≥ 0.75) get donated
maverick start --repeat 5 "…task…" # run the SAME task 5×
maverick donate status             # see what's queued in the outbox
```

> **Why `donate_min_entropy = 0`.** The default bar only donates
> high-disagreement *swarm* runs (entropy ≥ 0.5). A normal single-agent goal has
> entropy 0, so with the default bar **nothing is captured** — the outbox stays
> empty and there's nothing to train on. Set it to `0` to capture every
> successful, high-confidence run.
>
> **Where DPO pairs actually come from.** The agent revises until the verifier
> accepts, so every *shipped* answer scores ~1.0 — there is no better-vs-worse
> gradient among finished runs (repeating a task just yields N good answers). The
> real preference signal is the **rejected draft**: when the verifier rejects a
> FINAL and the agent revises, that rejected draft (low score) pairs against the
> accepted final (high score) within the same task. This needs the draft *text*,
> so set `donate_text = true`. With it off you get metadata only and **zero DPO
> pairs**. Use tasks with real constraints (so the verifier sometimes rejects);
> pure-recall tasks rarely trigger a revision and so rarely produce a pair.

### The reliable way to get DPO pairs: best-of-N + objective tests

The rejected-draft path above depends on the verifier rejecting — but a strong
proposer + a strong verifier rarely rejects (verifier confidence tends to vary
very little between runs), so it produces few pairs. The
**robust** source of a quality gradient is *objective*, not the verifier:

- **best-of-N** runs N independent attempts at one coding task and scores each by
  whether your **local tests** pass (`--fail-to-pass`). A passing patch (reward
  1.0) vs a failing one (~0.0) is a real preference pair with a ~1.0 margin — no
  verifier rejection needed. This works with only your Anthropic key + `pytest`.

```toml
# ~/.maverick/config.toml  — for best-of-N candidate mining
[telemetry]
donate_trajectories = true
donate_text = true          # keeps the candidate patch text (DPO needs it)
donate_min_entropy = 0      # best-of-N runs aren't swarm runs (entropy 0)
donate_min_confidence = 0   # so a hard task whose best patch still scores low is kept
```

```bash
# Run in a GIT CHECKOUT of a real repo, with concrete failing tests.
# EARLY-EXIT OFF so the ladder keeps going after the first pass and captures a FAIL too:
MAVERICK_BON_EARLY_EXIT=0 \
maverick start "Fix <a real bug at the model's ~50% pass-rate frontier>" \
  --coding-mode --best-of-n 8 \
  --fail-to-pass 'pkg/tests/test_x.py::test_a||pkg/tests/test_x.py::test_b' \
  --pass-to-pass 'pkg/tests/test_x.py::test_c'
```

> **Pairs require divergence — pick frontier tasks.** A pair only forms when the N
> attempts *differ*: at least one passes and at least one fails. Trivial tasks
> (all pass) and impossible tasks (all fail) yield no gradient, and the run logs
> `best-of-N: no DPO pair donated …` instead of writing a useless all-tie record.
> Aim for tasks the model solves ~half the time. This is inherent to DPO data
> generation, not a bug — `0 pairs` off-frontier is expected.

The two training inputs are generated from this data (you don't hand-write them):

- `trajectories.jsonl` ← `python -m maverick.training.ingest` (from the outbox + world DB)
- `proposer_texts.jsonl` ← `python -m maverick.training.export_texts` (raw transcripts from the world DB, keyed to the same ids)

The training script in Option A does both for you. **No outbox data ⇒ nothing to train on.**

---

## Option A — everything on a cloud GPU pod (no laptop)

On a GPU pod (RunPod / Lambda / Vast / any GPU VM):

1. Get your data onto the pod — **either** copy your `~/.maverick/` (so the
   outbox + `world.db` are present and inputs auto-generate), **or** pre-run the
   two `ingest`/`export_texts` commands at home and upload the two `.jsonl` files.
2. Clone Lightwork at an exact commit and run the training script from that
   checkout. The script installs only from a clean checkout whose `HEAD`
   matches `MAVERICK_SOURCE_REF`:

```bash
LIGHTWORK_REF=<full-40-character-commit-sha>
git clone https://github.com/Daybreak-AI-Labs/LightworkOS lightwork
git -C lightwork checkout --detach "$LIGHTWORK_REF"

# cheap proof run (default base model, full-parameter, any GPU):
MAVERICK_SOURCE_DIR="$PWD/lightwork" MAVERICK_SOURCE_REF="$LIGHTWORK_REF" \
  bash lightwork/scripts/train_runpod.sh

# …or a larger model on one 80GB GPU (QLoRA):
BASE_MODEL=Qwen/Qwen3-Coder-30B-A3B LORA=1 BITS=4 \
  MAVERICK_SOURCE_DIR="$PWD/lightwork" MAVERICK_SOURCE_REF="$LIGHTWORK_REF" \
  bash lightwork/scripts/train_runpod.sh
```

It installs `packages/maverick-core[training]` from the checkout (torch +
transformers + peft + bitsandbytes + accelerate), generates any missing inputs,
trains the L2 PRM (CPU), runs real DPO (GPU, `--require-real-text`;
`LORA=1 BITS=4` uses 4-bit QLoRA so 7B–30B fit one GPU), and prints where the
outputs are.

> **Right-size to your data.** Start with the default tiny model to prove the
> loop cheaply; only graduate to 8B–30B once you have real trajectory volume —
> DPO on a few pairs barely moves a big model and overfits.

3. **Copy the outputs off the pod before stopping it** (pods are ephemeral):
   `maverick-train-out/prm_linear.json` and `maverick-train-out/proposer_dpo/`
   → S3 / Hugging Face.

Useful env vars: `BASE_MODEL`, `OUTBOX`, `OUT_DIR`, `SKIP_DPO=1` (CPU PRM only),
`DRY_RUN=1` (preview the commands), `INSTALL=0` (skip installation),
`BETA/EPOCHS/LR/MIN_MARGIN/MAX_PAIRS`. `bash lightwork/scripts/train_runpod.sh --help`
prints them all.

> Privacy: `export_texts` writes your raw transcripts to a local file (the thing
> the shared corpus deliberately avoids). Fine on a box you control; sending it
> to a third party is a deliberate egress decision. For air-gap, use your own GPU.

---

## Option B — step by step (local or remote, full control)

```bash
# 1. Generate the two inputs from your runs
python -m maverick.training.ingest        --in ~/.maverick/outbox --out trajectories.jsonl
python -m maverick.training.export_texts  --in ~/.maverick/outbox --out proposer_texts.jsonl

# 2. L2 — train the learned step PRM (CPU, seconds)
python -m maverick.training.prm_linear --data trajectories.jsonl --out prm_linear.json
export MAVERICK_PRM=linear MAVERICK_PRM_PATH="$PWD/prm_linear.json"
export MAVERICK_PRM_BOOTSTRAP_SHA256="$(sha256sum prm_linear.json | cut -d' ' -f1)"

# 3. L3 — real DPO (GPU; needs the [training] extra)
python -m pip install -e './packages/maverick-core[training]'
python -m maverick.training.rlaif \
    --data trajectories.jsonl \
    --text-sidecar proposer_texts.jsonl --require-real-text \
    --base-model <hf-id> --out ./proposer_dpo
```

---

## Prove it actually learned (the part that makes "self-improving" defensible)

Run a held-out task suite twice — learning frozen vs live — score each with the
verifier, then compute the lift:

```bash
# control arm (no learning) then treatment arm (learning live), same tasks/seeds
MAVERICK_LEARNING_FROZEN=1  maverick start ...   # collect "baseline" scores
MAVERICK_LEARNING_FROZEN=0  maverick start ...   # collect "treatment" scores

# scores.json = {"baseline": [...], "treatment": [...]}  (paired per task)
maverick prove-learning --scores scores.json --strict
```

`prove-learning` reports the mean paired lift with a seeded bootstrap 95% CI
(reproducible); `--strict` exits non-zero unless learning *significantly*
improved — a CI gate you can wire in.

---

## Troubleshooting

- **"no transcripts" / "no trajectories"** → the outbox is empty. Either you
  haven't run goals with `donate_trajectories = true` yet, or every run was a
  single-agent goal and the default disagreement bar filtered them all out — set
  `donate_min_entropy = 0` in `[telemetry]` to capture them (step 0).
- **"ingested 0 trajectories from 0 donation record(s)"** → same cause: the
  selection gate donated nothing. Set `donate_min_entropy = 0` and re-run.
- **DPO finds no preference pairs** → you ran each task once. DPO needs repeated
  attempts at the *same* task; use `maverick start --repeat N "…task…"`.
- **DPO is extremely slow** → you're on a CPU pod. The PRM/proof steps are CPU,
  but L3 needs a GPU.
- **OOM during DPO** → the default run is full-parameter. Use a smaller
  `BASE_MODEL`, a bigger card, or 4-bit QLoRA (`LORA=1 BITS=4`, see Option A) to
  tune a 7B+ model on one GPU.
- **`import transformers` fails** → from the reviewed checkout, install the
  extra: `python -m pip install -e './packages/maverick-core[training]'`.

See also: `docs/self-learning.md` (concepts), `scripts/train_runpod.sh` (the runner).
