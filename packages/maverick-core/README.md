# maverick-core

The Lightwork agent kernel. A recursive multi-agent swarm with persistent
world model, shared blackboard, hard budget caps, and closed-loop skill
learning.

See the [top-level README](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/README.md)
and [`ARCHITECTURE.md`](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/ARCHITECTURE.md)
for the full picture.

Lightwork is installed from source: follow
[Install from source](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/docs/source-install.md).
`scripts/install_release_cohort.py` installs this package together with the
other seven (shield, dashboard, setup wizard and so on). No PyPI package is
published. For kernel-only development, `pip install -e ./packages/maverick-core`
from the repository root installs this package alone, without the safety layer
or the setup wizard.
