"""Adaptive immune layer: discover, prove and remember what policies miss.

Innate controls (Shield, capabilities, approvals) govern one agent or one action
at a time. This package answers the questions those controls cannot:

* :mod:`.network`     -- what can agents do *together* (composition risk)?
* :mod:`.oversight`   -- is the human in the loop actually catching flaws?
* :mod:`.title`       -- can a machine-assisted discovery be owned and proven?
* :mod:`.invariance`  -- does a model behave differently when it is watched?
* :mod:`.policy`      -- does a candidate rule beat the current one on replay,
  and do two rules contradict each other?

Every module is deterministic and offline: findings come with the witness that
proves them, never a model's opinion. Only :mod:`.oversight` writes state, and
only when an operator seeds canaries (``[immune] canary_rate``, off by default).
"""
