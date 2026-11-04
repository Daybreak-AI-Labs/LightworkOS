"""Software development in Lightwork: a company's code, protected, improved by swarms.

- :mod:`.vault` keeps each repository sealed at rest and hands out private,
  short-lived working copies.
- :mod:`.features` runs a feature swarm on a branch under information-flow
  control, tests and independently reviews the change, and parks it for human
  approval before anything is merged or pushed.
"""
