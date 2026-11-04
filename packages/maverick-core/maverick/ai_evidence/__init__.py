"""Internal boundaries for governed AI evidence and output delivery.

Existing ``maverick.ai_evidence_gateway`` imports remain supported. Modules
under this package should depend on these narrow boundaries rather than
reaching into gateway storage or policy internals.
"""
