# Interface contracts

These documents specify versioned contracts that Lightwork implements. Each
names the schema or module that enforces it, its scope, and the boundaries it
does not cover.

| Contract | What it covers |
| --- | --- |
| [Platform contracts v1](./platform-contracts-v1.md) | The common envelope, schemas, transitions and export boundary in `maverick.platform_contracts` |
| [Worker authority binding v1](./worker-authority-binding-v1.md) | `lightwork.worker-authority.v1`: the service context bound to every provider effect in the supplier workflow |
| [Staged local restore reference validation v1](./restore-reference-validation-v1.md) | `lightwork.restore-reference-validation.v1`: reference and schema-version checks before a local restore publishes files |
| [Supplier request cancellation v1](./supplier-cancellation-v1.md) | Local cancellation of a supplier request and the provider state it retains |
| [Supported supplier evidence journey v1](./supplier-evidence-journey-v1.md) | The retained outcome contract for the supplier evidence workflow |

Other format specifications live in `docs/specs/`, for example the
[trust receipt format](../specs/trust-receipt-v1.md).
