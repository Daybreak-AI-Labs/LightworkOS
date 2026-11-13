# Supported release runtime dependencies

The `maverick-agent[release-runtime]` profile supplies the Python dependencies
used by the full frozen executable and application container. The eight-package
Lightwork cohort identifies first-party packages; it does not mean that every
optional integration, model or external engine is included.

| Included dependency family | Included operation | Additional deployment requirement |
| --- | --- | --- |
| Anthropic and OpenAI-compatible SDKs | Provider client construction and requests through supported adapters | An approved model/account, credentials, endpoint and real task acceptance. Azure managed identity, native Bedrock and native Vertex AI have separate optional dependencies (the `azure`, `bedrock` and `vertex` extras). |
| OpenPyXL, lxml, PyPDF and pdfplumber | Local spreadsheet/XML/PDF parsing and packaged document worker source | Native recalculation, OCR and document rendering require the configured isolated worker image and engine binaries. |
| SQLAlchemy and Psycopg binary/pool | Relational tool with SQLite or `postgresql+psycopg://`; optional PostgreSQL platform storage | Operator-controlled connection configuration and permissions, reachable database, live query and recovery acceptance. Other SQL dialects require their own drivers and qualification. |
| latex2mathml and its symbol data | Local LaTeX-to-MathML conversion | PDF compilation still requires a TeX engine in the configured sandbox. |
| prometheus-client | Platform metrics collection and Prometheus output | Explicit metrics configuration, network/access policy and an accepted monitoring/alerting setup. This does not include the optional OpenTelemetry or Sentry SDKs. |

`release-runtime-check` is an offline acceptance command. It exits unsuccessfully
if provider/parser imports, document worker source, or the checks below fail:

- Create, commit and read an in-memory SQL table; load the actual Psycopg SQL
  dialect, bundled binary libpq and a closed PostgreSQL connection pool.
- Convert a fraction containing a named symbol into complete MathML and reject
  an incomplete fraction, using the production conversion function.
- Render the actual platform collectors in a private Prometheus registry,
  checking that tool latency, provider error rate and latency-budget series exist.

The command reports the loaded libpq version and rejects native versions before
the fixed branches for [CVE-2026-6477](https://www.postgresql.org/support/security/CVE-2026-6477/):
14.23, 15.18, 16.14, 17.10 and 18.4. Subsequent major versions include prior
fixes. The reviewed Psycopg and binary wheel pin is 3.3.7; the connection pool
is pinned to 3.3.3. This is a release-artifact dependency gate, not a check on every
database operation in an independently configured source installation.

These checks do not connect to a remote database, start a metrics listener,
request a model response or change stored records. Staging and installed
Windows acceptance invoke this command inside the actual frozen executable.
The release/container and SBOM workflows also verify the profile. Hosted-run
results belong to their recorded revision and artifact; a source test alone
does not prove that the frozen artifact contains the necessary native libraries.

The nonpublishing `Frozen runtime` PR workflow builds the same PyInstaller spec
on Linux x86-64 and macOS arm64. It runs the CLI checks with disposable homes and
an empty developer PATH, and retains command logs and a binary hash tied to the
checkout. The release matrix uses Python 3.12.13 on Linux and 3.12.10 on Windows
and macOS, matching available official `actions/python-versions` binaries.
These are engineering checks, not signed or notarized release acceptance.

The reviewed dependency constraints include these libraries. PyInstaller
retains their dynamically selected modules, binary-driver hooks, distribution
metadata and MathML symbol data. Source installations can install the reviewed
package extra; a frozen application's missing dependency must be corrected in
the distributable build, rather than asking its operator to modify a system
Python environment.
