"""Browser failures must retain diagnostics from every custom fixture run."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
BROWSER = Path(__file__).parent / "browser"


def test_custom_browser_result_directories_are_uploaded_even_on_failure():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ui-regressions.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["customer-browser-journeys"]["steps"]
    upload = next(step for step in steps if step.get("with", {}).get("name") == "customer-browser-journeys")
    assert upload["if"] == "always()"
    assert upload["with"].get("include-hidden-files") is True
    uploaded_paths = set(upload["with"]["path"].splitlines())

    for config in sorted(BROWSER.glob("*.config.js")):
        if config.name == "playwright.config.js":
            continue
        output = re.search(
            r"outputDir:\s*path\.resolve\(__dirname,\s*['\"][^'\"]+['\"],\s*['\"]([^'\"]+)['\"]\)",
            config.read_text(encoding="utf-8"),
        )
        assert output is not None, f"Declare the retained output directory for {config.name}"
        directory = output.group(1)
        assert directory in uploaded_paths, f"{config.name} diagnostics are missing from the CI artifact: {directory}"
