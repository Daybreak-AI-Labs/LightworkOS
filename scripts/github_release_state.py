#!/usr/bin/env python3
"""Read one exact-tag GitHub release state and fail closed on API errors."""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class GitHubReleaseState:
    tag: str
    state: str
    prerelease: bool | None


def fetch_release_state(
    repository: str,
    tag: str,
    token: str,
) -> GitHubReleaseState:
    """Return absent/draft/published; only a confirmed HTTP 404 means absent."""
    if repository.count("/") != 1 or any(
        not component for component in repository.split("/")
    ):
        raise ValueError("repository must be OWNER/NAME")
    if not token:
        raise ValueError("GitHub token is empty")
    owner, name = repository.split("/")
    body = json.dumps(
        {
            "query": (
                "query($owner:String!,$name:String!,$tag:String!){"
                "repository(owner:$owner,name:$name){"
                "release(tagName:$tag){tagName isDraft isPrerelease}"
                "}}"
            ),
            "variables": {"owner": owner, "name": name, "tag": tag},
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        "https://api.github.com/graphql",
        data=body,
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Lightwork-release-state/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"GitHub release-state API failed with HTTP {exc.code}"
        ) from None
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"GitHub release-state API failed: {exc}") from exc

    if payload.get("errors"):
        raise RuntimeError("GitHub release-state GraphQL query returned errors")
    repository_payload = payload.get("data", {}).get("repository")
    if not isinstance(repository_payload, dict):
        raise RuntimeError("GitHub release-state response omitted the repository")
    release_payload = repository_payload.get("release")
    if release_payload is None:
        return GitHubReleaseState(
            tag=tag,
            state="absent",
            prerelease=None,
        )
    if not isinstance(release_payload, dict):
        raise RuntimeError("GitHub release-state response is malformed")
    if release_payload.get("tagName") != tag:
        raise RuntimeError("GitHub returned a different release tag")
    draft = release_payload.get("isDraft")
    prerelease = release_payload.get("isPrerelease")
    if not isinstance(draft, bool) or not isinstance(prerelease, bool):
        raise RuntimeError("GitHub release state has invalid boolean fields")
    return GitHubReleaseState(
        tag=tag,
        state="draft" if draft else "published",
        prerelease=prerelease,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--token-env", default="GH_TOKEN")
    parser.add_argument(
        "--expected-prerelease",
        required=True,
        choices=("true", "false"),
    )
    parser.add_argument(
        "--allow-state",
        action="append",
        choices=("absent", "draft", "published"),
        required=True,
    )
    parser.add_argument("--github-output", type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        result = fetch_release_state(
            args.repository,
            args.tag,
            os.environ.get(args.token_env, ""),
        )
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc

    if result.state not in set(args.allow_state):
        raise SystemExit(
            f"release {result.tag} is {result.state}, expected one of "
            f"{sorted(set(args.allow_state))}"
        )
    expected_prerelease = args.expected_prerelease == "true"
    if (
        result.prerelease is not None
        and result.prerelease is not expected_prerelease
    ):
        raise SystemExit("GitHub release prerelease state does not match its tag")
    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(f"state={result.state}\n")
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
