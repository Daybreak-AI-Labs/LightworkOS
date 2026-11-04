---
name: ci-cd-pipeline-design
triggers:
  - cicd
  - pipeline design
  - build deploy
tools_needed:
  - knowledge_search
---
# What this skill does

Designs a CI/CD pipeline for a given repo/service: the ordered stages from commit to production, the quality and approval gates between them, the artifact/promotion model, and the rollback path. Produces a pipeline design concrete enough to implement in the team's CI system, with each gate justified by a real risk it catches.

# Steps

1. Establish the target from the inputs: the stack and build tooling, the deploy target (containers, serverless, packages), the environments (dev/staging/prod), and any compliance or approval requirements. Quote the real commands/targets the project already uses; do not assume a toolchain.
2. Lay out the stages in order: build → unit tests → lint/static + security scan → package a single immutable artifact → deploy to staging → integration/e2e → promote to prod. Define what each stage runs and its pass/fail criteria from the project's actual test and lint commands.
3. Define the gates: which stages are blocking, which require manual approval (prod promote), and the policy gates (coverage threshold, secret scan, vulnerability severity). Use `knowledge_search` to pull the team's existing CI conventions and required checks; mark anything unverified rather than assuming a standard.
4. Specify the artifact and promotion model (build once, promote the same artifact across environments — never rebuild per env), environment config/secrets injection, and the deploy strategy (blue-green/canary/rolling) with its health check.
5. Report the pipeline as ordered stages with gates, the promotion model, and an explicit rollback path (redeploy previous artifact or flip traffic) including who triggers it — with assumptions and any unverified required-check listed.

# Notes

The output is wrong if it rebuilds artifacts per environment (staging no longer matches prod), if it lacks a tested rollback, if gates are advisory where they should block (security scan, prod approval), or if secrets are baked into images instead of injected. The deploy and rollback steps touch real environments and are irreversible — those stages are staged for human approval, not auto-run by this skill. Ground gates in the project's actual commands and required checks; mark unconfirmed ones. Not for a one-off manual script or a repo with no test/build tooling to gate on yet.
