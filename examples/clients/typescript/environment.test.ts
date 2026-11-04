import assert from "node:assert/strict";
import { test } from "node:test";

import {
  LIGHTWORK_MCP_ENV_ALLOWLIST,
  selectLightworkMcpEnvironment,
} from "./environment.js";

test("forwards every reviewed non-Lightwork environment name", () => {
  const source = Object.fromEntries(
    LIGHTWORK_MCP_ENV_ALLOWLIST.map((name) => [name, `value-for-${name}`]),
  );

  assert.deepEqual(selectLightworkMcpEnvironment(source), source);
});

test("applies the environment boundary table", async (t) => {
  const cases = [
    ["MAVERICK_CONFIG", true],
    ["MAVERICK_MODEL_OVERRIDE", true],
    ["LIGHTWORK_CONFIG", true],
    ["LIGHTWORK_MODEL_OVERRIDE", true],
    ["CODEX_HOME", true],
    ["AZURE_CLIENT_ID", true],
    ["AZURE_FEDERATED_TOKEN_FILE", true],
    ["TGI_BASE_URL", true],
    ["VLLM_BASE_URL", true],
    ["OPENAI_COMPATIBLE_BASE_URL", true],
    ["HTTPS_PROXY", true],
    ["https_proxy", true],
    ["SSL_CERT_FILE", true],
    ["NODE_EXTRA_CA_CERTS", true],
    ["STRIPE_API_KEY", false],
    ["UNRELATED_API_KEY", false],
    ["GITHUB_TOKEN", false],
    ["PYTHONPATH", false],
    ["PYTHONSTARTUP", false],
    ["LD_PRELOAD", false],
  ] as const;

  for (const [name, allowed] of cases) {
    await t.test(`${allowed ? "allows" : "rejects"} ${name}`, () => {
      const selected = selectLightworkMcpEnvironment({ [name]: "test-value" });
      assert.equal(Object.hasOwn(selected, name), allowed);
    });
  }
});

test("rejects exported shell functions and undefined values", () => {
  assert.deepEqual(
    selectLightworkMcpEnvironment({
      ANTHROPIC_API_KEY: undefined,
      MAVERICK_CONFIG: "() { injected; }",
      PATH: "/reviewed/bin",
    }),
    { PATH: "/reviewed/bin" },
  );
});

test("matches reviewed Windows names case-insensitively without recasing keys", () => {
  const source = {
    Path: "C:\\Windows\\System32",
    ComSpec: "C:\\Windows\\System32\\cmd.exe",
    SystemRoot: "C:\\Windows",
    ProgramFiles: "C:\\Program Files",
    mAvErIcK_config: "C:\\Lightwork\\config.toml",
    lIgHtWoRk_home: "C:\\Lightwork",
    Stripe_Api_Key: "must-not-cross", // pragma: allowlist secret
  };

  assert.deepEqual(
    selectLightworkMcpEnvironment(source, "win32"),
    {
      Path: source.Path,
      ComSpec: source.ComSpec,
      SystemRoot: source.SystemRoot,
      ProgramFiles: source.ProgramFiles,
      mAvErIcK_config: source.mAvErIcK_config,
      lIgHtWoRk_home: source.lIgHtWoRk_home,
    },
  );
});

test("keeps reviewed names case-sensitive off Windows", () => {
  assert.deepEqual(
    selectLightworkMcpEnvironment(
      {
        Path: "/unreviewed/casing",
        PATH: "/reviewed/bin",
        Maverick_Config: "/unreviewed/casing.toml",
        MAVERICK_CONFIG: "/reviewed/config.toml",
        Lightwork_Config: "/unreviewed/lightwork.toml",
        LIGHTWORK_CONFIG: "/reviewed/lightwork.toml",
      },
      "linux",
    ),
    {
      PATH: "/reviewed/bin",
      MAVERICK_CONFIG: "/reviewed/config.toml",
      LIGHTWORK_CONFIG: "/reviewed/lightwork.toml",
    },
  );
});
