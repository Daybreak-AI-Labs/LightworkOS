/**
 * Exact non-Lightwork environment contract for the stdio child.
 *
 * `MAVERICK_*` and its supported `LIGHTWORK_*` alias are intentionally
 * forwarded as Lightwork's owned configuration namespaces. Everything outside
 * them must be named here: provider credentials/configuration, Azure Identity
 * inputs, and the small cross-platform runtime/proxy/CA surface required by
 * Python and Codex.
 */
import process from "node:process";

export const LIGHTWORK_MCP_ENV_ALLOWLIST = [
  "ALL_PROXY",
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_BASE_URL",
  "APPDATA",
  "AWS_ACCESS_KEY_ID",
  "AWS_CA_BUNDLE",
  "AWS_CONFIG_FILE",
  "AWS_DEFAULT_REGION",
  "AWS_PROFILE",
  "AWS_REGION",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AWS_SHARED_CREDENTIALS_FILE",
  "AZURE_AUTHORITY_HOST",
  "AZURE_CLIENT_CERTIFICATE_PASSWORD",
  "AZURE_CLIENT_CERTIFICATE_PATH",
  "AZURE_CLIENT_ID",
  "AZURE_CLIENT_SECRET",
  "AZURE_CLIENT_SEND_CERTIFICATE_CHAIN",
  "AZURE_FEDERATED_TOKEN_FILE",
  "AZURE_IDENTITY_DISABLE_MULTITENANTAUTH",
  "AZURE_KUBERNETES_CA_DATA",
  "AZURE_KUBERNETES_CA_FILE",
  "AZURE_KUBERNETES_SNI_NAME",
  "AZURE_KUBERNETES_TOKEN_PROXY",
  "AZURE_OPENAI_AD_TOKEN",
  "AZURE_OPENAI_API_KEY",
  "AZURE_OPENAI_API_VERSION",
  "AZURE_OPENAI_AUTH",
  "AZURE_OPENAI_DEPLOYMENT",
  "AZURE_OPENAI_ENDPOINT",
  "AZURE_OPENAI_TOKEN_SCOPE",
  "AZURE_OPENAI_USE_MAX_COMPLETION",
  "AZURE_PASSWORD",
  "AZURE_POD_IDENTITY_AUTHORITY_HOST",
  "AZURE_REGIONAL_AUTHORITY_NAME",
  "AZURE_TENANT_ID",
  "AZURE_TOKEN_CREDENTIALS",
  "AZURE_USERNAME",
  "BEDROCK_API_KEY",
  "BEDROCK_MODEL_ID",
  "CODEX_ACCESS_TOKEN",
  "CODEX_HOME",
  "COMSPEC",
  "CURL_CA_BUNDLE",
  "DEEPSEEK_API_KEY",
  "DEEPSEEK_BASE_URL",
  "GEMINI_API_KEY",
  "GOOGLE_API_KEY",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "GOOGLE_CLOUD_PROJECT",
  "GOOGLE_CLOUD_QUOTA_PROJECT",
  "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH",
  "GROK_API_KEY",
  "HOME",
  "HOMEDRIVE",
  "HOMEPATH",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "IDENTITY_ENDPOINT",
  "IDENTITY_HEADER",
  "IDENTITY_SERVER_THUMBPRINT",
  "IMDS_ENDPOINT",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "LOCALAPPDATA",
  "LOGNAME",
  "MOONSHOT_API_KEY",
  "MOONSHOT_BASE_URL",
  "MSI_ENDPOINT",
  "MSI_SECRET",
  "NODE_EXTRA_CA_CERTS",
  "NO_PROXY",
  "OPENAI_API_KEY",
  "OPENAI_BASE_URL",
  "OPENAI_COMPATIBLE_API_KEY",
  "OPENAI_COMPATIBLE_BASE_URL",
  "OPENAI_ORGANIZATION",
  "OPENAI_ORG_ID",
  "OPENAI_PROJECT_ID",
  "OPENROUTER_API_KEY",
  "PATH",
  "PROCESSOR_ARCHITECTURE",
  "PROGRAMFILES",
  "REQUESTS_CA_BUNDLE",
  "SHELL",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
  "SYSTEMDRIVE",
  "SYSTEMROOT",
  "TEMP",
  "TERM",
  "TGI_API_KEY",
  "TGI_BASE_URL",
  "TMP",
  "TMPDIR",
  "USER",
  "USERNAME",
  "USERPROFILE",
  "VLLM_API_KEY",
  "VLLM_BASE_URL",
  "XAI_API_KEY",
  "XAI_BASE_URL",
  "XDG_CACHE_HOME",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  "all_proxy",
  "http_proxy",
  "https_proxy",
  "no_proxy",
] as const;

const allowedNames = new Set<string>(LIGHTWORK_MCP_ENV_ALLOWLIST);

export type EnvironmentSource = Readonly<
  Record<string, string | undefined>
>;

/**
 * Select only Lightwork-owned settings and explicitly reviewed dependencies.
 *
 * Shell-function exports begin with `()` and are intentionally discarded,
 * matching the MCP SDK's safe default environment behavior.
 */
export function selectLightworkMcpEnvironment(
  source: EnvironmentSource,
  platform: string = process.platform,
): Record<string, string> {
  const isWindows = platform === "win32";
  return Object.fromEntries(
    Object.entries(source).filter(
      ([name, value]) => {
        const reviewedName = isWindows ? name.toUpperCase() : name;
        return (
          value !== undefined &&
          !value.startsWith("()") &&
          (
            reviewedName.startsWith("MAVERICK_") ||
            reviewedName.startsWith("LIGHTWORK_") ||
            allowedNames.has(reviewedName)
          )
        );
      },
    ),
  ) as Record<string, string>;
}
