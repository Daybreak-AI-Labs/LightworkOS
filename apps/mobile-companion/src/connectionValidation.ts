/* Shared by the connection form, atomic storage write, and request guard. */
export function connectionValidationError(baseUrl: string, token = ""): string | null {
  let url: URL;
  try {
    if (baseUrl.length > 4096 || /[\r\n]/.test(baseUrl)) throw new Error();
    url = new URL(baseUrl.trim());
  } catch {
    return "Enter the full dashboard address, starting with https:// (for example https://lightwork.yourcompany.com).";
  }
  if (!url.hostname || url.username || url.password || url.search || url.hash) {
    return "Enter only the dashboard address. Remove anything after a ? or #, and any name or password in it.";
  }
  const host = url.hostname.toLowerCase();
  const loopback = ["localhost", "127.0.0.1", "::1", "[::1]"].includes(host);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    return "Use a secure address that starts with https://. Addresses starting with http:// work only for a dashboard running on this same device.";
  }
  if (token.length > 8192 || /[\r\n]/.test(token.trim())) {
    return "The access token doesn't look right: it is too long or has a line break in it. Copy it again from your administrator's message.";
  }
  return null;
}
