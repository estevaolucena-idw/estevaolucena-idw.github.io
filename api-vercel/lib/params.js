/**
 * Extrai o username da rota /api/sessions/:username.
 * Compatível com params síncronos, Promise (Next/Vercel recentes) e fallback via URL.
 */
export async function resolveUsername(request, context) {
  let params = context?.params;
  if (params && typeof params.then === "function") {
    params = await params;
  }
  const fromParams = params?.username;
  if (typeof fromParams === "string" && fromParams) return fromParams;
  if (Array.isArray(fromParams) && fromParams[0]) return fromParams[0];

  const url = new URL(request.url);
  const parts = url.pathname.split("/").filter(Boolean);
  // ["api", "sessions", "<username>"]
  const idx = parts.indexOf("sessions");
  if (idx >= 0 && parts[idx + 1]) return decodeURIComponent(parts[idx + 1]);
  return parts[parts.length - 1] || "";
}
