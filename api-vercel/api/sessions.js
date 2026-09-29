import { json, noContent } from "../lib/cors.js";
import { clearAllSessions, listSessions } from "../lib/store.js";

export async function OPTIONS(request) {
  return noContent(request);
}

export async function GET(request) {
  try {
    const sessions = await listSessions();
    return json(request, { sessions });
  } catch (error) {
    return json(
      request,
      { error: error instanceof Error ? error.message : String(error) },
      500
    );
  }
}

export async function DELETE(request) {
  try {
    const url = new URL(request.url);
    if (url.searchParams.get("confirm") !== "poc-passkey-clear") {
      return json(
        request,
        { error: "Informe ?confirm=poc-passkey-clear para limpar todas as sessões." },
        400
      );
    }
    const result = await clearAllSessions();
    return json(request, result);
  } catch (error) {
    return json(
      request,
      { error: error instanceof Error ? error.message : String(error) },
      500
    );
  }
}
