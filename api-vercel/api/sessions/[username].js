import { json, noContent } from "../../lib/cors.js";
import { resolveUsername } from "../../lib/params.js";
import { deleteSession, getSession, putSession } from "../../lib/store.js";

export async function OPTIONS(request) {
  return noContent(request);
}

export async function GET(request, context) {
  try {
    const username = await resolveUsername(request, context);
    const session = await getSession(username);
    return json(request, session);
  } catch (error) {
    return json(
      request,
      { error: error instanceof Error ? error.message : String(error) },
      400
    );
  }
}

export async function PUT(request, context) {
  try {
    const username = await resolveUsername(request, context);
    const body = await request.json();
    const session = await putSession(username, body);
    return json(request, session);
  } catch (error) {
    return json(
      request,
      { error: error instanceof Error ? error.message : String(error) },
      400
    );
  }
}

export async function DELETE(request, context) {
  try {
    const username = await resolveUsername(request, context);
    const result = await deleteSession(username);
    return json(request, result);
  } catch (error) {
    return json(
      request,
      { error: error instanceof Error ? error.message : String(error) },
      400
    );
  }
}
