import { json, noContent } from "../lib/cors.js";

export async function OPTIONS(request) {
  return noContent(request);
}

export async function GET(request) {
  const hasBlobToken = Boolean(process.env.BLOB_READ_WRITE_TOKEN);
  let blobOk = null;
  let blobError = null;
  if (hasBlobToken) {
    try {
      const { list } = await import("@vercel/blob");
      await list({
        prefix: "poc-passkey/",
        limit: 1,
        token: process.env.BLOB_READ_WRITE_TOKEN,
      });
      blobOk = true;
    } catch (error) {
      blobOk = false;
      blobError = error instanceof Error ? error.message : String(error);
    }
  }

  return json(request, {
    ok: true,
    service: "poc-passkey-api",
    storage: "vercel-blob",
    blobConfigured: hasBlobToken,
    blobOk,
    blobError,
  });
}
