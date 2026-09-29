import { put, list } from "@vercel/blob";

const BLOB_PATH = "poc-passkey/sessions.json";

function emptyRoot() {
  return { sessions: {} };
}

function emptySession() {
  return { user: null, credentials: [], updatedAt: null };
}

function blobToken() {
  const token = process.env.BLOB_READ_WRITE_TOKEN;
  if (!token) {
    throw new Error("BLOB_READ_WRITE_TOKEN não configurado na Vercel.");
  }
  return token;
}

export async function readRoot() {
  const token = blobToken();
  const { blobs } = await list({
    prefix: "poc-passkey/",
    limit: 20,
    token,
  });
  const blob = blobs.find((item) => item.pathname === BLOB_PATH);
  if (!blob) return emptyRoot();
  const response = await fetch(blob.url, { cache: "no-store" });
  if (!response.ok) return emptyRoot();
  const data = await response.json();
  return {
    sessions:
      data && typeof data.sessions === "object" && data.sessions
        ? data.sessions
        : {},
  };
}

export async function writeRoot(root) {
  const token = blobToken();
  await put(BLOB_PATH, JSON.stringify(root), {
    access: "public",
    addRandomSuffix: false,
    allowOverwrite: true,
    contentType: "application/json",
    cacheControlMaxAge: 0,
    token,
  });
  return root;
}

export function normalizeUsername(value) {
  const username = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "-")
    .replace(/[^a-z0-9._@+-]/g, "")
    .slice(0, 64);
  if (!username || username.length < 2) {
    throw new Error("username inválido");
  }
  return username;
}

export async function listSessions() {
  const root = await readRoot();
  return Object.keys(root.sessions)
    .sort()
    .map((username) => {
      const session = root.sessions[username] || emptySession();
      return {
        username,
        credentialCount: session.credentials?.length || 0,
        updatedAt: session.updatedAt || null,
        hasUser: Boolean(session.user),
      };
    });
}

export async function getSession(username) {
  const root = await readRoot();
  const key = normalizeUsername(username);
  const session = root.sessions[key] || emptySession();
  return { username: key, ...session };
}

export async function putSession(username, body) {
  const root = await readRoot();
  const key = normalizeUsername(username);
  const next = {
    user: body?.user ?? null,
    credentials: Array.isArray(body?.credentials) ? body.credentials : [],
    updatedAt: new Date().toISOString(),
  };
  root.sessions[key] = next;
  await writeRoot(root);
  return { username: key, ...next };
}

export async function deleteSession(username) {
  const root = await readRoot();
  const key = normalizeUsername(username);
  const existed = Boolean(root.sessions[key]);
  delete root.sessions[key];
  await writeRoot(root);
  return { ok: true, username: key, removed: existed };
}

export async function clearAllSessions() {
  const root = await readRoot();
  const usernames = Object.keys(root.sessions);
  await writeRoot(emptyRoot());
  return { ok: true, cleared: usernames.length, usernames };
}
