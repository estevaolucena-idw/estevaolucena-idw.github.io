/**
 * Cliente HTTP da API Vercel (sessões centralizadas).
 * Defina window.__PASSKEY_API_BASE ou edite DEFAULT_API_BASE após o deploy.
 */
export const DEFAULT_API_BASE = "https://poc-passkey-api.vercel.app";

export function getApiBase() {
  if (typeof window !== "undefined" && window.__PASSKEY_API_BASE) {
    return String(window.__PASSKEY_API_BASE).replace(/\/$/, "");
  }
  return DEFAULT_API_BASE.replace(/\/$/, "");
}

async function request(path, options = {}) {
  const url = `${getApiBase()}${path}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { raw: text };
  }
  if (!response.ok) {
    const error = new Error(data?.error || `API ${response.status}`);
    error.code = "API_ERROR";
    error.status = response.status;
    error.details = data;
    throw error;
  }
  return data;
}

export function apiListSessions() {
  return request("/api/sessions");
}

export function apiGetSession(username) {
  return request(`/api/sessions/${encodeURIComponent(username)}`);
}

export function apiPutSession(username, body) {
  return request(`/api/sessions/${encodeURIComponent(username)}`, {
    method: "PUT",
    body: JSON.stringify(body),
  });
}

export function apiDeleteSession(username) {
  return request(`/api/sessions/${encodeURIComponent(username)}`, {
    method: "DELETE",
  });
}

export function apiClearAllSessions() {
  return request("/api/sessions?confirm=poc-passkey-clear", {
    method: "DELETE",
  });
}

export function apiHealth() {
  return request("/api/health");
}
