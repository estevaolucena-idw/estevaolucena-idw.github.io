/**
 * Servidor mock no navegador (WebAuthn + verificação).
 * Sessões/credenciais centralizadas na API Vercel (api-client.js).
 * Challenge da cerimônia permanece local (sessionStorage).
 */
import {
  base64UrlToBuffer,
  bufferToBase64Url,
  decodeAttestationObject,
  decodeClientDataJSON,
  parseAuthenticatorData,
  sha256Hex,
} from "./decode.js";
import {
  apiClearAllSessions,
  apiDeleteSession,
  apiGetSession,
  apiHealth,
  apiListSessions,
  apiPutSession,
  getApiBase,
} from "./api-client.js";

/** Fingerprints / packages espelhados de .well-known/assetlinks.json */
const ANDROID_FINGERPRINTS = [
  "4C:AB:A3:7A:62:20:D2:AA:B0:C9:A6:D1:10:94:97:C2:52:53:18:6F:3C:F1:52:77:27:91:D1:0C:D6:48:17:15",
  "3D:C5:06:AD:57:56:F9:26:94:4C:B8:70:75:07:AE:17:EA:A0:BE:8B:7D:12:3D:C1:45:4B:BB:2A:88:86:C1:D3",
  "FA:E1:14:07:AC:F1:B3:9A:36:73:07:D2:88:05:EB:A5:60:20:30:11:46:8F:E1:F8:C9:88:F8:FA:33:04:36:A7",
  "BC:C9:14:C3:87:61:0F:56:55:B0:A5:F3:E9:67:D4:C5:E3:81:1C:36:14:CB:1D:8E:4B:80:8D:1C:59:32:81:EA",
  "5A:9C:15:28:24:FB:DB:23:D8:AB:7C:EF:70:84:87:3B:FA:16:D9:69:41:58:0F:DF:9C:0A:BA:D8:D2:24:35:EC",
];

const ANDROID_PACKAGES = [
  "co.idwall.sdk.webview.app1",
  "co.idwall.sdk.webview.app2",
  "co.idwall.sdk.webview.app3",
  "co.idwall.sdk.webview.app4",
  "co.idwall.sdk.webview.app5",
];

function fingerprintToApkKeyHash(fingerprint) {
  const bytes = Uint8Array.from(fingerprint.split(":").map((part) => parseInt(part, 16)));
  return bufferToBase64Url(bytes);
}

const ALLOWED_ANDROID_ORIGINS = new Map(
  ANDROID_FINGERPRINTS.map((fp, index) => [
    `android:apk-key-hash:${fingerprintToApkKeyHash(fp)}`,
    { packageName: ANDROID_PACKAGES[index], fingerprint: fp },
  ])
);

function assertAllowedOrigin(origin) {
  if (origin === location.origin) {
    return { kind: "web", origin };
  }
  const android = ALLOWED_ANDROID_ORIGINS.get(origin);
  if (android) {
    return { kind: "android", origin, ...android };
  }
  throw pocError("VERIFICATION_FAILED", "Origin não confere.", {
    expected: [location.origin, ...ALLOWED_ANDROID_ORIGINS.keys()],
    got: origin,
    hint: origin?.startsWith("android:apk-key-hash:")
      ? "Origin de app Android. Inclua o fingerprint deste APK em assetlinks.json."
      : "Origin inesperado para esta PoC.",
  });
}

/** @type {Array<(entry: object) => void>} */
const timelineListeners = [];

export function onTimeline(listener) {
  timelineListeners.push(listener);
  return () => {
    const idx = timelineListeners.indexOf(listener);
    if (idx >= 0) timelineListeners.splice(idx, 1);
  };
}

function emitTimeline(entry) {
  timelineListeners.forEach((listener) => listener(entry));
}

function pocError(code, message, details = null) {
  const error = new Error(message);
  error.code = code;
  error.details = details;
  error.name = "PasskeyPocError";
  return error;
}

function normalizeUsername(value) {
  const username = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "-")
    .replace(/[^a-z0-9._@+-]/g, "")
    .slice(0, 64);
  if (!username || username.length < 2) {
    throw pocError("INVALID_USERNAME", "Informe um usuário com pelo menos 2 caracteres válidos.");
  }
  return username;
}

const SESSION_KEY = "poc-passkey:session-user";
const CHALLENGE_KEY = "poc-passkey:pending-challenge";
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

function emptySession(username) {
  return { username, user: null, credentials: [], updatedAt: null };
}

function readLocalChallenge() {
  try {
    const raw = sessionStorage.getItem(CHALLENGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function writeLocalChallenge(challenge) {
  if (!challenge) sessionStorage.removeItem(CHALLENGE_KEY);
  else sessionStorage.setItem(CHALLENGE_KEY, JSON.stringify(challenge));
}

export async function listSessions() {
  const data = await apiListSessions();
  return data.sessions || [];
}

export async function getSession(username) {
  return apiGetSession(username);
}

export async function ensureSession(username) {
  try {
    return await apiGetSession(username);
  } catch (error) {
    if (error.status === 404 || error.status === 400) {
      return apiPutSession(username, { user: null, credentials: [] });
    }
    // sessão inexistente: API devolve bucket vazio 200 — então só cria se falhar
    return apiPutSession(username, { user: null, credentials: [] });
  }
}

export async function upsertSession(username, patch) {
  const current = await apiGetSession(username).catch(() => emptySession(username));
  return apiPutSession(username, {
    user: patch.user !== undefined ? patch.user : current.user,
    credentials:
      patch.credentials !== undefined ? patch.credentials : current.credentials || [],
  });
}

export async function removeSession(username) {
  const result = await apiDeleteSession(username);
  emitTimeline({
    route: "removeSession",
    ok: true,
    request: { username },
    response: result,
    durationMs: 0,
    at: new Date().toISOString(),
  });
  return result.removed;
}

export async function clearAllSessions() {
  const result = await apiClearAllSessions();
  emitTimeline({
    route: "clearAllSessions",
    ok: true,
    request: null,
    response: result,
    durationMs: 0,
    at: new Date().toISOString(),
  });
  return result;
}

export function getSessionUser() {
  try {
    return sessionStorage.getItem(SESSION_KEY) || localStorage.getItem(SESSION_KEY) || "";
  } catch {
    return "";
  }
}

export async function setSessionUser(rawUsername) {
  const username = normalizeUsername(rawUsername);
  sessionStorage.setItem(SESSION_KEY, username);
  localStorage.setItem(SESSION_KEY, username);
  const session = await ensureSession(username);
  emitTimeline({
    route: "setSessionUser",
    ok: true,
    request: { username, apiBase: getApiBase() },
    response: {
      username,
      credentialCount: session.credentials?.length || 0,
    },
    durationMs: 0,
    at: new Date().toISOString(),
  });
  return username;
}

export function clearSessionUser() {
  sessionStorage.removeItem(SESSION_KEY);
}

function requireSessionUsername() {
  const username = getSessionUser();
  if (!username) {
    throw pocError("NO_SESSION", "Defina um nome de usuário para iniciar a sessão de teste.");
  }
  return username;
}

async function loadStore() {
  const username = requireSessionUsername();
  const session = await apiGetSession(username);
  return {
    username,
    user: session.user || null,
    credentials: session.credentials || [],
    challenge: readLocalChallenge(),
  };
}

async function saveStore(store) {
  await apiPutSession(store.username, {
    user: store.user,
    credentials: store.credentials,
  });
  // challenge só local
  writeLocalChallenge(store.challenge || null);
}

export async function listSessionUsernames() {
  const sessions = await listSessions();
  return sessions.map((s) => s.username).sort();
}

export async function getStoreSnapshot() {
  const username = getSessionUser();
  const sessions = await listSessions();
  if (!username) {
    return {
      sessionUser: null,
      credentials: [],
      challenge: null,
      sessions,
      apiBase: getApiBase(),
    };
  }
  const session = await apiGetSession(username);
  const challenge = readLocalChallenge();
  return {
    sessionUser: username,
    user: session.user,
    credentials: session.credentials || [],
    challenge: challenge
      ? {
          type: challenge.type,
          expiresAt: challenge.expiresAt,
          expired: challenge.expiresAt < Date.now(),
        }
      : null,
    sessions,
    apiBase: getApiBase(),
  };
}

export async function clearStore() {
  const username = getSessionUser();
  if (!username) {
    emitTimeline({
      route: "clearStore",
      ok: true,
      request: null,
      response: { cleared: false, reason: "no-session" },
      durationMs: 0,
      at: new Date().toISOString(),
    });
    return { cleared: false };
  }
  await apiPutSession(username, { user: null, credentials: [] });
  writeLocalChallenge(null);
  emitTimeline({
    route: "clearStore",
    ok: true,
    request: { username },
    response: { cleared: true, username },
    durationMs: 0,
    at: new Date().toISOString(),
  });
  return { cleared: true, username };
}

export async function checkApiHealth() {
  return apiHealth();
}

function randomChallenge() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bufferToBase64Url(bytes);
}

function randomUserId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bufferToBase64Url(bytes);
}

function takeChallenge(expectedType) {
  const challenge = readLocalChallenge();
  writeLocalChallenge(null);
  if (!challenge || challenge.type !== expectedType || challenge.expiresAt < Date.now()) {
    throw pocError("CHALLENGE_EXPIRED", "Desafio expirado ou inexistente. Tente novamente.", {
      expectedType,
      hadChallenge: Boolean(challenge),
    });
  }
  return challenge.value;
}

function setChallenge(type, value) {
  writeLocalChallenge({
    type,
    value,
    expiresAt: Date.now() + CHALLENGE_TTL_MS,
  });
}

async function withTimeline(route, request, action) {
  const started = performance.now();
  const at = new Date().toISOString();
  try {
    const response = await action();
    emitTimeline({
      route,
      ok: true,
      request,
      response,
      durationMs: Math.round(performance.now() - started),
      at,
    });
    return response;
  } catch (error) {
    const normalized = {
      code: error.code || "BROWSER_ERROR",
      message: error instanceof Error ? error.message : String(error),
      details: error.details || null,
    };
    emitTimeline({
      route,
      ok: false,
      request,
      response: normalized,
      durationMs: Math.round(performance.now() - started),
      at,
    });
    throw error;
  }
}

export async function registerOptions(userName, capabilities = {}) {
  const sessionUser = userName ? normalizeUsername(userName) : requireSessionUsername();
  if (getSessionUser() !== sessionUser) {
    await setSessionUser(sessionUser);
  }

  return withTimeline("registerOptions", { userName: sessionUser, capabilities }, async () => {
    const store = await loadStore();
    if (!store.user || store.user.name !== sessionUser) {
      store.user = {
        id: randomUserId(),
        name: sessionUser,
        displayName: sessionUser,
      };
      await saveStore(store);
    }

    const challenge = randomChallenge();
    setChallenge("registration", challenge);

    const excludeCredentials = store.credentials.map((cred) => ({
      type: "public-key",
      id: cred.credentialId,
      transports: cred.transports,
    }));

    const preferPlatform = Boolean(capabilities.platformAuthenticator);
    const authenticatorSelection = {
      residentKey: preferPlatform ? "required" : "preferred",
      requireResidentKey: preferPlatform,
      userVerification: "required",
    };

    if (preferPlatform) {
      authenticatorSelection.authenticatorAttachment = "platform";
    } else if (capabilities.crossPlatformOnly) {
      authenticatorSelection.authenticatorAttachment = "cross-platform";
    }

    const options = {
      challenge,
      rp: {
        name: "PoC Passkey",
        id: location.hostname,
      },
      user: {
        id: store.user.id,
        name: store.user.name,
        displayName: store.user.displayName,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      timeout: 120000,
      attestation: "none",
      excludeCredentials,
      authenticatorSelection,
    };

    if (preferPlatform) {
      options.hints = ["client-device"];
    }

    return options;
  });
}

function coseToJwk(cose) {
  if (!cose || cose.kty !== 2 || cose.alg !== -7) {
    throw pocError("VERIFICATION_FAILED", "Só ES256 (EC2 P-256) é suportado neste PoC.", { cose });
  }
  return {
    kty: "EC",
    crv: "P-256",
    x: cose.x,
    y: cose.y,
    ext: true,
  };
}

async function importPublicKey(cose) {
  const jwk = coseToJwk(cose);
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
}

function derToRaw(signatureDer) {
  const der = new Uint8Array(signatureDer);
  if (der[0] !== 0x30) {
    if (der.length === 64) return der;
    throw pocError("VERIFICATION_FAILED", "Assinatura ECDSA em formato inesperado.");
  }
  let offset = 2;
  if (der[1] & 0x80) offset += der[1] & 0x7f;

  if (der[offset] !== 0x02) throw pocError("VERIFICATION_FAILED", "DER inválido (r).");
  const rLen = der[offset + 1];
  let r = der.slice(offset + 2, offset + 2 + rLen);
  offset += 2 + rLen;

  if (der[offset] !== 0x02) throw pocError("VERIFICATION_FAILED", "DER inválido (s).");
  const sLen = der[offset + 1];
  let s = der.slice(offset + 2, offset + 2 + sLen);

  if (r.length > 32) r = r.slice(r.length - 32);
  if (s.length > 32) s = s.slice(s.length - 32);

  const raw = new Uint8Array(64);
  raw.set(r, 32 - r.length);
  raw.set(s, 64 - s.length);
  return raw;
}

async function verifyAssertionSignature(publicKeyCose, authenticatorData, clientDataJSON, signature) {
  const key = await importPublicKey(publicKeyCose);
  const authData = new Uint8Array(
    typeof authenticatorData === "string" ? base64UrlToBuffer(authenticatorData) : authenticatorData
  );
  const clientData =
    typeof clientDataJSON === "string" ? base64UrlToBuffer(clientDataJSON) : clientDataJSON;
  const clientHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientData));
  const signed = new Uint8Array(authData.length + clientHash.length);
  signed.set(authData, 0);
  signed.set(clientHash, authData.length);

  const sigRaw = derToRaw(
    typeof signature === "string" ? base64UrlToBuffer(signature) : signature
  );

  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sigRaw, signed);
}

export async function registerVerify(credential) {
  return withTimeline("registerVerify", { id: credential?.id }, async () => {
    const expectedChallenge = takeChallenge("registration");
    const response = credential.response;
    const clientData = decodeClientDataJSON(response.clientDataJSON);

    if (clientData.type !== "webauthn.create") {
      throw pocError("VERIFICATION_FAILED", "clientDataJSON.type inválido.", { type: clientData.type });
    }
    if (clientData.challenge !== expectedChallenge) {
      throw pocError("VERIFICATION_FAILED", "Challenge não confere.", {
        expected: expectedChallenge,
        got: clientData.challenge,
      });
    }
    const originInfo = assertAllowedOrigin(clientData.origin);

    const attestation = decodeAttestationObject(response.attestationObject);
    const authData = attestation.authenticatorData;
    const expectedRpHash = await sha256Hex(location.hostname);
    if (authData.rpIdHash !== expectedRpHash) {
      throw pocError("VERIFICATION_FAILED", "rpIdHash não confere.", {
        expected: expectedRpHash,
        got: authData.rpIdHash,
      });
    }
    if (!authData.flags.UP || !authData.flags.UV) {
      throw pocError("VERIFICATION_FAILED", "User presence/verification ausente.", {
        flags: authData.flags,
      });
    }
    if (!authData.credentialId || !authData.credentialPublicKeyCose) {
      throw pocError("VERIFICATION_FAILED", "Credencial não encontrada no attestation.");
    }

    const transports = response.getTransports?.() || credential.transports || [];
    const store = await loadStore();
    const record = {
      credentialId: authData.credentialId,
      publicKeyCose: authData.credentialPublicKeyCose,
      publicKey: authData.credentialPublicKey,
      counter: authData.signCount,
      transports,
      aaguid: authData.aaguid,
      deviceType: authData.flags.BS ? "multiDevice" : "singleDevice",
      backedUp: Boolean(authData.flags.BE && authData.flags.BS),
      createdAt: new Date().toISOString(),
      lastUsedAt: null,
      username: store.username,
      registeredOrigin: originInfo,
    };
    store.credentials = store.credentials.filter((item) => item.credentialId !== record.credentialId);
    store.credentials.push(record);
    await saveStore(store);

    return {
      verified: true,
      credential: record,
      metadata: {
        clientData,
        attestation,
        expectedRpHash,
        originInfo,
      },
    };
  });
}

export async function authenticateOptions(capabilities = {}) {
  return withTimeline("authenticateOptions", { capabilities }, async () => {
    const store = await loadStore();
    // Discoverable: não exige credenciais no store local.
    // Assim dá para autenticar no celular com passkey sincronizada (GPM/iCloud)
    // mesmo sem a chave pública cadastrada neste navegador.
    const challenge = randomChallenge();
    setChallenge("authentication", challenge);

    const options = {
      challenge,
      timeout: 120000,
      rpId: location.hostname,
      userVerification: "required",
      localCredentialCount: store.credentials.length,
      crossDeviceHint: store.credentials.length === 0,
    };

    if (capabilities.platformAuthenticator) {
      options.hints = ["client-device"];
    }

    return options;
  });
}

export async function authenticateVerify(credential) {
  return withTimeline("authenticateVerify", { id: credential?.id }, async () => {
    const expectedChallenge = takeChallenge("authentication");
    const store = await loadStore();
    let stored = store.credentials.find((item) => item.credentialId === credential.id);

    const response = credential.response;
    const clientData = decodeClientDataJSON(response.clientDataJSON);

    if (clientData.type !== "webauthn.get") {
      throw pocError("VERIFICATION_FAILED", "clientDataJSON.type inválido.", { type: clientData.type });
    }
    if (clientData.challenge !== expectedChallenge) {
      throw pocError("VERIFICATION_FAILED", "Challenge não confere.", {
        expected: expectedChallenge,
        got: clientData.challenge,
      });
    }

    const originInfo = assertAllowedOrigin(clientData.origin);
    const authData = parseAuthenticatorData(response.authenticatorData);
    const expectedRpHash = await sha256Hex(location.hostname);
    if (authData.rpIdHash !== expectedRpHash) {
      throw pocError("VERIFICATION_FAILED", "rpIdHash não confere.", {
        expected: expectedRpHash,
        got: authData.rpIdHash,
      });
    }
    if (!authData.flags.UP || !authData.flags.UV) {
      throw pocError("VERIFICATION_FAILED", "User presence/verification ausente.", {
        flags: authData.flags,
      });
    }

    let verificationMode = "full";
    let signatureVerified = false;

    if (stored?.publicKeyCose) {
      const ok = await verifyAssertionSignature(
        stored.publicKeyCose,
        response.authenticatorData,
        response.clientDataJSON,
        response.signature
      );
      if (!ok) {
        throw pocError("VERIFICATION_FAILED", "Assinatura da Passkey inválida.");
      }
      signatureVerified = true;
      stored.counter = authData.signCount;
      stored.lastUsedAt = new Date().toISOString();
      stored.lastOrigin = originInfo;
    } else {
      // Passkey veio de outro dispositivo (sync do gerenciador) sem chave pública local.
      // Validamos a cerimônia (challenge/origin/rpId/UV); a assinatura exige importar o export.
      verificationMode = "cross-device-assertion";
      signatureVerified = false;
      stored = {
        credentialId: credential.id,
        publicKeyCose: null,
        publicKey: null,
        counter: authData.signCount,
        transports: credential.response?.transports || [],
        aaguid: null,
        deviceType: authData.flags.BS ? "multiDevice" : "singleDevice",
        backedUp: Boolean(authData.flags.BE && authData.flags.BS),
        createdAt: null,
        lastUsedAt: new Date().toISOString(),
        username: store.username,
        lastOrigin: originInfo,
        notedFromCrossDevice: true,
      };
      const idx = store.credentials.findIndex((item) => item.credentialId === credential.id);
      if (idx >= 0) store.credentials[idx] = { ...store.credentials[idx], ...stored };
      else store.credentials.push(stored);
    }

    await saveStore(store);

    return {
      verified: true,
      verificationMode,
      signatureVerified,
      credential: stored,
      metadata: {
        clientData,
        authenticatorData: authData,
        expectedRpHash,
        originInfo,
        note:
          verificationMode === "cross-device-assertion"
            ? "Cerimônia OK neste aparelho. Sem chave pública nesta sessão mock — cadastre aqui ou use o mesmo navegador do cadastro para verificação completa."
            : null,
      },
    };
  });
}

export async function hasLocalCredentials() {
  const username = getSessionUser();
  if (!username) return false;
  const session = await apiGetSession(username);
  return Boolean(session?.credentials?.length);
}

export async function hasVerifiableCredentials() {
  const username = getSessionUser();
  if (!username) return false;
  const session = await apiGetSession(username);
  return Boolean(session?.credentials?.some((c) => c.publicKeyCose));
}
