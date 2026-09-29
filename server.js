/**
 * Servidor simulado no navegador.
 * Contrato alinhado a um backend real: register/authenticate options+verify.
 * Verificação via WebCrypto (ES256) — @simplewebauthn/server não roda no browser.
 */
import {
  base64UrlToBuffer,
  bufferToBase64Url,
  decodeAttestationObject,
  decodeClientDataJSON,
  parseAuthenticatorData,
  sha256Hex,
} from "./decode.js";

const STORE_KEY = "poc-passkey:store";
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

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

function loadStore() {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (!raw) return { users: [], credentials: [], challenge: null };
    const parsed = JSON.parse(raw);
    return {
      users: parsed.users || [],
      credentials: parsed.credentials || [],
      challenge: parsed.challenge || null,
    };
  } catch {
    return { users: [], credentials: [], challenge: null };
  }
}

function saveStore(store) {
  localStorage.setItem(
    STORE_KEY,
    JSON.stringify({
      users: store.users,
      credentials: store.credentials,
      challenge: store.challenge,
    })
  );
}

export function getStoreSnapshot() {
  const store = loadStore();
  return {
    users: store.users,
    credentials: store.credentials,
    challenge: store.challenge
      ? {
          type: store.challenge.type,
          expiresAt: store.challenge.expiresAt,
          expired: store.challenge.expiresAt < Date.now(),
        }
      : null,
  };
}

export function clearStore() {
  localStorage.removeItem(STORE_KEY);
  emitTimeline({
    route: "clearStore",
    ok: true,
    request: null,
    response: { cleared: true },
    durationMs: 0,
    at: new Date().toISOString(),
  });
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
  const store = loadStore();
  const { challenge } = store;
  store.challenge = null;
  saveStore(store);
  if (!challenge || challenge.type !== expectedType || challenge.expiresAt < Date.now()) {
    throw pocError("CHALLENGE_EXPIRED", "Desafio expirado ou inexistente. Tente novamente.", {
      expectedType,
      hadChallenge: Boolean(challenge),
    });
  }
  return challenge.value;
}

function setChallenge(type, value) {
  const store = loadStore();
  store.challenge = {
    type,
    value,
    expiresAt: Date.now() + CHALLENGE_TTL_MS,
  };
  saveStore(store);
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

export async function registerOptions(userName = "poc-user") {
  return withTimeline("registerOptions", { userName }, async () => {
    const store = loadStore();
    let user = store.users.find((item) => item.name === userName);
    if (!user) {
      user = { id: randomUserId(), name: userName, displayName: userName };
      store.users.push(user);
      saveStore(store);
    }

    const challenge = randomChallenge();
    setChallenge("registration", challenge);

    const excludeCredentials = store.credentials.map((cred) => ({
      type: "public-key",
      id: cred.credentialId,
      transports: cred.transports,
    }));

    return {
      challenge,
      rp: {
        name: "PoC Passkey",
        id: location.hostname,
      },
      user: {
        id: user.id,
        name: user.name,
        displayName: user.displayName,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      timeout: 60000,
      attestation: "none",
      excludeCredentials,
      authenticatorSelection: {
        residentKey: "required",
        requireResidentKey: true,
        userVerification: "required",
      },
    };
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

/** Converte assinatura DER (ECDSA) para r||s (64 bytes). */
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
    if (clientData.origin !== location.origin) {
      throw pocError("VERIFICATION_FAILED", "Origin não confere.", {
        expected: location.origin,
        got: clientData.origin,
      });
    }

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
    const store = loadStore();
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
    };
    store.credentials = store.credentials.filter((item) => item.credentialId !== record.credentialId);
    store.credentials.push(record);
    saveStore(store);

    return {
      verified: true,
      credential: record,
      metadata: {
        clientData,
        attestation,
        expectedRpHash,
      },
    };
  });
}

export async function authenticateOptions() {
  return withTimeline("authenticateOptions", {}, async () => {
    const store = loadStore();
    if (!store.credentials.length) {
      throw pocError("CREDENTIAL_NOT_FOUND", "Nenhuma Passkey cadastrada neste navegador.");
    }

    const challenge = randomChallenge();
    setChallenge("authentication", challenge);

    return {
      challenge,
      timeout: 60000,
      rpId: location.hostname,
      // Discoverable: sem allowCredentials
      userVerification: "required",
    };
  });
}

export async function authenticateVerify(credential) {
  return withTimeline("authenticateVerify", { id: credential?.id }, async () => {
    const expectedChallenge = takeChallenge("authentication");
    const store = loadStore();
    const stored = store.credentials.find((item) => item.credentialId === credential.id);
    if (!stored) {
      throw pocError(
        "CREDENTIAL_NOT_FOUND",
        "Credencial não encontrada no store local deste navegador.",
        { id: credential.id }
      );
    }

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
    if (clientData.origin !== location.origin) {
      throw pocError("VERIFICATION_FAILED", "Origin não confere.", {
        expected: location.origin,
        got: clientData.origin,
      });
    }

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

    const ok = await verifyAssertionSignature(
      stored.publicKeyCose,
      response.authenticatorData,
      response.clientDataJSON,
      response.signature
    );
    if (!ok) {
      throw pocError("VERIFICATION_FAILED", "Assinatura da Passkey inválida.");
    }

    stored.counter = authData.signCount;
    stored.lastUsedAt = new Date().toISOString();
    saveStore(store);

    return {
      verified: true,
      credential: stored,
      metadata: {
        clientData,
        authenticatorData: authData,
        expectedRpHash,
      },
    };
  });
}

export function hasLocalCredentials() {
  return loadStore().credentials.length > 0;
}
