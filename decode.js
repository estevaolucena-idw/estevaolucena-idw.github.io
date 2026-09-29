/**
 * Decodifica clientDataJSON, authenticatorData e attestationObject (CBOR).
 * Usa cbor-x via esm.sh.
 */
import { decode as cborDecode } from "https://esm.sh/cbor-x@1.6.0";

const textDecoder = new TextDecoder();

export function bufferToHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlToBuffer(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  const binary = atob(padded + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function decodeClientDataJSON(clientDataJSON) {
  const buffer =
    typeof clientDataJSON === "string"
      ? base64UrlToBuffer(clientDataJSON)
      : clientDataJSON;
  const json = JSON.parse(textDecoder.decode(buffer));
  return {
    raw: json,
    type: json.type,
    origin: json.origin,
    challenge: json.challenge,
    crossOrigin: Boolean(json.crossOrigin),
  };
}

function parseFlags(flagsByte) {
  return {
    UP: Boolean(flagsByte & 0x01),
    UV: Boolean(flagsByte & 0x04),
    BE: Boolean(flagsByte & 0x08),
    BS: Boolean(flagsByte & 0x10),
    AT: Boolean(flagsByte & 0x40),
    ED: Boolean(flagsByte & 0x80),
  };
}

export function parseAuthenticatorData(authData) {
  const data = new Uint8Array(
    typeof authData === "string" ? base64UrlToBuffer(authData) : authData
  );
  if (data.length < 37) {
    throw new Error("authenticatorData muito curto");
  }

  const rpIdHash = data.slice(0, 32);
  const flags = parseFlags(data[32]);
  const signCount = new DataView(data.buffer, data.byteOffset + 33, 4).getUint32(0);

  let offset = 37;
  let aaguid = null;
  let credentialId = null;
  let credentialPublicKey = null;
  let credentialPublicKeyCose = null;

  if (flags.AT) {
    aaguid = bufferToHex(data.slice(offset, offset + 16));
    offset += 16;
    const credIdLen = new DataView(data.buffer, data.byteOffset + offset, 2).getUint16(0);
    offset += 2;
    credentialId = bufferToBase64Url(data.slice(offset, offset + credIdLen));
    offset += credIdLen;
    const coseBytes = data.slice(offset);
    credentialPublicKey = bufferToBase64Url(coseBytes);
    credentialPublicKeyCose = decodeCoseKey(coseBytes);
  }

  return {
    rpIdHash: bufferToHex(rpIdHash),
    flags,
    signCount,
    aaguid,
    credentialId,
    credentialPublicKey,
    credentialPublicKeyCose,
    rawLength: data.length,
  };
}

function coseGet(map, key) {
  if (map instanceof Map) {
    if (map.has(key)) return map.get(key);
    if (map.has(String(key))) return map.get(String(key));
    return undefined;
  }
  if (map && typeof map === "object") {
    if (key in map) return map[key];
    if (String(key) in map) return map[String(key)];
  }
  return undefined;
}

function decodeCoseKey(coseBytes) {
  try {
    const map = cborDecode(coseBytes);
    // COSE_Key map keys: 1=kty, 3=alg, -1=crv, -2=x, -3=y
    const kty = coseGet(map, 1);
    const alg = coseGet(map, 3);
    const crv = coseGet(map, -1);
    const x = coseGet(map, -2);
    const y = coseGet(map, -3);
    return {
      kty,
      alg,
      crv,
      x: x ? bufferToBase64Url(x) : undefined,
      y: y ? bufferToBase64Url(y) : undefined,
      algName: alg === -7 ? "ES256" : alg === -257 ? "RS256" : String(alg),
      ktyName: kty === 2 ? "EC2" : kty === 3 ? "RSA" : String(kty),
    };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

export function decodeAttestationObject(attestationObject) {
  const buffer =
    typeof attestationObject === "string"
      ? base64UrlToBuffer(attestationObject)
      : attestationObject;
  const decoded = cborDecode(new Uint8Array(buffer));
  const fmt = decoded.get?.("fmt") ?? decoded.fmt;
  const authDataRaw = decoded.get?.("authData") ?? decoded.authData;
  const attStmt = decoded.get?.("attStmt") ?? decoded.attStmt;
  const authenticatorData = parseAuthenticatorData(authDataRaw);

  return {
    fmt,
    attStmt: summarizeAttStmt(attStmt),
    authenticatorData,
  };
}

function summarizeAttStmt(attStmt) {
  if (!attStmt) return null;
  if (attStmt instanceof Map) {
    const out = {};
    attStmt.forEach((value, key) => {
      out[key] = value instanceof Uint8Array ? bufferToBase64Url(value) : value;
    });
    return out;
  }
  return attStmt;
}

export async function sha256Hex(input) {
  const data =
    typeof input === "string" ? new TextEncoder().encode(input) : new Uint8Array(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return bufferToHex(hash);
}

export function decodeRegistrationResponse(credential) {
  const response = credential.response || credential;
  const clientData = decodeClientDataJSON(response.clientDataJSON);
  const attestation = decodeAttestationObject(response.attestationObject);
  return {
    id: credential.id,
    type: credential.type,
    rawId: typeof credential.rawId === "string" ? credential.rawId : bufferToBase64Url(credential.rawId),
    clientData,
    attestation,
    transports: response.getTransports?.() || credential.transports || [],
  };
}

export function decodeAuthenticationResponse(credential) {
  const response = credential.response || credential;
  const clientData = decodeClientDataJSON(response.clientDataJSON);
  const authenticatorData = parseAuthenticatorData(response.authenticatorData);
  const userHandle = response.userHandle
    ? bufferToBase64Url(
        typeof response.userHandle === "string"
          ? base64UrlToBuffer(response.userHandle)
          : response.userHandle
      )
    : null;

  return {
    id: credential.id,
    type: credential.type,
    rawId: typeof credential.rawId === "string" ? credential.rawId : bufferToBase64Url(credential.rawId),
    clientData,
    authenticatorData,
    signature: bufferToBase64Url(
      typeof response.signature === "string"
        ? base64UrlToBuffer(response.signature)
        : response.signature
    ),
    userHandle,
  };
}

/**
 * Decodifica uma resposta colada (JSON do app nativo ou da web).
 * Aceita PublicKeyCredential serializado ou apenas o bloco response.
 */
export async function inspectExternalResponse(rawJson, expectedRpId) {
  const parsed = typeof rawJson === "string" ? JSON.parse(rawJson) : rawJson;
  const credential = parsed.response ? parsed : { id: parsed.id, response: parsed };
  const response = credential.response;

  if (response.attestationObject) {
    const decoded = decodeRegistrationResponse(credential);
    const expectedHash = expectedRpId ? await sha256Hex(expectedRpId) : null;
    return {
      ceremony: "registration",
      origin: decoded.clientData.origin,
      challenge: decoded.clientData.challenge,
      type: decoded.clientData.type,
      rpIdHash: decoded.attestation.authenticatorData.rpIdHash,
      rpIdHashMatches: expectedHash
        ? decoded.attestation.authenticatorData.rpIdHash === expectedHash
        : null,
      flags: decoded.attestation.authenticatorData.flags,
      aaguid: decoded.attestation.authenticatorData.aaguid,
      credentialId: decoded.attestation.authenticatorData.credentialId || decoded.id,
      fmt: decoded.attestation.fmt,
      cose: decoded.attestation.authenticatorData.credentialPublicKeyCose,
      decoded,
    };
  }

  if (response.authenticatorData || response.signature) {
    const decoded = decodeAuthenticationResponse(credential);
    const expectedHash = expectedRpId ? await sha256Hex(expectedRpId) : null;
    return {
      ceremony: "authentication",
      origin: decoded.clientData.origin,
      challenge: decoded.clientData.challenge,
      type: decoded.clientData.type,
      rpIdHash: decoded.authenticatorData.rpIdHash,
      rpIdHashMatches: expectedHash
        ? decoded.authenticatorData.rpIdHash === expectedHash
        : null,
      flags: decoded.authenticatorData.flags,
      signCount: decoded.authenticatorData.signCount,
      signature: decoded.signature,
      userHandle: decoded.userHandle,
      decoded,
    };
  }

  throw new Error("JSON sem attestationObject nem authenticatorData/signature.");
}
