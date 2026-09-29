import {
  authenticateOptions,
  authenticateVerify,
  clearStore,
  getStoreSnapshot,
  hasLocalCredentials,
  onTimeline,
  registerOptions,
  registerVerify,
} from "./server.js";
import {
  decodeAuthenticationResponse,
  decodeRegistrationResponse,
  inspectExternalResponse,
  sha256Hex,
} from "./decode.js";

const $ = (id) => document.getElementById(id);

const els = {
  status: $("status"),
  btnContinue: $("btn-continue"),
  btnRegister: $("btn-register"),
  btnClear: $("btn-clear"),
  btnInspect: $("btn-inspect"),
  flowPanel: $("flow-panel"),
  successPanel: $("success-panel"),
  timeline: $("timeline"),
  storeView: $("store-view"),
  lastMeta: $("last-meta"),
  inspectorInput: $("inspector-input"),
  inspectorOut: $("inspector-out"),
  rpId: $("rp-id"),
  origin: $("origin"),
};

const timeline = [];

function setStatus(message, kind = "idle") {
  els.status.textContent = message;
  els.status.className = `status ${kind}`;
}

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function refreshStore() {
  els.storeView.textContent = pretty(getStoreSnapshot());
}

function renderTimeline() {
  if (!timeline.length) {
    els.timeline.innerHTML = `<p class="muted">Nenhuma cerimônia ainda.</p>`;
    return;
  }
  els.timeline.innerHTML = timeline
    .slice()
    .reverse()
    .map(
      (item) => `
      <article class="timeline-item">
        <header>
          <strong>${item.route}</strong>
          <span class="badge ${item.ok ? "ok" : "err"}">${item.ok ? "ok" : "erro"}</span>
          <span class="muted">${item.durationMs}ms · ${item.at}</span>
        </header>
        <details>
          <summary>request / response</summary>
          <pre class="json">${pretty({ request: item.request, response: item.response })}</pre>
        </details>
      </article>`
    )
    .join("");
}

onTimeline((entry) => {
  timeline.push(entry);
  renderTimeline();
  refreshStore();
});

function bufferSourceToBase64Url(value) {
  if (typeof value === "string") return value;
  const bytes = new Uint8Array(value);
  let binary = "";
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBuffer(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  const binary = atob(padded + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/** Converte options JSON (ids em base64url) para ArrayBuffer no navigator.credentials. */
function prepareCreateOptions(options) {
  return {
    publicKey: {
      ...options,
      challenge: base64UrlToBuffer(options.challenge),
      user: {
        ...options.user,
        id: base64UrlToBuffer(options.user.id),
      },
      excludeCredentials: (options.excludeCredentials || []).map((cred) => ({
        ...cred,
        id: base64UrlToBuffer(cred.id),
      })),
    },
  };
}

function prepareGetOptions(options) {
  return {
    publicKey: {
      ...options,
      challenge: base64UrlToBuffer(options.challenge),
      allowCredentials: (options.allowCredentials || []).map((cred) => ({
        ...cred,
        id: base64UrlToBuffer(cred.id),
      })),
    },
  };
}

function serializeCredential(credential) {
  const response = credential.response;
  const base = {
    id: credential.id,
    rawId: bufferSourceToBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment || null,
    clientExtensionResults: credential.getClientExtensionResults?.() || {},
  };

  if (response.attestationObject) {
    return {
      ...base,
      response: {
        clientDataJSON: bufferSourceToBase64Url(response.clientDataJSON),
        attestationObject: bufferSourceToBase64Url(response.attestationObject),
        transports: response.getTransports?.() || [],
      },
      transports: response.getTransports?.() || [],
    };
  }

  return {
    ...base,
    response: {
      clientDataJSON: bufferSourceToBase64Url(response.clientDataJSON),
      authenticatorData: bufferSourceToBase64Url(response.authenticatorData),
      signature: bufferSourceToBase64Url(response.signature),
      userHandle: response.userHandle ? bufferSourceToBase64Url(response.userHandle) : null,
    },
  };
}

async function showCeremonyMeta(kind, options, credential, verification) {
  const expectedRpHash = await sha256Hex(location.hostname);
  let decoded;
  if (kind === "registration") {
    decoded = decodeRegistrationResponse({
      ...credential,
      response: {
        ...credential.response,
        getTransports: () => credential.transports || [],
      },
    });
  } else {
    decoded = decodeAuthenticationResponse(credential);
  }

  const payload = {
    kind,
    options,
    expectedRpId: location.hostname,
    expectedRpHash,
    expectedOrigin: location.origin,
    decoded,
    verification: {
      verified: verification.verified,
      credential: verification.credential,
      metadata: verification.metadata,
    },
  };
  els.lastMeta.textContent = pretty(payload);
}

function showSuccess() {
  els.flowPanel.classList.add("hidden");
  els.successPanel.classList.remove("hidden");
  setStatus("Autenticado. Pode seguir.", "ok");
}

function showFlow() {
  els.successPanel.classList.add("hidden");
  els.flowPanel.classList.remove("hidden");
}

function normalizeBrowserError(error) {
  return {
    code: error.code || error.name || "BROWSER_ERROR",
    message: error instanceof Error ? error.message : String(error),
    details: error.details || null,
  };
}

async function runRegister() {
  els.btnRegister.disabled = true;
  els.btnContinue.disabled = true;
  setStatus("Gerando options de cadastro…", "idle");
  try {
    const options = await registerOptions(`poc-${location.hostname}`);
    setStatus("Aguardando cerimônia create no autenticador…", "idle");
    const credential = await navigator.credentials.create(prepareCreateOptions(options));
    if (!credential) throw new Error("Cerimônia cancelada (create retornou null).");
    const serialized = serializeCredential(credential);
    // Reanexar buffers para verificação + getTransports
    serialized.response.clientDataJSON = credential.response.clientDataJSON;
    serialized.response.attestationObject = credential.response.attestationObject;
    serialized.response.getTransports = () => credential.response.getTransports?.() || [];

    setStatus("Verificando cadastro…", "idle");
    const verification = await registerVerify(serialized);
    await showCeremonyMeta("registration", options, serialized, verification);
    setStatus("Passkey cadastrada e verificada.", "ok");
    showSuccess();
  } catch (error) {
    const normalized = normalizeBrowserError(error);
    setStatus(pretty(normalized), "err");
    els.lastMeta.textContent = pretty({ error: normalized });
    if (normalized.code === "NotAllowedError" || normalized.code === "BROWSER_ERROR") {
      els.btnRegister.classList.remove("hidden");
    }
  } finally {
    els.btnRegister.disabled = false;
    els.btnContinue.disabled = false;
    refreshStore();
  }
}

async function runAuthenticate() {
  els.btnRegister.disabled = true;
  els.btnContinue.disabled = true;
  setStatus("Gerando options de autenticação…", "idle");
  try {
    if (!window.PublicKeyCredential) {
      throw Object.assign(new Error("WebAuthn não suportado neste navegador."), {
        code: "BROWSER_ERROR",
      });
    }

    const options = await authenticateOptions();
    setStatus("Aguardando cerimônia get no autenticador…", "idle");
    const credential = await navigator.credentials.get(prepareGetOptions(options));
    if (!credential) throw new Error("Cerimônia cancelada (get retornou null).");

    const serialized = serializeCredential(credential);
    serialized.response.clientDataJSON = credential.response.clientDataJSON;
    serialized.response.authenticatorData = credential.response.authenticatorData;
    serialized.response.signature = credential.response.signature;
    serialized.response.userHandle = credential.response.userHandle;

    setStatus("Verificando autenticação…", "idle");
    const verification = await authenticateVerify(serialized);
    await showCeremonyMeta("authentication", options, serialized, verification);
    showSuccess();
  } catch (error) {
    const normalized = normalizeBrowserError(error);
    setStatus(pretty(normalized), "err");
    els.lastMeta.textContent = pretty({ error: normalized });

    const needsRegister =
      normalized.code === "CREDENTIAL_NOT_FOUND" ||
      normalized.code === "NotAllowedError" ||
      normalized.code === "InvalidStateError" ||
      !hasLocalCredentials();

    if (needsRegister) {
      els.btnRegister.classList.remove("hidden");
      setStatus(
        `${pretty(normalized)}\n\nNenhuma passkey utilizável aqui. Use "Cadastrar passkey".`,
        "err"
      );
    }
  } finally {
    els.btnRegister.disabled = false;
    els.btnContinue.disabled = false;
    refreshStore();
  }
}

els.btnContinue.addEventListener("click", () => {
  showFlow();
  runAuthenticate();
});

els.btnRegister.addEventListener("click", () => {
  showFlow();
  runRegister();
});

els.btnClear.addEventListener("click", () => {
  clearStore();
  timeline.length = 0;
  renderTimeline();
  refreshStore();
  els.lastMeta.textContent = "{}";
  showFlow();
  els.btnRegister.classList.add("hidden");
  setStatus("Store local limpo. A passkey no autenticador permanece.", "idle");
});

els.btnInspect.addEventListener("click", async () => {
  try {
    const result = await inspectExternalResponse(
      els.inspectorInput.value.trim(),
      location.hostname
    );
    els.inspectorOut.textContent = pretty(result);
    setStatus(`Inspetor: cerimônia ${result.ceremony}, origin=${result.origin}`, "ok");
  } catch (error) {
    const normalized = normalizeBrowserError(error);
    els.inspectorOut.textContent = pretty(normalized);
    setStatus(pretty(normalized), "err");
  }
});

async function boot() {
  els.rpId.textContent = location.hostname;
  els.origin.textContent = location.origin;
  refreshStore();
  renderTimeline();

  if (!window.isSecureContext) {
    setStatus("Contexto inseguro: WebAuthn exige HTTPS (ou localhost).", "err");
    els.btnContinue.disabled = true;
    els.btnRegister.disabled = true;
    return;
  }

  if (hasLocalCredentials()) {
    els.btnRegister.classList.add("hidden");
    setStatus('Há passkey no store local. Use "Continuar com passkey".', "idle");
  } else {
    els.btnRegister.classList.remove("hidden");
    setStatus('Nenhuma passkey no store. Use "Continuar" (pode falhar) ou "Cadastrar".', "idle");
  }
}

boot();
