import {
  authenticateOptions,
  authenticateVerify,
  clearStore,
  getSessionUser,
  getStoreSnapshot,
  hasLocalCredentials,
  listSessionUsernames,
  onTimeline,
  registerOptions,
  registerVerify,
  setSessionUser,
} from "./server.js";
import {
  decodeAuthenticationResponse,
  decodeRegistrationResponse,
  inspectExternalResponse,
  sha256Hex,
} from "./decode.js";

const $ = (id) => document.getElementById(id);

const els = {
  rpId: $("rp-id"),
  origin: $("origin"),
  steps: $("steps"),
  panelSession: $("panel-session"),
  panelFlow: $("panel-flow"),
  panelSuccess: $("panel-success"),
  formSession: $("form-session"),
  username: $("username"),
  recentUsers: $("recent-users"),
  caps: $("caps"),
  capsFlow: $("caps-flow"),
  sessionLabel: $("session-label"),
  credBadge: $("cred-badge"),
  flowTitle: $("flow-title"),
  guide: $("guide"),
  status: $("status"),
  btnStart: $("btn-start"),
  btnContinue: $("btn-continue"),
  btnRegister: $("btn-register"),
  btnClear: $("btn-clear"),
  btnChangeUser: $("btn-change-user"),
  btnTestAgain: $("btn-test-again"),
  btnSuccessChangeUser: $("btn-success-change-user"),
  btnInspect: $("btn-inspect"),
  successDetail: $("success-detail"),
  timeline: $("timeline"),
  storeView: $("store-view"),
  lastMeta: $("last-meta"),
  inspectorInput: $("inspector-input"),
  inspectorOut: $("inspector-out"),
  diagnostics: $("diagnostics"),
};

/** @type {{ webauthn: boolean, platformAuthenticator: boolean, conditionalMediation: boolean, crossPlatformOnly: boolean, userAgent: string }} */
let capabilities = {
  webauthn: false,
  platformAuthenticator: false,
  conditionalMediation: false,
  crossPlatformOnly: false,
  userAgent: navigator.userAgent,
};

const timeline = [];

function setStatus(message, kind = "idle") {
  els.status.textContent = message;
  els.status.className = `status ${kind}`;
}

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function setStep(n) {
  els.steps.querySelectorAll(".step").forEach((el) => {
    const step = Number(el.dataset.step);
    el.classList.toggle("active", step === n);
    el.classList.toggle("done", step < n);
  });
  els.panelSession.classList.toggle("hidden", n !== 1);
  els.panelFlow.classList.toggle("hidden", n !== 2);
  els.panelSuccess.classList.toggle("hidden", n !== 3);
}

function refreshStore() {
  els.storeView.textContent = pretty(getStoreSnapshot());
  const hasCreds = hasLocalCredentials();
  els.credBadge.textContent = hasCreds ? "com passkey" : "sem passkey";
  els.credBadge.className = `badge ${hasCreds ? "ok" : ""}`;
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

async function probeCapabilities() {
  const webauthn = Boolean(window.PublicKeyCredential);
  let platformAuthenticator = false;
  let conditionalMediation = false;

  if (webauthn && typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
    try {
      platformAuthenticator = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
      platformAuthenticator = false;
    }
  }

  if (webauthn && typeof PublicKeyCredential.isConditionalMediationAvailable === "function") {
    try {
      conditionalMediation = await PublicKeyCredential.isConditionalMediationAvailable();
    } catch {
      conditionalMediation = false;
    }
  }

  capabilities = {
    webauthn,
    platformAuthenticator,
    conditionalMediation,
    crossPlatformOnly: webauthn && !platformAuthenticator,
    userAgent: navigator.userAgent,
  };
  return capabilities;
}

function renderCapabilities(target) {
  if (!target) return;
  const rows = [
    ["WebAuthn", capabilities.webauthn],
    ["Passkey neste aparelho (plataforma)", capabilities.platformAuthenticator],
    ["Mediação condicional", capabilities.conditionalMediation],
    ["Só cross-platform / hybrid", capabilities.crossPlatformOnly],
  ];
  target.innerHTML = rows
    .map(
      ([label, value]) =>
        `<div><span class="badge ${value ? "ok" : "err"}">${value ? "sim" : "não"}</span> ${label}</div>`
    )
    .join("");
}

function renderRecentUsers() {
  const users = listSessionUsernames();
  if (!users.length) {
    els.recentUsers.innerHTML = "";
    return;
  }
  els.recentUsers.innerHTML = `
    <p class="hint">Sessões já usadas neste navegador:</p>
    <div class="chip-row">
      ${users
        .map((u) => `<button type="button" class="chip" data-user="${u}">${u}</button>`)
        .join("")}
    </div>`;
  els.recentUsers.querySelectorAll("[data-user]").forEach((btn) => {
    btn.addEventListener("click", () => {
      els.username.value = btn.dataset.user;
      els.username.focus();
    });
  });
}

function applyFlowUi() {
  const username = getSessionUser();
  els.sessionLabel.textContent = username || "—";
  renderCapabilities(els.capsFlow);
  refreshStore();

  if (!window.isSecureContext) {
    setStatus("Contexto inseguro: WebAuthn exige HTTPS (ou localhost).", "err");
    els.btnContinue.disabled = true;
    els.btnRegister.disabled = true;
    els.btnRegister.classList.add("hidden");
    return;
  }

  if (!capabilities.webauthn) {
    setStatus("Este navegador não expõe WebAuthn.", "err");
    els.btnContinue.disabled = true;
    els.btnRegister.disabled = true;
    els.btnRegister.classList.add("hidden");
    return;
  }

  els.btnContinue.disabled = false;
  els.btnRegister.disabled = false;

  const hasCreds = hasLocalCredentials();
  if (hasCreds) {
    els.btnRegister.classList.add("hidden");
    els.btnContinue.classList.remove("secondary");
    els.flowTitle.textContent = "2. Continue com sua passkey";
    els.guide.innerHTML = `
      <li>Há passkey salva para <strong>${username}</strong> neste navegador.</li>
      <li>Toque em <strong>Continuar com passkey</strong>.</li>
      <li>Confirme com biometria ou bloqueio de tela.</li>`;
    setStatus(
      capabilities.platformAuthenticator
        ? "Pronto para autenticar neste aparelho."
        : "Pronto para autenticar (pode abrir hybrid/QR se não houver plataforma).",
      "idle"
    );
  } else {
    els.btnRegister.classList.remove("hidden");
    els.btnContinue.classList.add("secondary");
    els.flowTitle.textContent = "2. Cadastre uma passkey";
    els.guide.innerHTML = capabilities.platformAuthenticator
      ? `
      <li>Este aparelho suporta passkey de plataforma.</li>
      <li>Toque em <strong>Cadastrar passkey</strong>.</li>
      <li>Escolha salvar <em>neste dispositivo</em> (não use o QR de outro celular).</li>`
      : `
      <li>Sem autenticador de plataforma detectado.</li>
      <li>O cadastro pode pedir chave de segurança ou outro aparelho.</li>
      <li>Toque em <strong>Cadastrar passkey</strong> para tentar mesmo assim.</li>`;
    setStatus(
      capabilities.platformAuthenticator
        ? `Usuário "${username}" sem passkey local. Cadastre neste aparelho.`
        : `Usuário "${username}" sem passkey local. Cadastro pode usar hybrid.`,
      "idle"
    );
  }
}

function enterSession(rawUsername) {
  const username = setSessionUser(rawUsername);
  els.username.value = username;
  setStep(2);
  applyFlowUi();
  els.lastMeta.textContent = pretty({ sessionUser: username, capabilities });
}

function goToSessionStep() {
  setStep(1);
  renderRecentUsers();
  renderCapabilities(els.caps);
  els.username.focus();
}

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
  const decoded =
    kind === "registration"
      ? decodeRegistrationResponse({
          ...credential,
          response: {
            ...credential.response,
            getTransports: () => credential.transports || [],
          },
        })
      : decodeAuthenticationResponse(credential);

  els.lastMeta.textContent = pretty({
    kind,
    sessionUser: getSessionUser(),
    capabilities,
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
  });
}

function normalizeBrowserError(error) {
  return {
    code: error.code || error.name || "BROWSER_ERROR",
    message: error instanceof Error ? error.message : String(error),
    details: error.details || null,
  };
}

function showSuccess(kind) {
  setStep(3);
  const user = getSessionUser();
  els.successDetail.textContent =
    kind === "registration"
      ? `Passkey cadastrada e verificada para "${user}". Pode seguir ou testar de novo.`
      : `Autenticação verificada para "${user}". Pode seguir.`;
}

async function runRegister() {
  els.btnRegister.disabled = true;
  els.btnContinue.disabled = true;
  setStatus("Gerando options de cadastro…", "idle");
  try {
    if (!capabilities.webauthn) {
      throw Object.assign(new Error("WebAuthn não suportado."), { code: "BROWSER_ERROR" });
    }

    const username = getSessionUser();
    const options = await registerOptions(username, capabilities);
    setStatus(
      capabilities.platformAuthenticator
        ? "Aguardando passkey neste aparelho… Confirme biometria/bloqueio."
        : "Aguardando autenticador…",
      "idle"
    );
    const credential = await navigator.credentials.create(prepareCreateOptions(options));
    if (!credential) throw new Error("Cerimônia cancelada (create retornou null).");

    const serialized = serializeCredential(credential);
    serialized.response.clientDataJSON = credential.response.clientDataJSON;
    serialized.response.attestationObject = credential.response.attestationObject;
    serialized.response.getTransports = () => credential.response.getTransports?.() || [];

    setStatus("Verificando cadastro…", "idle");
    const verification = await registerVerify(serialized);
    await showCeremonyMeta("registration", options, serialized, verification);
    setStatus("Passkey cadastrada e verificada.", "ok");
    showSuccess("registration");
  } catch (error) {
    const normalized = normalizeBrowserError(error);
    setStatus(pretty({ ...normalized, sessionUser: getSessionUser(), capabilities }), "err");
    els.lastMeta.textContent = pretty({ error: normalized, capabilities });
    els.diagnostics.open = true;
    els.btnRegister.classList.remove("hidden");
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
    if (!capabilities.webauthn) {
      throw Object.assign(new Error("WebAuthn não suportado."), { code: "BROWSER_ERROR" });
    }

    const options = await authenticateOptions(capabilities);
    setStatus(
      capabilities.platformAuthenticator
        ? "Aguardando passkey neste aparelho…"
        : "Aguardando autenticador…",
      "idle"
    );
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
    showSuccess("authentication");
  } catch (error) {
    const normalized = normalizeBrowserError(error);
    setStatus(pretty({ ...normalized, sessionUser: getSessionUser(), capabilities }), "err");
    els.lastMeta.textContent = pretty({ error: normalized, capabilities });
    els.diagnostics.open = true;

    const needsRegister =
      normalized.code === "CREDENTIAL_NOT_FOUND" ||
      normalized.code === "NotAllowedError" ||
      normalized.code === "InvalidStateError" ||
      !hasLocalCredentials();

    if (needsRegister && capabilities.webauthn) {
      els.btnRegister.classList.remove("hidden");
      setStatus(
        `${normalized.message}\n\nCadastre uma passkey para "${getSessionUser()}" neste aparelho.`,
        "err"
      );
      applyFlowUi();
    }
  } finally {
    els.btnRegister.disabled = false;
    els.btnContinue.disabled = false;
    refreshStore();
  }
}

els.formSession.addEventListener("submit", (event) => {
  event.preventDefault();
  const errBox = $("session-error");
  try {
    errBox.classList.add("hidden");
    enterSession(els.username.value);
  } catch (error) {
    const normalized = normalizeBrowserError(error);
    errBox.textContent = normalized.message;
    errBox.classList.remove("hidden");
  }
});

els.btnRegister.addEventListener("click", () => runRegister());
els.btnContinue.addEventListener("click", () => runAuthenticate());

els.btnClear.addEventListener("click", () => {
  clearStore();
  timeline.length = 0;
  renderTimeline();
  applyFlowUi();
  setStatus(
    `Passkeys locais de "${getSessionUser()}" removidas. A passkey no autenticador permanece até você apagar manualmente.`,
    "idle"
  );
});

els.btnChangeUser.addEventListener("click", () => goToSessionStep());
els.btnSuccessChangeUser.addEventListener("click", () => goToSessionStep());
els.btnTestAgain.addEventListener("click", () => {
  setStep(2);
  applyFlowUi();
});

els.btnInspect.addEventListener("click", async () => {
  try {
    const result = await inspectExternalResponse(
      els.inspectorInput.value.trim(),
      location.hostname
    );
    els.inspectorOut.textContent = pretty(result);
    setStatus(`Inspetor: ${result.ceremony}, origin=${result.origin}`, "ok");
    els.diagnostics.open = true;
  } catch (error) {
    const normalized = normalizeBrowserError(error);
    els.inspectorOut.textContent = pretty(normalized);
    setStatus(pretty(normalized), "err");
  }
});

async function boot() {
  els.rpId.textContent = location.hostname;
  els.origin.textContent = location.origin;
  await probeCapabilities();
  renderCapabilities(els.caps);
  renderRecentUsers();
  renderTimeline();
  refreshStore();

  const existing = getSessionUser();
  if (existing) {
    els.username.value = existing;
  }
  setStep(1);
  els.username.focus();
}

boot();
