import {
  authenticateOptions,
  authenticateVerify,
  checkApiHealth,
  clearAllSessions,
  clearStore,
  getSessionUser,
  getStoreSnapshot,
  hasLocalCredentials,
  hasVerifiableCredentials,
  listSessionUsernames,
  onTimeline,
  registerOptions,
  registerVerify,
  setSessionUser,
} from "./server.js";
import { getApiBase } from "./api-client.js";
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
  btnClearAll: $("btn-clear-all"),
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
  wellknown: $("wellknown"),
  btnWellknownRefresh: $("btn-wellknown-refresh"),
  wkAssetlinksBadge: $("wk-assetlinks-badge"),
  wkAssetlinksSummary: $("wk-assetlinks-summary"),
  wkAssetlinksBody: $("wk-assetlinks-body"),
  wkAssetlinksLink: $("wk-assetlinks-link"),
  wkAasaBadge: $("wk-aasa-badge"),
  wkAasaSummary: $("wk-aasa-summary"),
  wkAasaBody: $("wk-aasa-body"),
  wkAasaLink: $("wk-aasa-link"),
  wkAasaCdnLink: $("wk-aasa-cdn-link"),
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

const WELL_KNOWN = {
  assetlinks: "/.well-known/assetlinks.json",
  aasa: "/.well-known/apple-app-site-association",
};

async function fetchWellKnown(path) {
  const url = new URL(path, location.origin).href;
  const response = await fetch(url, { cache: "no-store" });
  const contentType = response.headers.get("content-type") || "";
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return {
    url,
    ok: response.ok,
    status: response.status,
    contentType,
    text,
    json,
  };
}

function summarizeAssetLinks(json) {
  if (!Array.isArray(json)) return ["Formato inesperado (esperado array)."];
  return json.map((entry, index) => {
    const pkg = entry?.target?.package_name || "?";
    const fps = entry?.target?.sha256_cert_fingerprints || [];
    const relations = (entry?.relation || []).join(", ");
    const fpShort = fps[0] ? `${String(fps[0]).slice(0, 11)}…` : "sem fingerprint";
    return `<li><code>${pkg}</code> · ${fps.length} fp · ${fpShort}${
      relations ? ` · <span class="muted">${relations}</span>` : ""
    } <span class="muted">(#${index + 1})</span></li>`;
  });
}

function summarizeAasa(json) {
  if (!json || typeof json !== "object") return ["Formato inesperado (esperado objeto JSON)."];
  const appIds = json?.applinks?.details?.[0]?.appIDs || [];
  const webcreds = json?.webcredentials?.apps || [];
  const lines = [];
  lines.push(
    `<li>applinks: <strong>${appIds.length}</strong> appID(s)</li>`
  );
  appIds.forEach((id) => {
    lines.push(`<li><code>${id}</code></li>`);
  });
  lines.push(
    `<li>webcredentials: <strong>${webcreds.length}</strong> app(s)</li>`
  );
  webcreds.forEach((id) => {
    if (!appIds.includes(id)) lines.push(`<li><code>${id}</code> <span class="muted">(só webcredentials)</span></li>`);
  });
  return lines;
}

function renderWellKnownResult({ badgeEl, summaryEl, bodyEl, result, summarize }) {
  if (!result.ok) {
    badgeEl.textContent = `HTTP ${result.status}`;
    badgeEl.className = "badge err";
    summaryEl.innerHTML = `<li>Falha ao carregar <code>${result.url}</code></li>`;
    bodyEl.textContent = result.text || `(HTTP ${result.status})`;
    return;
  }

  badgeEl.textContent = `HTTP ${result.status}`;
  badgeEl.className = "badge ok";
  if (result.json == null) {
    summaryEl.innerHTML = `<li>Resposta não-JSON · <code>${result.contentType || "sem content-type"}</code></li>`;
    bodyEl.textContent = result.text;
    return;
  }

  const items = summarize(result.json);
  summaryEl.innerHTML =
    items.join("") +
    `<li class="muted">content-type: <code>${result.contentType || "—"}</code></li>`;
  bodyEl.textContent = pretty(result.json);
}

async function loadWellKnown() {
  els.wkAssetlinksBadge.textContent = "…";
  els.wkAssetlinksBadge.className = "badge";
  els.wkAasaBadge.textContent = "…";
  els.wkAasaBadge.className = "badge";
  els.wkAssetlinksBody.textContent = "Carregando…";
  els.wkAasaBody.textContent = "Carregando…";
  els.wkAssetlinksSummary.innerHTML = "";
  els.wkAasaSummary.innerHTML = "";

  const host = location.hostname;
  els.wkAssetlinksLink.href = WELL_KNOWN.assetlinks;
  els.wkAasaLink.href = WELL_KNOWN.aasa;
  els.wkAasaCdnLink.href = `https://app-site-association.cdn-apple.com/a/v1/${host}`;

  const [assetlinks, aasa] = await Promise.all([
    fetchWellKnown(WELL_KNOWN.assetlinks).catch((error) => ({
      url: WELL_KNOWN.assetlinks,
      ok: false,
      status: 0,
      contentType: "",
      text: error instanceof Error ? error.message : String(error),
      json: null,
    })),
    fetchWellKnown(WELL_KNOWN.aasa).catch((error) => ({
      url: WELL_KNOWN.aasa,
      ok: false,
      status: 0,
      contentType: "",
      text: error instanceof Error ? error.message : String(error),
      json: null,
    })),
  ]);

  renderWellKnownResult({
    badgeEl: els.wkAssetlinksBadge,
    summaryEl: els.wkAssetlinksSummary,
    bodyEl: els.wkAssetlinksBody,
    result: assetlinks,
    summarize: summarizeAssetLinks,
  });
  renderWellKnownResult({
    badgeEl: els.wkAasaBadge,
    summaryEl: els.wkAasaSummary,
    bodyEl: els.wkAasaBody,
    result: aasa,
    summarize: summarizeAasa,
  });
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

async function refreshStore() {
  try {
    const snap = await getStoreSnapshot();
    els.storeView.textContent = pretty(snap);
    const count = snap.credentials?.length || 0;
    const verifiable = (snap.credentials || []).filter((c) => c.publicKeyCose).length;
    if (count === 0) {
      els.credBadge.textContent = "sem passkey";
      els.credBadge.className = "badge";
    } else {
      els.credBadge.textContent =
        verifiable === count
          ? `${count} passkey(s)`
          : `${count} passkey(s) · ${verifiable} verificável(is)`;
      els.credBadge.className = "badge ok";
    }
  } catch (error) {
    els.storeView.textContent = pretty({
      apiBase: getApiBase(),
      error: error instanceof Error ? error.message : String(error),
    });
    els.credBadge.textContent = "api offline";
    els.credBadge.className = "badge err";
  }
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
  void refreshStore();
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

async function renderRecentUsers() {
  try {
    const users = await listSessionUsernames();
    if (!users.length) {
      els.recentUsers.innerHTML = `<p class="hint">API: <code>${getApiBase()}</code></p>`;
      return;
    }
    els.recentUsers.innerHTML = `
    <p class="hint">Sessões na API (<code>${getApiBase()}</code>):</p>
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
  } catch (error) {
    els.recentUsers.innerHTML = `<p class="hint">Falha ao listar sessões em <code>${getApiBase()}</code>: ${
      error instanceof Error ? error.message : String(error)
    }</p>`;
  }
}

async function applyFlowUi() {
  const username = getSessionUser();
  els.sessionLabel.textContent = username || "—";
  renderCapabilities(els.capsFlow);
  await refreshStore();

  if (!window.isSecureContext) {
    setStatus("Contexto inseguro: WebAuthn exige HTTPS (ou localhost).", "err");
    els.btnContinue.disabled = true;
    els.btnRegister.disabled = true;
    els.btnContinue.classList.add("hidden");
    return;
  }

  if (!capabilities.webauthn) {
    setStatus("Este navegador não expõe WebAuthn.", "err");
    els.btnContinue.disabled = true;
    els.btnRegister.disabled = true;
    els.btnContinue.classList.add("hidden");
    return;
  }

  els.btnRegister.disabled = false;
  els.btnRegister.classList.remove("hidden");

  let hasCreds = false;
  let hasKeys = false;
  let count = 0;
  try {
    hasCreds = await hasLocalCredentials();
    hasKeys = await hasVerifiableCredentials();
    const snap = await getStoreSnapshot();
    count = snap.credentials?.length || 0;
  } catch (error) {
    setStatus(
      `API indisponível (${getApiBase()}): ${
        error instanceof Error ? error.message : String(error)
      }`,
      "err"
    );
    els.btnContinue.classList.add("hidden");
    els.btnContinue.disabled = true;
    return;
  }

  // Continuar só quando já identificamos passkey(s) para este usuário neste navegador
  els.btnContinue.classList.toggle("hidden", !hasCreds);
  els.btnContinue.disabled = !hasCreds;

  if (hasKeys) {
    els.btnContinue.classList.remove("secondary");
    els.flowTitle.textContent = "2. Continue com sua passkey";
    els.guide.innerHTML = `
      <li>Identificadas <strong>${count}</strong> passkey(s) para <strong>${username}</strong>.</li>
      <li>Toque em <strong>Continuar com passkey</strong> para autenticar.</li>
      <li><strong>Cadastrar</strong> de novo cria outra credencial (outro provider/dispositivo é ok).</li>`;
    setStatus(`Passkey identificada para "${username}". Pode continuar.`, "idle");
  } else if (hasCreds) {
    els.btnContinue.classList.remove("secondary");
    els.flowTitle.textContent = "2. Continue ou complete a sessão";
    els.guide.innerHTML = `
      <li>Há passkey(s) anotada(s) para <strong>${username}</strong>, sem chave pública completa.</li>
      <li><strong>Continuar</strong> tenta a cerimônia neste aparelho.</li>
      <li><strong>Cadastrar</strong> adiciona outra passkey (ex.: Google além do 1Password).</li>`;
    setStatus(`Passkey identificada para "${username}" (parcial). Pode continuar.`, "idle");
  } else {
    els.flowTitle.textContent = "2. Cadastre uma passkey";
    els.guide.innerHTML = `
      <li>Nenhuma passkey identificada ainda para <strong>${username}</strong> neste navegador.</li>
      <li>Toque em <strong>Cadastrar passkey</strong> (1Password, Google, iCloud, etc.).</li>
      <li>Vários providers são permitidos; cada cadastro vira um item no array da sessão.</li>`;
    setStatus(
      `Nenhuma passkey identificada para "${username}". Cadastre para continuar.`,
      "idle"
    );
  }
}

async function enterSession(rawUsername) {
  const username = await setSessionUser(rawUsername);
  els.username.value = username;
  setStep(2);
  await applyFlowUi();
  els.lastMeta.textContent = pretty({
    sessionUser: username,
    apiBase: getApiBase(),
    capabilities,
  });
}

async function goToSessionStep() {
  setStep(1);
  await renderRecentUsers();
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

function prepareGetOptions(options) {
  const {
    localCredentialCount: _count,
    crossDeviceHint: _hint,
    hints,
    ...publicKeyFields
  } = options;
  const publicKey = {
    ...publicKeyFields,
    challenge: base64UrlToBuffer(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((cred) => ({
      ...cred,
      id: base64UrlToBuffer(cred.id),
    })),
  };
  if (hints) publicKey.hints = hints;
  return { publicKey };
}

function prepareCreateOptions(options) {
  const { hints, ...rest } = options;
  const publicKey = {
    ...rest,
    challenge: base64UrlToBuffer(options.challenge),
    user: {
      ...options.user,
      id: base64UrlToBuffer(options.user.id),
    },
    excludeCredentials: (options.excludeCredentials || []).map((cred) => ({
      ...cred,
      id: base64UrlToBuffer(cred.id),
    })),
  };
  if (hints) publicKey.hints = hints;
  return { publicKey };
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
      verificationMode: verification.verificationMode || "full",
      signatureVerified: verification.signatureVerified !== false,
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

function showSuccess(kind, verification) {
  setStep(3);
  const user = getSessionUser();
  if (kind === "registration") {
    els.successDetail.textContent = `Passkey cadastrada para "${user}" e salva no array mock deste navegador.`;
  } else if (verification?.verificationMode === "cross-device-assertion") {
    els.successDetail.textContent = `Cerimônia OK para "${user}" neste aparelho. Assinatura não checada (sem chave pública nesta sessão mock).`;
  } else {
    els.successDetail.textContent = `Autenticação verificada por completo para "${user}".`;
  }
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
    showSuccess("registration", verification);
  } catch (error) {
    const normalized = normalizeBrowserError(error);
    setStatus(pretty({ ...normalized, sessionUser: getSessionUser(), capabilities }), "err");
    els.lastMeta.textContent = pretty({ error: normalized, capabilities });
    els.diagnostics.open = true;
    els.btnRegister.classList.remove("hidden");
  } finally {
    els.btnRegister.disabled = false;
    els.btnContinue.disabled = false;
    await refreshStore();
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
    if (verification.verificationMode === "cross-device-assertion") {
      setStatus(
        "Cerimônia cross-device OK (sem chave pública local). Importe o export para verificação completa.",
        "ok"
      );
    } else {
      setStatus("Autenticação verificada.", "ok");
    }
    showSuccess("authentication", verification);
  } catch (error) {
    const normalized = normalizeBrowserError(error);
    setStatus(pretty({ ...normalized, sessionUser: getSessionUser(), capabilities }), "err");
    els.lastMeta.textContent = pretty({ error: normalized, capabilities });
    els.diagnostics.open = true;

    const hasCreds = await hasLocalCredentials().catch(() => false);
    const needsRegister =
      normalized.code === "CREDENTIAL_NOT_FOUND" ||
      normalized.code === "NotAllowedError" ||
      normalized.code === "InvalidStateError" ||
      !hasCreds;

    if (needsRegister && capabilities.webauthn) {
      els.btnRegister.classList.remove("hidden");
      setStatus(
        `${normalized.message}\n\nCadastre uma passkey para "${getSessionUser()}" neste aparelho.`,
        "err"
      );
      await applyFlowUi();
    }
  } finally {
    els.btnRegister.disabled = false;
    els.btnContinue.disabled = false;
    await refreshStore();
  }
}

els.formSession.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errBox = $("session-error");
  try {
    errBox.classList.add("hidden");
    await enterSession(els.username.value);
  } catch (error) {
    const normalized = normalizeBrowserError(error);
    errBox.textContent = normalized.message;
    errBox.classList.remove("hidden");
  }
});

els.btnRegister.addEventListener("click", () => runRegister());
els.btnContinue.addEventListener("click", () => runAuthenticate());

els.btnClear.addEventListener("click", async () => {
  await clearStore();
  timeline.length = 0;
  renderTimeline();
  await applyFlowUi();
  setStatus(
    `Sessão de "${getSessionUser()}" limpa na API. A passkey no autenticador permanece.`,
    "idle"
  );
});

els.btnClearAll.addEventListener("click", async () => {
  if (!confirm("Limpar TODAS as sessões na API Vercel?")) return;
  await clearAllSessions();
  timeline.length = 0;
  renderTimeline();
  await applyFlowUi();
  setStatus("Todas as sessões foram removidas na API.", "idle");
});

els.btnChangeUser.addEventListener("click", () => goToSessionStep());
els.btnSuccessChangeUser.addEventListener("click", () => goToSessionStep());
els.btnTestAgain.addEventListener("click", async () => {
  setStep(2);
  await applyFlowUi();
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

els.btnWellknownRefresh.addEventListener("click", () => {
  void loadWellKnown();
});

async function boot() {
  els.rpId.textContent = location.hostname;
  els.origin.textContent = location.origin;
  await probeCapabilities();
  renderCapabilities(els.caps);
  renderTimeline();
  void loadWellKnown();
  try {
    const health = await checkApiHealth();
    setStatus(`API ok: ${getApiBase()} (${health.storage || "ok"})`, "idle");
  } catch (error) {
    setStatus(
      `API indisponível: ${getApiBase()} — ${
        error instanceof Error ? error.message : String(error)
      }`,
      "err"
    );
  }
  await renderRecentUsers();
  await refreshStore();

  const existing = getSessionUser();
  if (existing) {
    els.username.value = existing;
  }
  setStep(1);
  els.username.focus();
}

boot();
