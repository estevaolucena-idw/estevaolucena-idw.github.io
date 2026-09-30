# PoC Passkey — estevaolucena-idw.github.io

App web estática no GitHub Pages para validar a hipótese de que **múltiplos apps nativos** (Android e iOS) conseguem realizar a cerimônia de Passkey no **mesmo rpID** (`estevaolucena-idw.github.io`), liberados pelos arquivos `.well-known` na raiz do domínio.

## URLs

| Recurso | URL |
| --- | --- |
| App | https://estevaolucena-idw.github.io/ |
| API (Vercel) | https://poc-passkey-api.vercel.app |
| Health | https://poc-passkey-api.vercel.app/api/health |
| Android Digital Asset Links | https://estevaolucena-idw.github.io/.well-known/assetlinks.json |
| Apple App Site Association | https://estevaolucena-idw.github.io/.well-known/apple-app-site-association |
| CDN Apple (cache AASA) | https://app-site-association.cdn-apple.com/a/v1/estevaolucena-idw.github.io |

## O que a app faz

1. **Continuar com passkey** — aparece se a sessão na API já tem passkey cadastrada
2. **Cadastrar passkey** — `registerOptions` → `create` → `registerVerify`
3. Cerimônia no browser (`server.js`); usuários/credenciais centralizados na **API Vercel** (`api-client.js` → Blob)
4. Challenge da cerimônia fica no `sessionStorage` local; o resto é compartilhado entre PC e celular
5. Painel de metadados + inspetor para respostas dos apps nativos

Backend: projeto irmão `../api-sessions` (Vercel Functions + Vercel Blob). Override local: `window.__PASSKEY_API_BASE`.

> Este diretório local chama-se `web-pages`, mas o **remote GitHub** permanece `estevaolucena-idw.github.io` (exigência do GitHub Pages / rpID).

## Apps liberados

### Android (`assetlinks.json`)

| package | fingerprint (SHA-256) |
| --- | --- |
| `co.idwall.sdk.webview.app1` | `4C:AB:A3:7A:…:17:15` |
| `co.idwall.sdk.webview.app2` | `3D:C5:06:AD:…:C1:D3` |
| `co.idwall.sdk.webview.app3` | `FA:E1:14:07:…:36:A7` |
| `co.idwall.sdk.webview.app4` | `BC:C9:14:C3:…:81:EA` |
| `co.idwall.sdk.webview.app5` | `5A:9C:15:28:…:35:EC` |

Relations: `handle_all_urls` + `get_login_creds`.

### iOS (`apple-app-site-association`)

Team ID `55V4KQ8R32`:

- `55V4KQ8R32.com.webview-app-ios`
- `55V4KQ8R32.com.webview-app-ios-2`
- `55V4KQ8R32.com.webview-app-ios-3`
- `55V4KQ8R32.com.webview-app-ios-4`
- `55V4KQ8R32.com.webview-app-ios-5`

## Roteiro de validação

1. Conferir HTTP 200 nas URLs `.well-known` acima.
2. Validar Android na [Digital Asset Links API](https://developers.google.com/digital-asset-links/tools/generator).
3. Validar iOS no CDN da Apple.
4. Na web: cadastrar → autenticar → inspecionar metadados.
5. Em cada app nativo: `rpId = estevaolucena-idw.github.io`, create/get, colar JSON no inspetor.

## Validação automática (deploy)

Conferido em 2026-09-29:

| Check | Resultado |
| --- | --- |
| Site `https://estevaolucena-idw.github.io/` | HTTP 200 |
| `assetlinks.json` | HTTP 200, `application/json` |
| `apple-app-site-association` | HTTP 200 (GitHub serve como `application/octet-stream`) |
| Digital Asset Links API (`get_login_creds`) | 5 statements (app1–app5) |
| CDN Apple AASA | HTTP 200, JSON com os 5 app IDs |

## Matriz de resultados (cerimônias)

Preencher nos testes manuais (web + apps nativos com `rpId = estevaolucena-idw.github.io`):

| App | create ok | get ok | origin | erro |
| --- | --- | --- | --- | --- |
| web (estevaolucena-idw.github.io) | | | | |
| co.idwall.sdk.webview.app1 | | | | |
| co.idwall.sdk.webview.app2 | | | | |
| co.idwall.sdk.webview.app3 | | | | |
| co.idwall.sdk.webview.app4 | | | | |
| co.idwall.sdk.webview.app5 | | | | |
| com.webview-app-ios | | | | |
| com.webview-app-ios-2 | | | | |
| com.webview-app-ios-3 | | | | |
| com.webview-app-ios-4 | | | | |
| com.webview-app-ios-5 | | | | |

## Desenvolvimento local

```bash
cd estevaolucena-idw.github.io
# WebAuthn exige HTTPS ou localhost
python3 -m http.server 8080
# abrir http://localhost:8080
```

Em `localhost`, o `rpID` será `localhost` — para testar o domínio real, use o GitHub Pages.

## Limitações (PoC)

- O array de credenciais vale só para o navegador (localStorage).
- Verificação criptográfica no cliente (WebCrypto ES256); não substitui um backend de produção.
- Remover a passkey do autenticador é manual se for repetir o cadastro do zero.
