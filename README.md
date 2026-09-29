# PoC Passkey — estevaolucena-idw.github.io

App web estática no GitHub Pages para validar a hipótese de que **múltiplos apps nativos** (Android e iOS) conseguem realizar a cerimônia de Passkey no **mesmo rpID** (`estevaolucena-idw.github.io`), liberados pelos arquivos `.well-known` na raiz do domínio.

## URLs

| Recurso | URL |
| --- | --- |
| App | https://estevaolucena-idw.github.io/ |
| Android Digital Asset Links | https://estevaolucena-idw.github.io/.well-known/assetlinks.json |
| Apple App Site Association | https://estevaolucena-idw.github.io/.well-known/apple-app-site-association |
| CDN Apple (cache AASA) | https://app-site-association.cdn-apple.com/a/v1/estevaolucena-idw.github.io |

## O que a app faz

1. **Continuar com passkey** — `authenticateOptions` → `navigator.credentials.get` (discoverable) → `authenticateVerify`
2. **Cadastrar passkey** — `registerOptions` → `navigator.credentials.create` → `registerVerify`
3. Servidor simulado no navegador (`server.js`) com store em `localStorage`
4. Painel de metadados + inspetor para colar respostas dos apps nativos

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
- `55V4KQ8R32.com.webview-app-ios.app2`
- `55V4KQ8R32.com.webview-app-ios.app3`
- `55V4KQ8R32.com.webview-app-ios.app4`
- `55V4KQ8R32.com.webview-app-ios.app5`

## Roteiro de validação

1. Conferir HTTP 200 nas URLs `.well-known` acima.
2. Validar Android na [Digital Asset Links API](https://developers.google.com/digital-asset-links/tools/generator).
3. Validar iOS no CDN da Apple.
4. Na web: cadastrar → autenticar → inspecionar metadados.
5. Em cada app nativo: `rpId = estevaolucena-idw.github.io`, create/get, colar JSON no inspetor.

## Matriz de resultados

Preencher durante os testes:

| App | create ok | get ok | origin | erro |
| --- | --- | --- | --- | --- |
| web (estevaolucena-idw.github.io) | | | | |
| co.idwall.sdk.webview.app1 | | | | |
| co.idwall.sdk.webview.app2 | | | | |
| co.idwall.sdk.webview.app3 | | | | |
| co.idwall.sdk.webview.app4 | | | | |
| co.idwall.sdk.webview.app5 | | | | |
| com.webview-app-ios | | | | |
| com.webview-app-ios.app2 | | | | |
| com.webview-app-ios.app3 | | | | |
| com.webview-app-ios.app4 | | | | |
| com.webview-app-ios.app5 | | | | |

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
