# PoC Passkey — estevaolucena-idw.github.io

App web estática no GitHub Pages para a cerimônia de Passkey (cadastro e autenticação) no **rpID** `estevaolucena-idw.github.io`, com sessões na API remota.

A UI e o `server.js` ainda esperam `/.well-known/assetlinks.json` e `/.well-known/apple-app-site-association` (arquitetura pronta). **Esses arquivos não estão publicados** neste domínio.

## URLs

| Recurso | URL |
| --- | --- |
| App | https://estevaolucena-idw.github.io/ |
| API (Vercel) | https://poc-passkey-api.vercel.app |
| Health | https://poc-passkey-api.vercel.app/api/health |

## O que a app faz

1. **Continuar com passkey** — aparece se a sessão na API já tem passkey cadastrada
2. **Cadastrar passkey** — `registerOptions` → `create` → `registerVerify`
3. Cerimônia no browser (`server.js`); usuários/credenciais centralizados na **API Vercel** (`api-client.js` → Blob)
4. Challenge da cerimônia fica no `sessionStorage` local; o resto é compartilhado entre PC e celular
5. Painel de metadados + inspetor para respostas externas

Backend: projeto irmão `../api-sessions` (Vercel Functions + Vercel Blob). Override local: `window.__PASSKEY_API_BASE`.

> Este diretório local chama-se `web-pages`, mas o **remote GitHub** permanece `estevaolucena-idw.github.io` (exigência do GitHub Pages / rpID).

## Desenvolvimento local

```bash
cd estevaolucena-idw.github.io
# WebAuthn exige HTTPS ou localhost
python3 -m http.server 8080
# abrir http://localhost:8080
```

Em `localhost`, o `rpID` será `localhost` — para testar o domínio real, use o GitHub Pages.

## Limitações (PoC)

- Sem os arquivos `.well-known` publicados, associação de apps nativos e a allowlist dinâmica a partir do assetlinks não funcionam neste host.
- Verificação criptográfica no cliente (WebCrypto ES256); não substitui um backend de produção.
- Remover a passkey do autenticador é manual se for repetir o cadastro do zero.
