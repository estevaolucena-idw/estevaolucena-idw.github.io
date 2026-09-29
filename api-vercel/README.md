# PoC Passkey API (Vercel)

Backend centralizado de sessões/usuários × passkeys para o frontend em
`https://estevaolucena-idw.github.io`.

## Rotas

| Método | Path | Descrição |
| --- | --- | --- |
| GET | `/api/health` | healthcheck |
| GET | `/api/sessions` | lista sessões |
| DELETE | `/api/sessions?confirm=poc-passkey-clear` | limpa todas |
| GET | `/api/sessions/:username` | lê sessão |
| PUT | `/api/sessions/:username` | cria/atualiza (`user`, `credentials`) |
| DELETE | `/api/sessions/:username` | remove sessão |

Persistência: **Vercel Blob** (`poc-passkey/sessions.json`).

## Deploy

```bash
cd api-vercel
npm install
npx vercel login
npx vercel link
# criar Blob store no dashboard e puxar env, ou:
npx vercel env pull
npx vercel --prod
```

Defina `BLOB_READ_WRITE_TOKEN` no projeto (ao criar um Blob Store na Vercel ele é injetado).
