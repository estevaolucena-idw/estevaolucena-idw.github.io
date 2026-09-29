const ALLOWED = new Set([
  "https://estevaolucena-idw.github.io",
  "http://localhost:8080",
  "http://localhost:3000",
  "http://localhost:5179",
  "http://127.0.0.1:8080",
  "http://127.0.0.1:5179",
]);

export function corsOrigin(req) {
  const origin = req.headers.get("origin") || "";
  if (ALLOWED.has(origin)) return origin;
  return "https://estevaolucena-idw.github.io";
}

export function withCors(req, response) {
  const origin = corsOrigin(req);
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Access-Control-Allow-Methods", "GET,PUT,DELETE,OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  headers.set("Vary", "Origin");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export function json(req, data, status = 200) {
  return withCors(
    req,
    new Response(JSON.stringify(data), {
      status,
      headers: { "Content-Type": "application/json; charset=utf-8" },
    })
  );
}

export function noContent(req) {
  return withCors(req, new Response(null, { status: 204 }));
}
