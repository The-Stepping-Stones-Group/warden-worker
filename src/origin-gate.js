const DEFAULT_ORIGIN_SECRET_HEADER = "X-SSG-Origin-Secret";

function configuredSecret(env) {
  const secret = env?.ORIGIN_SHARED_SECRET;
  return typeof secret === "string" && secret.length > 0 ? secret : null;
}

function configuredHeaderName(env) {
  const headerName = env?.ORIGIN_SHARED_SECRET_HEADER;
  return typeof headerName === "string" && headerName.trim()
    ? headerName.trim()
    : DEFAULT_ORIGIN_SECRET_HEADER;
}

function constantTimeEqual(a, b) {
  const left = new TextEncoder().encode(a);
  const right = new TextEncoder().encode(b);
  let diff = left.length ^ right.length;
  const length = Math.max(left.length, right.length);

  for (let i = 0; i < length; i++) {
    diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
  }

  return diff === 0;
}

function stripHeader(request, headerName) {
  const next = new Request(request);
  next.headers.delete(headerName);
  return next;
}

export function enforceOriginProof(request, env) {
  const secret = configuredSecret(env);
  if (!secret) {
    return { ok: true, request };
  }

  const headerName = configuredHeaderName(env);
  const provided = request.headers.get(headerName);
  if (!provided || !constantTimeEqual(provided, secret)) {
    return {
      ok: false,
      response: new Response("Forbidden", { status: 403 }),
    };
  }

  return {
    ok: true,
    request: stripHeader(request, headerName),
  };
}

export function isWorkerRoute(pathname) {
  return (
    pathname === "/api" ||
    pathname.startsWith("/api/") ||
    pathname === "/identity" ||
    pathname.startsWith("/identity/") ||
    pathname === "/notifications" ||
    pathname.startsWith("/notifications/")
  );
}
