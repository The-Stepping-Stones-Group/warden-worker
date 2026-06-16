import { describe, expect, test } from "bun:test";

import {
  enforceOriginProof,
  isWorkerRoute,
} from "./origin-gate.js";

describe("origin proof gate", () => {
  test("allows requests when ORIGIN_SHARED_SECRET is unset", () => {
    const request = new Request("https://vault.example.com/");

    const result = enforceOriginProof(request, {});

    expect(result.ok).toBe(true);
    expect(result.request).toBe(request);
  });

  test("rejects requests missing the configured origin proof", async () => {
    const request = new Request("https://vault.example.com/");

    const result = enforceOriginProof(request, {
      ORIGIN_SHARED_SECRET: "secret-value",
    });

    expect(result.ok).toBe(false);
    expect(result.response.status).toBe(403);
    await expect(result.response.text()).resolves.toBe("Forbidden");
  });

  test("allows matching origin proof and strips it before downstream handlers", () => {
    const request = new Request("https://vault.example.com/api/sync", {
      headers: {
        "X-SSG-Origin-Secret": "secret-value",
      },
    });

    const result = enforceOriginProof(request, {
      ORIGIN_SHARED_SECRET: "secret-value",
    });

    expect(result.ok).toBe(true);
    expect(result.request.headers.get("X-SSG-Origin-Secret")).toBeNull();
  });

  test("supports a custom origin proof header name", () => {
    const request = new Request("https://vault.example.com/api/sync", {
      headers: {
        "X-Origin-Proof": "secret-value",
      },
    });

    const result = enforceOriginProof(request, {
      ORIGIN_SHARED_SECRET: "secret-value",
      ORIGIN_SHARED_SECRET_HEADER: "X-Origin-Proof",
    });

    expect(result.ok).toBe(true);
    expect(result.request.headers.get("X-Origin-Proof")).toBeNull();
  });
});

describe("worker route detection", () => {
  test.each([
    ["/api/sync", true],
    ["/identity/connect/token", true],
    ["/notifications/hub", true],
    ["/", false],
    ["/app/main.js", false],
  ])("%s => %s", (pathname, expected) => {
    expect(isWorkerRoute(pathname)).toBe(expected);
  });
});
