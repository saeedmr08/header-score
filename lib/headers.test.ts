import { describe, expect, it } from "vitest";
import { parseHeaderBlock, scoreHeaders } from "./headers";

const MISSING_HSTS = `
HTTP/2 200
content-type: text/html
content-security-policy: default-src 'self'; script-src 'self'
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
x-frame-options: DENY
permissions-policy: camera=(), microphone=(), geolocation=()
`.trim();

const WEAK_CSP = `
HTTP/1.1 200 OK
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src *; script-src * 'unsafe-inline' 'unsafe-eval'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
X-Frame-Options: SAMEORIGIN
Permissions-Policy: camera=(), microphone=()
`.trim();

const GOOD_BASELINE = `
HTTP/2 200
strict-transport-security: max-age=63072000; includeSubDomains; preload
content-security-policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
x-content-type-options: nosniff
referrer-policy: no-referrer
x-frame-options: DENY
permissions-policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
`.trim();

describe("parseHeaderBlock", () => {
  it("skips status lines and maps names to values", () => {
    const map = parseHeaderBlock(GOOD_BASELINE);
    expect(map.get("x-content-type-options")).toBe("nosniff");
    expect(map.has("http/2 200")).toBe(false);
  });
});

describe("scoreHeaders", () => {
  it("flags missing HSTS as a fail with zero HSTS points", () => {
    const result = scoreHeaders(MISSING_HSTS);
    const hsts = result.findings.find((f) => f.id === "hsts");
    expect(hsts).toBeDefined();
    expect(hsts!.severity).toBe("fail");
    expect(hsts!.points).toBe(0);
    expect(hsts!.title.toLowerCase()).toContain("missing");
    expect(result.total).toBeLessThan(result.maxTotal);
  });

  it("penalizes weak CSP with unsafe-inline, unsafe-eval, and wildcards", () => {
    const result = scoreHeaders(WEAK_CSP);
    const csp = result.findings.find((f) => f.id === "csp");
    expect(csp).toBeDefined();
    expect(csp!.points).toBeLessThan(csp!.maxPoints);
    expect(["warn", "fail"]).toContain(csp!.severity);
    expect(csp!.explanation.toLowerCase()).toMatch(/unsafe|wildcard|\*/);
  });

  it("awards a strong grade for a good baseline", () => {
    const result = scoreHeaders(GOOD_BASELINE);
    expect(result.grade).toMatch(/^[AB]$/);
    expect(result.total).toBeGreaterThanOrEqual(90);
    for (const f of result.findings) {
      expect(f.severity).toBe("pass");
      expect(f.points).toBeGreaterThan(0);
    }
  });
});
