export interface Fixture {
  id: string;
  label: string;
  blurb: string;
  headers: string;
}

export const FIXTURES: Fixture[] = [
  {
    id: "newsprint-shop",
    label: "Newsprint shop (strong)",
    blurb: "Synthetic storefront with a tight header set.",
    headers: `HTTP/2 200
strict-transport-security: max-age=63072000; includeSubDomains; preload
content-security-policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
x-content-type-options: nosniff
referrer-policy: no-referrer
x-frame-options: DENY
permissions-policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()`,
  },
  {
    id: "missing-hsts",
    label: "Missing HSTS",
    blurb: "Looks fine elsewhere — TLS stickiness forgotten.",
    headers: `HTTP/2 200
content-type: text/html; charset=utf-8
content-security-policy: default-src 'self'; script-src 'self'
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
x-frame-options: DENY
permissions-policy: camera=(), microphone=(), geolocation=()`,
  },
  {
    id: "weak-csp",
    label: "Weak CSP",
    blurb: "Wildcard sources plus unsafe-inline / unsafe-eval.",
    headers: `HTTP/1.1 200 OK
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src *; script-src * 'unsafe-inline' 'unsafe-eval'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
X-Frame-Options: SAMEORIGIN
Permissions-Policy: camera=(), microphone=()`,
  },
  {
    id: "bare-minimum",
    label: "Bare responses",
    blurb: "Almost no security headers — typical legacy API.",
    headers: `HTTP/1.1 200 OK
content-type: application/json
cache-control: no-store
server: example`,
  },
];

export function fixtureById(id: string): Fixture | undefined {
  return FIXTURES.find((f) => f.id === id);
}
