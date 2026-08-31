# Security Policy

## Scope

HeaderScore analyzes HTTP response headers that you paste into the browser or load from bundled fixtures. It is intentionally offline with respect to third-party hosts.

## Hard rule: no remote fetch

This project **must not** fetch arbitrary user-supplied URLs from the server (or from a privileged backend). Doing so would create a server-side request forgery (SSRF) risk.

Allowed inputs:

- Raw header text pasted by the user
- Local fixture strings shipped with the repository

Disallowed:

- Server-side `fetch` / `http.get` of user URLs
- Proxy endpoints that retrieve live sites on demand
- Blind URL “scan this host” features without an explicit, sandboxed design

## Reporting

If you find a vulnerability in HeaderScore, open an issue describing the impact and a minimal reproduction. Do not include secrets in public reports.
