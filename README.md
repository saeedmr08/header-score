# HeaderScore

HeaderScore is a paste-only HTTP response header scorecard by **Saeed Rumaneh**. Paste headers (or click a fixture), get a letter-grade score for CSP, HSTS, X-Content-Type-Options, Referrer-Policy, X-Frame-Options, and Permissions-Policy — with plain-language findings.

Built from scratch for portfolio use. No remote URL fetching (SSRF-safe by design).

## How to run

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

| Script | Purpose |
|--------|---------|
| `npm run dev` | Dev server |
| `npm run build` | Production build |
| `npm test` | Vitest |
| `npm run typecheck` | TypeScript check |

## Example inputs

Click the fixture buttons on the copy desk:

| Button | What you should see |
|--------|---------------------|
| **Missing HSTS** | HSTS finding fails; other headers mostly OK |
| **Weak CSP** | CSP warns/fails on `*` / `unsafe-inline` / `unsafe-eval` |
| **Good baseline** | High grade (A/B) across the six scored headers |
| **Bare responses** | Near-zero score — almost no security headers |

Or paste raw `curl -I` output into the textarea. The last paste is restored from `localStorage` on reload.

## Scoring overview

| Header | Max points |
|--------|------------|
| Content-Security-Policy | 25 |
| Strict-Transport-Security | 20 |
| X-Content-Type-Options | 15 |
| Referrer-Policy | 15 |
| X-Frame-Options | 15 |
| Permissions-Policy | 10 |

Letter grades: A ≥ 90%, B ≥ 75%, C ≥ 60%, D ≥ 40%, else F. Logic lives in `lib/headers.ts`.

## Complete product flows

1. Click **Missing HSTS** — HSTS fails; the letter grade updates.
2. Click **Weak CSP** — CSP warns/fails on `*` / `unsafe-inline` / `unsafe-eval`.
3. Paste custom headers and reload — the grade and paste persist in `localStorage`.

## Security note

See [SECURITY.md](./SECURITY.md). This tool never fetches arbitrary URLs.

## License

MIT © 2026 Saeed Rumaneh
