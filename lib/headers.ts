/**
 * HeaderScore — paste-only HTTP security header scoring.
 * All analysis is local. Do not add remote URL fetchers here.
 */

export type Severity = "pass" | "warn" | "fail";

export interface Finding {
  id: string;
  header: string;
  severity: Severity;
  points: number;
  maxPoints: number;
  title: string;
  explanation: string;
  recommendation: string;
  observed: string | null;
}

export interface Scorecard {
  total: number;
  maxTotal: number;
  grade: "A" | "B" | "C" | "D" | "F";
  findings: Finding[];
  parsedCount: number;
}

export const HEADER_WEIGHTS = {
  "content-security-policy": 25,
  "strict-transport-security": 20,
  "x-content-type-options": 15,
  "referrer-policy": 15,
  "x-frame-options": 15,
  "permissions-policy": 10,
} as const;

export type ScoredHeader = keyof typeof HEADER_WEIGHTS;

const MAX_TOTAL = Object.values(HEADER_WEIGHTS).reduce((a, b) => a + b, 0);

/** Parse raw HTTP response / header-block text into a lowercase name → value map. */
export function parseHeaderBlock(raw: string): Map<string, string> {
  const map = new Map<string, string>();
  const lines = raw.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || /^HTTP\/\d/i.test(trimmed)) continue;

    const colon = trimmed.indexOf(":");
    if (colon <= 0) continue;

    const name = trimmed.slice(0, colon).trim().toLowerCase();
    const value = trimmed.slice(colon + 1).trim();
    if (!name) continue;

    // Last wins for duplicates (common for Set-Cookie; fine for our scored set).
    map.set(name, value);
  }

  return map;
}

function gradeFromTotal(total: number, max: number): Scorecard["grade"] {
  const pct = max === 0 ? 0 : (total / max) * 100;
  if (pct >= 90) return "A";
  if (pct >= 75) return "B";
  if (pct >= 60) return "C";
  if (pct >= 40) return "D";
  return "F";
}

function scoreCsp(value: string | undefined): Finding {
  const max = HEADER_WEIGHTS["content-security-policy"];
  const header = "Content-Security-Policy";

  if (!value) {
    return {
      id: "csp",
      header,
      severity: "fail",
      points: 0,
      maxPoints: max,
      title: "CSP missing",
      explanation:
        "Without Content-Security-Policy, the browser cannot restrict script, style, and frame sources. XSS and injection bugs have fewer guardrails.",
      recommendation:
        "Add a CSP with a restrictive default-src (ideally 'self' or 'none') and explicit allowlists for scripts and styles.",
      observed: null,
    };
  }

  const lower = value.toLowerCase();
  const hasUnsafeInline = /'unsafe-inline'/.test(lower);
  const hasUnsafeEval = /'unsafe-eval'/.test(lower);
  const hasStar =
    /(^|;)\s*(default-src|script-src|script-src-elem|object-src)\s[^;]*\*/.test(
      lower,
    ) || /\*\s*;|\*\s*$/.test(lower.split("script-src")[1] ?? "");
  const hasDefault =
    /default-src\s+('none'|'self'|https?:)/.test(lower) ||
    /default-src\s+'none'/.test(lower) ||
    /default-src\s+'self'/.test(lower);

  let points: number = max;
  const issues: string[] = [];

  if (hasUnsafeInline) {
    points -= 8;
    issues.push("'unsafe-inline' weakens XSS protections for scripts/styles");
  }
  if (hasUnsafeEval) {
    points -= 6;
    issues.push("'unsafe-eval' allows string-to-code evaluation");
  }
  if (hasStar) {
    points -= 8;
    issues.push("wildcard (*) sources over-broaden the policy");
  }
  if (!hasDefault && !/script-src\s/.test(lower)) {
    points -= 5;
    issues.push("no clear default-src or script-src baseline");
  }

  points = Math.max(0, Math.min(max, points));

  if (issues.length === 0) {
    return {
      id: "csp",
      header,
      severity: "pass",
      points: max,
      maxPoints: max,
      title: "CSP present and reasonably strict",
      explanation:
        "A Content-Security-Policy is set without the common footguns this scorecard flags (unsafe-inline, unsafe-eval, and broad wildcards on key directives).",
      recommendation:
        "Keep tightening with nonces/hashes and report-uri/report-to as you harden further.",
      observed: value,
    };
  }

  const severity: Severity = points >= max * 0.6 ? "warn" : "fail";
  return {
    id: "csp",
    header,
    severity,
    points,
    maxPoints: max,
    title: severity === "warn" ? "CSP present but weakened" : "CSP too permissive",
    explanation: `Policy is present, but: ${issues.join("; ")}.`,
    recommendation:
      "Remove 'unsafe-inline' / 'unsafe-eval' where possible, avoid * on script/default sources, and prefer nonces or hashes.",
    observed: value,
  };
}

function scoreHsts(value: string | undefined): Finding {
  const max = HEADER_WEIGHTS["strict-transport-security"];
  const header = "Strict-Transport-Security";

  if (!value) {
    return {
      id: "hsts",
      header,
      severity: "fail",
      points: 0,
      maxPoints: max,
      title: "HSTS missing",
      explanation:
        "Without Strict-Transport-Security, browsers may still attempt plain HTTP on later visits, enabling SSL-stripping and cookie leakage on the wire.",
      recommendation:
        "Serve Strict-Transport-Security: max-age=31536000; includeSubDomains (add preload only after qualifying).",
      observed: null,
    };
  }

  const lower = value.toLowerCase();
  const maxAgeMatch = /max-age\s*=\s*(\d+)/i.exec(value);
  const maxAge = maxAgeMatch ? Number(maxAgeMatch[1]) : 0;
  const includeSub = /includesubdomains/i.test(lower);
  const year = 31_536_000;

  let points = 0;
  if (maxAge >= year) points += 12;
  else if (maxAge >= 2_592_000) points += 7;
  else if (maxAge > 0) points += 3;

  if (includeSub) points += 6;
  if (/preload/i.test(lower) && maxAge >= year && includeSub) points += 2;

  points = Math.min(max, points);

  if (maxAge >= year && includeSub) {
    return {
      id: "hsts",
      header,
      severity: "pass",
      points,
      maxPoints: max,
      title: "HSTS configured strongly",
      explanation: `max-age is ${maxAge}s${includeSub ? " with includeSubDomains" : ""}. Browsers will prefer HTTPS for this host (and subdomains if flagged).`,
      recommendation:
        "Maintain HTTPS everywhere before enabling preload; review certificate agility.",
      observed: value,
    };
  }

  return {
    id: "hsts",
    header,
    severity: points > 0 ? "warn" : "fail",
    points,
    maxPoints: max,
    title: "HSTS present but incomplete",
    explanation:
      maxAge < year
        ? `max-age (${maxAge}) is below one year (${year}), so protection may expire too soon.`
        : "includeSubDomains is missing, so subdomains remain unprotected by this policy.",
    recommendation:
      "Use max-age of at least 31536000 and includeSubDomains once all subdomains speak HTTPS.",
    observed: value,
  };
}

function scoreXcto(value: string | undefined): Finding {
  const max = HEADER_WEIGHTS["x-content-type-options"];
  const header = "X-Content-Type-Options";

  if (!value) {
    return {
      id: "xcto",
      header,
      severity: "fail",
      points: 0,
      maxPoints: max,
      title: "X-Content-Type-Options missing",
      explanation:
        "Without nosniff, some browsers may MIME-sniff responses and treat non-script content as executable in certain contexts.",
      recommendation: "Set X-Content-Type-Options: nosniff on all responses.",
      observed: null,
    };
  }

  if (value.trim().toLowerCase() === "nosniff") {
    return {
      id: "xcto",
      header,
      severity: "pass",
      points: max,
      maxPoints: max,
      title: "MIME sniffing disabled",
      explanation:
        "nosniff tells the browser to respect the declared Content-Type, reducing MIME-confusion attacks.",
      recommendation: "Keep nosniff on static and API responses alike.",
      observed: value,
    };
  }

  return {
    id: "xcto",
    header,
    severity: "fail",
    points: 0,
    maxPoints: max,
    title: "X-Content-Type-Options invalid",
    explanation: `Expected "nosniff", got "${value}".`,
    recommendation: "Replace the value with nosniff.",
    observed: value,
  };
}

const STRONG_REFERRER = new Set([
  "no-referrer",
  "same-origin",
  "strict-origin",
  "strict-origin-when-cross-origin",
]);

const WEAK_REFERRER = new Set([
  "unsafe-url",
  "no-referrer-when-downgrade",
  "origin-when-cross-origin",
]);

function scoreReferrer(value: string | undefined): Finding {
  const max = HEADER_WEIGHTS["referrer-policy"];
  const header = "Referrer-Policy";

  if (!value) {
    return {
      id: "referrer",
      header,
      severity: "fail",
      points: 0,
      maxPoints: max,
      title: "Referrer-Policy missing",
      explanation:
        "Without an explicit policy, browsers may send full URLs (including path/query) as Referer on navigations and requests, leaking sensitive tokens in query strings.",
      recommendation:
        "Prefer strict-origin-when-cross-origin or no-referrer for sensitive apps.",
      observed: null,
    };
  }

  // Take first token if comma-separated (browsers use the first supported).
  const primary = value.split(",")[0]?.trim().toLowerCase() ?? "";

  if (STRONG_REFERRER.has(primary)) {
    return {
      id: "referrer",
      header,
      severity: "pass",
      points: max,
      maxPoints: max,
      title: "Referrer-Policy is restrictive",
      explanation: `"${primary}" limits how much of the URL is shared with other origins.`,
      recommendation: "Document the choice for analytics teams that rely on referrers.",
      observed: value,
    };
  }

  if (WEAK_REFERRER.has(primary) || primary === "origin") {
    const points = primary === "unsafe-url" ? 3 : 8;
    return {
      id: "referrer",
      header,
      severity: "warn",
      points,
      maxPoints: max,
      title: "Referrer-Policy could be tighter",
      explanation: `"${primary}" still shares more referrer detail than recommended for high-sensitivity apps.`,
      recommendation:
        "Move toward strict-origin-when-cross-origin, same-origin, or no-referrer.",
      observed: value,
    };
  }

  return {
    id: "referrer",
    header,
    severity: "warn",
    points: 5,
    maxPoints: max,
    title: "Referrer-Policy unrecognized",
    explanation: `Value "${value}" is not among the common policies this scorecard grades.`,
    recommendation:
      "Use a standard token such as strict-origin-when-cross-origin.",
    observed: value,
  };
}

function scoreXfo(value: string | undefined, headers: Map<string, string>): Finding {
  const max = HEADER_WEIGHTS["x-frame-options"];
  const header = "X-Frame-Options";
  const csp = headers.get("content-security-policy") ?? "";
  const hasFrameAncestors = /frame-ancestors\s+/i.test(csp);

  if (!value) {
    if (hasFrameAncestors) {
      return {
        id: "xfo",
        header,
        severity: "pass",
        points: max - 2,
        maxPoints: max,
        title: "Clickjacking covered via CSP",
        explanation:
          "X-Frame-Options is absent, but CSP frame-ancestors provides modern clickjacking control.",
        recommendation:
          "Optionally add X-Frame-Options: DENY for older clients; keep frame-ancestors authoritative.",
        observed: null,
      };
    }

    return {
      id: "xfo",
      header,
      severity: "fail",
      points: 0,
      maxPoints: max,
      title: "X-Frame-Options missing",
      explanation:
        "Without X-Frame-Options (or CSP frame-ancestors), the page may be embedded in a hostile iframe (clickjacking).",
      recommendation:
        "Set X-Frame-Options: DENY (or SAMEORIGIN) and/or CSP frame-ancestors 'none'|'self'.",
      observed: null,
    };
  }

  const upper = value.trim().toUpperCase();
  if (upper === "DENY" || upper === "SAMEORIGIN") {
    return {
      id: "xfo",
      header,
      severity: "pass",
      points: max,
      maxPoints: max,
      title: "Framing restricted",
      explanation: `${upper} prevents cross-origin framing${upper === "SAMEORIGIN" ? " from other sites" : " entirely"}.`,
      recommendation:
        "Prefer DENY when embedding is never required; otherwise SAMEORIGIN or CSP frame-ancestors.",
      observed: value,
    };
  }

  if (upper.startsWith("ALLOW-FROM")) {
    return {
      id: "xfo",
      header,
      severity: "warn",
      points: 5,
      maxPoints: max,
      title: "Deprecated ALLOW-FROM",
      explanation:
        "ALLOW-FROM is obsolete and ignored by modern browsers. Prefer CSP frame-ancestors.",
      recommendation: "Replace with CSP frame-ancestors and DENY/SAMEORIGIN as needed.",
      observed: value,
    };
  }

  return {
    id: "xfo",
    header,
    severity: "fail",
    points: 0,
    maxPoints: max,
    title: "X-Frame-Options invalid",
    explanation: `Unrecognized value "${value}".`,
    recommendation: "Use DENY or SAMEORIGIN.",
    observed: value,
  };
}

function scorePermissions(value: string | undefined): Finding {
  const max = HEADER_WEIGHTS["permissions-policy"];
  const header = "Permissions-Policy";

  if (!value) {
    return {
      id: "permissions",
      header,
      severity: "warn",
      points: 3,
      maxPoints: max,
      title: "Permissions-Policy missing",
      explanation:
        "Without Permissions-Policy (formerly Feature-Policy), powerful APIs like camera, microphone, and geolocation default to browser allow rules — often too open for sensitive UIs.",
      recommendation:
        "Declare an explicit policy, e.g. camera=(), microphone=(), geolocation=(), interest-cohort=().",
      observed: null,
    };
  }

  const lower = value.toLowerCase();
  const disablesSomething = /=\(\)/.test(lower) || /=\(self\)/.test(lower);
  const allowsAll = /\*\s*[,)]|=\(\*\)/.test(lower);

  if (allowsAll && !disablesSomething) {
    return {
      id: "permissions",
      header,
      severity: "warn",
      points: 4,
      maxPoints: max,
      title: "Permissions-Policy too open",
      explanation: "The policy appears to allow broad feature access (*).",
      recommendation: "Deny sensitive features by default with empty allowlists (=()).",
      observed: value,
    };
  }

  if (disablesSomething) {
    return {
      id: "permissions",
      header,
      severity: "pass",
      points: max,
      maxPoints: max,
      title: "Permissions-Policy restricts features",
      explanation:
        "At least one feature is explicitly limited (empty allowlist or self-only), which is a solid baseline.",
      recommendation: "Expand the deny-list to cover unused powerful APIs.",
      observed: value,
    };
  }

  return {
    id: "permissions",
    header,
    severity: "warn",
    points: 6,
    maxPoints: max,
    title: "Permissions-Policy present",
    explanation:
      "A Permissions-Policy header is set. Review each directive against features your app actually needs.",
    recommendation: "Prefer explicit =() denials for unused capabilities.",
    observed: value,
  };
}

/** Score a raw header block. Safe for paste-only / fixture input. */
export function scoreHeaders(raw: string): Scorecard {
  const headers = parseHeaderBlock(raw);
  const findings: Finding[] = [
    scoreCsp(headers.get("content-security-policy")),
    scoreHsts(headers.get("strict-transport-security")),
    scoreXcto(headers.get("x-content-type-options")),
    scoreReferrer(headers.get("referrer-policy")),
    scoreXfo(headers.get("x-frame-options"), headers),
    scorePermissions(headers.get("permissions-policy")),
  ];

  const total = findings.reduce((sum, f) => sum + f.points, 0);

  return {
    total,
    maxTotal: MAX_TOTAL,
    grade: gradeFromTotal(total, MAX_TOTAL),
    findings,
    parsedCount: headers.size,
  };
}

export { MAX_TOTAL };
