"use client";

import { useEffect, useMemo, useState, useTransition } from "react";
import { FIXTURES } from "@/lib/fixtures";
import { scoreHeaders, type Finding, type Scorecard } from "@/lib/headers";
import styles from "./score-desk.module.css";

const STORAGE_KEY = "header-score:last-paste";

/** Primary fixture buttons requested for demos. */
const FEATURED_FIXTURE_IDS = ["missing-hsts", "weak-csp", "newsprint-shop"] as const;

function severityClass(severity: Finding["severity"]): string {
  if (severity === "pass") return styles.pass;
  if (severity === "warn") return styles.warn;
  return styles.fail;
}

function GradeMark({ card }: { card: Scorecard }) {
  return (
    <div className={styles.gradeBlock} aria-label={`Grade ${card.grade}`}>
      <span className={styles.gradeLetter}>{card.grade}</span>
      <span className={styles.gradeMeta}>
        {card.total}
        <span className={styles.gradeSlash}>/</span>
        {card.maxTotal}
      </span>
      <span className={styles.gradeCaption}>points</span>
    </div>
  );
}

function readStoredPaste(): { raw: string; fixtureId: string } | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { raw?: string; fixtureId?: string };
    if (typeof parsed.raw !== "string" || !parsed.raw.trim()) return null;
    return {
      raw: parsed.raw,
      fixtureId: typeof parsed.fixtureId === "string" ? parsed.fixtureId : "",
    };
  } catch {
    return null;
  }
}

export function ScoreDesk() {
  const [raw, setRaw] = useState(FIXTURES[0].headers);
  const [fixtureId, setFixtureId] = useState(FIXTURES[0].id);
  const [hydrated, setHydrated] = useState(false);
  const [pending, startTransition] = useTransition();

  useEffect(() => {
    const stored = readStoredPaste();
    if (stored) {
      setRaw(stored.raw);
      setFixtureId(stored.fixtureId);
    }
    setHydrated(true);
  }, []);

  useEffect(() => {
    if (!hydrated) return;
    try {
      localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({ raw, fixtureId }),
      );
    } catch {
      // quota / private mode — scoring still works
    }
  }, [raw, fixtureId, hydrated]);

  const card = useMemo(() => scoreHeaders(raw), [raw]);

  function applyFixture(id: string) {
    const fixture = FIXTURES.find((f) => f.id === id);
    if (!fixture) return;
    setFixtureId(id);
    startTransition(() => {
      setRaw(fixture.headers);
    });
  }

  const featured = FEATURED_FIXTURE_IDS.map(
    (id) => FIXTURES.find((f) => f.id === id)!,
  ).filter(Boolean);

  return (
    <div className={styles.desk}>
      <header className={styles.masthead}>
        <p className={styles.pressMark}>Rumaneh Press · Vol. XX</p>
        <h1 className={styles.brand}>HeaderScore</h1>
        <p className={styles.lede}>
          Paste response headers. Read the scorecard. No remote fetches — fixtures and paste
          only.
        </p>
      </header>

      <div className={styles.board}>
        <section className={styles.inputPane} aria-labelledby="paste-heading">
          <div className={styles.paneHead}>
            <h2 id="paste-heading">Copy desk</h2>
          </div>

          <div className={styles.fixtureRow} role="group" aria-label="Header fixtures">
            {featured.map((f) => (
              <button
                key={f.id}
                type="button"
                className={
                  fixtureId === f.id ? styles.fixtureBtnActive : styles.fixtureBtn
                }
                onClick={() => applyFixture(f.id)}
                title={f.blurb}
              >
                {f.id === "newsprint-shop"
                  ? "Good baseline"
                  : f.id === "missing-hsts"
                    ? "Missing HSTS"
                    : "Weak CSP"}
              </button>
            ))}
            {FIXTURES.filter(
              (f) =>
                !(FEATURED_FIXTURE_IDS as readonly string[]).includes(f.id),
            ).map((f) => (
              <button
                key={f.id}
                type="button"
                className={
                  fixtureId === f.id ? styles.fixtureBtnActive : styles.fixtureBtn
                }
                onClick={() => applyFixture(f.id)}
                title={f.blurb}
              >
                {f.label}
              </button>
            ))}
          </div>

          <p className={styles.hint}>
            {FIXTURES.find((f) => f.id === fixtureId)?.blurb ??
              "Edit freely — analysis stays in the browser. Last paste is saved to localStorage."}
          </p>
          <textarea
            className={styles.textarea}
            value={raw}
            onChange={(e) => {
              setFixtureId("");
              setRaw(e.target.value);
            }}
            spellCheck={false}
            rows={16}
            aria-label="HTTP response headers"
            placeholder={"HTTP/2 200\nstrict-transport-security: max-age=31536000\n…"}
          />
          <p className={styles.parsed}>
            Parsed {card.parsedCount} header{card.parsedCount === 1 ? "" : "s"}
            {pending ? " · updating…" : ""}
            {hydrated ? " · session saved" : ""}
          </p>
        </section>

        <section className={styles.scorePane} aria-labelledby="score-heading">
          <div className={styles.paneHead}>
            <h2 id="score-heading">Scorecard</h2>
            <GradeMark card={card} />
          </div>

          <ol className={styles.findings}>
            {card.findings.map((f) => (
              <li key={f.id} className={`${styles.finding} ${severityClass(f.severity)}`}>
                <div className={styles.findingTop}>
                  <span className={styles.stamp}>{f.severity}</span>
                  <span className={styles.points}>
                    {f.points}/{f.maxPoints}
                  </span>
                </div>
                <h3 className={styles.findingTitle}>{f.title}</h3>
                <p className={styles.headerName}>{f.header}</p>
                <p className={styles.explanation}>{f.explanation}</p>
                <p className={styles.recommendation}>
                  <span className={styles.recLabel}>Next</span> {f.recommendation}
                </p>
                {f.observed ? (
                  <pre className={styles.observed}>{f.observed}</pre>
                ) : (
                  <p className={styles.absent}>Not observed in paste</p>
                )}
              </li>
            ))}
          </ol>
        </section>
      </div>

      <footer className={styles.colophon}>
        <span>MIT 2026 Saeed Rumaneh</span>
        <span className={styles.sep}>·</span>
        <span>Paste-only · see SECURITY.md</span>
      </footer>
    </div>
  );
}
