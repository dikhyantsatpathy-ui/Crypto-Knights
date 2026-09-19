// ============================================================================
// Project guide chatbot. A floating "?" button that answers questions about
// the project — backed by /api/chat (scoped Gemini with full codebase ingestion),
// with the offline knowledge base (knowledge.ts) as an automatic fallback when
// the AI is off, misconfigured, rate-limited, or unreachable.
// ============================================================================

import { useEffect, useRef, useState, type FormEvent, type MouseEvent } from "react";
import {
  answerFor,
  SUGGESTED_QUESTIONS,
  type BotMessage,
} from "../knowledge";
import { IconChat, IconX } from "./ui";

const OPEN_MS = 26_000;

function formatBotMarkdown(text: string): string {
  const esc = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  // 1. Extract fenced code blocks: ```lang\ncode\n```
  const codeBlocks: string[] = [];
  const textWithPlaceholders = text.replace(
    /```([a-zA-Z0-9_\-]*)\r?\n([\s\S]*?)```/g,
    (_match, lang, code) => {
      const idx = codeBlocks.length;
      const cleanCode = code.replace(/\r?\n$/, "");
      const langLabel = (lang || "code").toLowerCase();
      const encoded = encodeURIComponent(cleanCode);
      const blockHtml = `<div class="guide-code-box"><div class="guide-code-box__header"><span>${esc(
        langLabel
      )}</span><button type="button" class="guide-code-box__copy guide-code-copy" data-copy="${encoded}">Copy</button></div><pre><code>${esc(
        cleanCode
      )}</code></pre></div>`;
      codeBlocks.push(blockHtml);
      return `\n%%CODE_BLOCK_${idx}%%\n`;
    }
  );

  const lines = textWithPlaceholders.split("\n");
  const processed: string[] = [];

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();

    // Check placeholder
    const placeholderMatch = trimmed.match(/^%%CODE_BLOCK_(\d+)%%$/);
    if (placeholderMatch) {
      const blockIdx = parseInt(placeholderMatch[1], 10);
      processed.push(codeBlocks[blockIdx] || "");
      continue;
    }

    // Markdown Headers
    if (/^###\s+/.test(trimmed)) {
      const hText = trimmed.replace(/^###\s+/, "");
      processed.push(`<div class="guide-h4">${formatInline(hText, esc)}</div>`);
    } else if (/^##\s+/.test(trimmed)) {
      const hText = trimmed.replace(/^##\s+/, "");
      processed.push(`<div class="guide-h3">${formatInline(hText, esc)}</div>`);
    } else if (/^#\s+/.test(trimmed)) {
      const hText = trimmed.replace(/^#\s+/, "");
      processed.push(`<div class="guide-h2">${formatInline(hText, esc)}</div>`);
    } else if (/^[•\-\*]\s+/.test(trimmed)) {
      // Bullet list
      const bulletContent = trimmed.replace(/^[•\-\*]\s+/, "");
      processed.push(
        `<div class="guide-msg-item"><span>${formatInline(bulletContent, esc)}</span></div>`
      );
    } else if (/^\d+\.\s+/.test(trimmed)) {
      // Numbered list
      const numMatch = trimmed.match(/^(\d+)\.\s+(.*)$/);
      if (numMatch) {
        processed.push(
          `<div class="guide-msg-item"><span style="font-weight:700;color:var(--seal);font-family:var(--mono);">${numMatch[1]}.</span> <span>${formatInline(
            numMatch[2],
            esc
          )}</span></div>`
        );
      } else {
        processed.push(`<div>${formatInline(trimmed, esc)}</div>`);
      }
    } else if (trimmed === "") {
      processed.push("<div style='height:6px;'></div>");
    } else {
      processed.push(`<div>${formatInline(trimmed, esc)}</div>`);
    }
  }

  return processed.join("");
}

function formatInline(s: string, esc: (str: string) => string): string {
  let out = esc(s)
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<em>$1</em>")
    .replace(/`([^`]+)`/g, "<code>$1</code>");

  // Format citations like (app/main.py:122) or app/screening.py:30-40 or frontend/src/App.tsx:20
  out = out.replace(
    /(?:\b|\()((?:app|frontend|scripts|tests)\/[a-zA-Z0-9_\-\.\/]+:\d+(?:-\d+)?)(?:\b|\))/g,
    `<span class="guide-citation">$1</span>`
  );

  return out;
}

async function chatAnswer(
  message: string,
  history: { role: "user" | "model"; text: string }[],
): Promise<string> {
  try {
    const ctrl = new AbortController();
    const timer = window.setTimeout(() => ctrl.abort(), 60_000);
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, history }),
      credentials: "include",
      signal: ctrl.signal,
    });
    window.clearTimeout(timer);
    const data = (await res.json()) as {
      ok?: boolean;
      answer?: string;
      message?: string;
    };
    if (data && data.ok && data.answer) {
      return data.answer;
    }
    // If backend AI hit an error, is unconfigured, or rate-limited, fall back to offline curated knowledge base
    const fallback = answerFor(message);
    if (fallback) {
      return fallback;
    }
    if (data && data.message) {
      return data.message;
    }
    return answerFor(message) || "";
  } catch {
    return answerFor(message) || "";
  }
}

export default function ProjectChatbot() {
  const [open, setOpen] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [invited, setInvited] = useState(false);
  const [asked, setAsked] = useState(false);
  const [input, setInput] = useState("");
  const [msgs, setMsgs] = useState<BotMessage[]>([]);
  const [loading, setLoading] = useState(false);
  const listRef = useRef<HTMLDivElement | null>(null);

  // One gentle invitation after a while, unless the user already asked
  // something or explicitly closed the panel.
  useEffect(() => {
    if (invited || open || asked) return;
    const id = window.setTimeout(() => {
      setInvited(true);
      setOpen(true);
    }, OPEN_MS);
    return () => window.clearTimeout(id);
  }, [invited, open, asked]);

  // Keep the newest message in view
  useEffect(() => {
    const el = listRef.current;
    if (el && msgs.length) el.scrollTop = el.scrollHeight;
  }, [msgs, open, loading, expanded]);

  const ask = (text: string) => {
    const q = text.trim();
    if (!q || loading) return;
    setAsked(true);
    setInvited(true);
    setOpen(true);
    setInput("");
    setLoading(true);

    const history = msgs.slice(-10).map(({ role, text: t }) => ({
      role: (role === "bot" ? "model" : "user") as "user" | "model",
      text: t,
    }));

    setMsgs((m) => [...m, { role: "user", text: q }]);

    chatAnswer(q, history)
      .then((answer) => {
        setMsgs((m) => [...m, { role: "bot", text: answer }]);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    ask(input);
  };

  // Delegated click handler for code block copy buttons
  const onListClick = (e: MouseEvent<HTMLDivElement>) => {
    const target = (e.target as HTMLElement).closest(".guide-code-copy");
    if (target) {
      const code = target.getAttribute("data-copy");
      if (code) {
        navigator.clipboard.writeText(decodeURIComponent(code));
        const original = target.textContent ?? "Copy";
        target.textContent = "Copied!";
        setTimeout(() => {
          target.textContent = original;
        }, 1800);
      }
    }
  };

  return (
    <>
      <button
        className={`guide-fab${open ? " guide-fab--open" : ""}`}
        aria-label="Open the project guide"
        title="Project guide"
        onClick={() => setOpen((v) => !v)}
      >
        <IconChat size={22} />
      </button>

      {open && (
        <section className={`guide-bot${expanded ? " guide-bot--expanded" : ""}`} aria-label="Project guide">
          <header className="guide-bot__head">
            <div className="guide-bot__logo">?</div>
            <div style={{ minWidth: 0, flex: 1 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <strong>nocap guide</strong>
                <span className="guide-bot__live-badge">
                  <span className="dot" style={{ background: "var(--seal-2)" }} />
                  Full Codebase Live
                </span>
              </div>
              <div className="guide-bot__sub">Instant visibility into every line of code</div>
            </div>
            <div className="guide-bot__actions">
              <button
                type="button"
                className="guide-head-btn"
                aria-label={expanded ? "Restore standard size" : "Expand size for code reading"}
                title={expanded ? "Restore standard size" : "Expand for reading code"}
                onClick={() => setExpanded((v) => !v)}
              >
                {expanded ? "⤡" : "⤢"}
              </button>
              {msgs.length > 0 && (
                <button
                  type="button"
                  className="guide-head-btn"
                  aria-label="Clear chat"
                  title="Clear chat"
                  onClick={() => {
                    setMsgs([]);
                    setAsked(false);
                  }}
                >
                  ↺
                </button>
              )}
              <button
                type="button"
                className="guide-head-btn"
                aria-label="Close guide"
                title="Close"
                onClick={() => setOpen(false)}
              >
                <IconX size={15} />
              </button>
            </div>
          </header>

          <div className="guide-bot__msgs" ref={listRef} onClick={onListClick}>
            {msgs.length === 0 && (
              <p className="guide-bot__welcome">
                Ask about <strong>cryptographic signing</strong>, <strong>Merkle tree blockchain anchoring</strong>,{" "}
                <strong>kill-switch revocation</strong>, <strong>MHA identity screening</strong>,{" "}
                <strong>FastAPI backend routes</strong>, <strong>React components</strong>, or any file in the <strong>entire repository</strong>.
              </p>
            )}
            {msgs.map((m, i) => (
              <div
                key={i}
                className={`guide-msg guide-msg--${m.role}`}
                dangerouslySetInnerHTML={{
                  __html:
                    m.role === "bot"
                      ? formatBotMarkdown(m.text)
                      : formatInline(m.text, (s) =>
                          s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
                        ),
                }}
              />
            ))}
            {loading && (
              <div className="guide-msg guide-msg--bot">
                <div className="guide-typing" aria-label="Analyzing codebase...">
                  <span />
                  <span />
                  <span />
                </div>
              </div>
            )}
          </div>

          {!asked && msgs.length === 0 && (
            <div className="guide-bot__chips">
              {SUGGESTED_QUESTIONS.map((q) => (
                <button key={q} className="guide-chip" onClick={() => ask(q)}>
                  {q}
                </button>
              ))}
            </div>
          )}

          <form className="guide-bot__input" onSubmit={onSubmit}>
            <input
              className="input"
              placeholder="Ask anything about the code or architecture…"
              value={input}
              disabled={loading}
              onChange={(e) => setInput(e.target.value)}
            />
            <button className="guide-bot__send" aria-label="Send" disabled={!input.trim() || loading}>
              ➤
            </button>
          </form>
        </section>
      )}
    </>
  );
}