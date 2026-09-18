// ============================================================================
// Project guide chatbot. A floating "?" button that answers questions about
// the project — backed by /api/chat (scoped Gemini 3.6 Flash), with the offline
// knowledge base (knowledge.ts) as an automatic fallback when the AI is off,
// misconfigured, rate-limited, or unreachable.
// ============================================================================

import { useEffect, useRef, useState, type FormEvent } from "react";
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

  const lines = text.split("\n");
  const processed: string[] = [];

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    // Bullet points
    if (/^[•\-\*]\s+/.test(trimmed)) {
      const bulletContent = trimmed.replace(/^[•\-\*]\s+/, "");
      processed.push(
        `<div class="guide-msg-item"><span>${formatInline(bulletContent, esc)}</span></div>`
      );
    } else if (trimmed === "") {
      processed.push("<div style='height:6px;'></div>");
    } else {
      processed.push(`<div>${formatInline(trimmed, esc)}</div>`);
    }
  }

  return processed.join("");
}

function formatInline(s: string, esc: (str: string) => string): string {
  return esc(s)
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<em>$1</em>")
    .replace(/`([^`]+)`/g, "<code>$1</code>");
}

async function chatAnswer(
  message: string,
  history: { role: "user" | "model"; text: string }[],
): Promise<string> {
  try {
    const ctrl = new AbortController();
    const timer = window.setTimeout(() => ctrl.abort(), 25_000);
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
    if (data && data.message) {
      return data.message;
    }
    return answerFor(message);
  } catch {
    return answerFor(message);
  }
}

export default function ProjectChatbot() {
  const [open, setOpen] = useState(false);
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
  }, [msgs, open, loading]);

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
        <section className="guide-bot" aria-label="Project guide">
          <header className="guide-bot__head">
            <div className="guide-bot__logo">?</div>
            <div style={{ minWidth: 0, flex: 1 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <strong>nocap guide</strong>
                <span className="guide-bot__live-badge">
                  <span className="dot" style={{ background: "var(--seal-2)" }} />
                  Gemini Live
                </span>
              </div>
              <div className="guide-bot__sub">Ground-truth project intelligence</div>
            </div>
            <button
              className="guide-bot__close"
              aria-label="Close guide"
              onClick={() => setOpen(false)}
            >
              <IconX size={16} />
            </button>
          </header>

          <div className="guide-bot__msgs" ref={listRef}>
            {msgs.length === 0 && (
              <p className="guide-bot__welcome">
                Ask about <strong>verification mechanics</strong>, <strong>cryptographic signing</strong>,{" "}
                <strong>revocation kill-switch</strong>, <strong>screening checks</strong>,{" "}
                or <strong>verification analytics</strong>.
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
                <div className="guide-typing" aria-label="Analyzing...">
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
              placeholder="Ask anything about nocap…"
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