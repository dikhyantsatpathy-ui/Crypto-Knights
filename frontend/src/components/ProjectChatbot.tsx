// ============================================================================
// Project guide chatbot. A floating "?" button that answers questions about
// the project from the offline knowledge base (knowledge.ts).
//   - FAB opens/closes the panel (and deliberately stays OUT of explain mode's
//     interception list, since it's a helper, not a tool).
//   - After OPEN_MS of idle browsing it pops open once to invite a question.
//   - No network: searchKnowledge() + formatAnswer() only.
// ============================================================================

import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  answerFor,
  SUGGESTED_QUESTIONS,
  type BotMessage,
} from "../knowledge";
import { IconChat, IconX } from "./ui";

const OPEN_MS = 26_000;

export default function ProjectChatbot() {
  const [open, setOpen] = useState(false);
  const [invited, setInvited] = useState(false);
  const [asked, setAsked] = useState(false);
  const [input, setInput] = useState("");
  const [msgs, setMsgs] = useState<BotMessage[]>([]);
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

  // keep the newest message in view
  useEffect(() => {
    const el = listRef.current;
    if (el && msgs.length) el.scrollTop = el.scrollHeight;
  }, [msgs, open]);

  const ask = (text: string) => {
    const q = text.trim();
    if (!q) return;
    setAsked(true);
    setInvited(true);
    setOpen(true);
    setMsgs((m) => [...m, { role: "user", text: q }]);
    window.setTimeout(() => {
      setMsgs((m) => [...m, { role: "bot", text: answerFor(q) }]);
    }, 260);
    setInput("");
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
            <div>
              <strong>nocap guide</strong>
              <div className="guide-bot__sub">answers from the project's own notes</div>
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
                Ask about <strong>verify</strong>, <strong>sign</strong>,{" "}
                <strong>revoke</strong>, <strong>screening</strong>,{" "}
                <strong>analytics</strong>… or tap a shortcut below.
              </p>
            )}
            {msgs.map((m, i) => (
              <div
                key={i}
                className={`guide-msg guide-msg--${m.role}`}
                dangerouslySetInnerHTML={{
                  __html:
                    m.text
                      .replace(/</g, "&lt;")
                      .replace(/>/g, "&gt;")
                      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
                      .replace(/\*([^*]+)\*/g, "<em>$1</em>")
                      .replace(/`([^`]+)`/g, "<code>$1</code>")
                      .replace(/\n/g, "<br/>") || "",
                }}
              />
            ))}
          </div>

          {!asked && (
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
              placeholder="Ask about nocap…"
              value={input}
              onChange={(e) => setInput(e.target.value)}
            />
            <button className="guide-bot__send" aria-label="Send" disabled={!input.trim()}>
              ➤
            </button>
          </form>
        </section>
      )}
    </>
  );
}