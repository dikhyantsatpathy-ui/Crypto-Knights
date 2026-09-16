import { useEffect, useRef, useState } from "react";

const GLYPHS = "01!#$&*?@%XYZØ§Δλ_<>~^/[]{}|";

export function TerminalDecrypt({
  text = "before",
  className = "",
  autoStart = true,
}: {
  text?: string;
  className?: string;
  autoStart?: boolean;
}) {
  const [display, setDisplay] = useState(text);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const animatingRef = useRef(false);

  const trigger = () => {
    if (animatingRef.current) return;
    animatingRef.current = true;
    setIsDecrypting(true);

    const target = text;
    const len = target.length;
    let iteration = 0;
    const totalIterations = len * 4;

    const interval = window.setInterval(() => {
      iteration++;
      const resolvedChars = Math.floor(iteration / 4);

      const next = target
        .split("")
        .map((char, index) => {
          if (index < resolvedChars) {
            return target[index];
          }
          if (char === " ") return " ";
          return GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
        })
        .join("");

      setDisplay(next);

      if (iteration >= totalIterations) {
        window.clearInterval(interval);
        setDisplay(target);
        animatingRef.current = false;
        setIsDecrypting(false);
      }
    }, 38);
  };

  useEffect(() => {
    if (autoStart) {
      const timer = window.setTimeout(trigger, 140);
      return () => window.clearTimeout(timer);
    }
  }, [text, autoStart]);

  return (
    <span
      className={`terminal-decrypt ${isDecrypting ? "terminal-decrypt--active" : ""} ${className}`}
      onMouseEnter={trigger}
      title="Cryptographic terminal decryption — hover to reload cipher"
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") trigger();
      }}
    >
      <span className="terminal-decrypt__text">{display}</span>
      <span className="terminal-decrypt__cursor" aria-hidden="true" />
    </span>
  );
}
