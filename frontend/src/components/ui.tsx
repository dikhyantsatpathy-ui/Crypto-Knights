// ============================================================================
// Shared UI primitives — icons, buttons, cards, dropzone, modal, count-up.
// ============================================================================

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type CSSProperties,
  type ReactNode,
} from "react";
import { formatCount } from "../app/util";

// ----------------------------------------------------------------------------
// Icons — minimal inline SVG set (stroke-based, currentColor)
// ----------------------------------------------------------------------------

type IconProps = { size?: number; className?: string };

function base(size: number, className?: string) {
  return {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 2,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    className,
    "aria-hidden": true,
  };
}

export const IconShield = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10" />
    <path d="m9 12 2 2 4-4" />
  </svg>
);
export const IconCheck = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <path d="M20 6 9 17l-5-5" />
  </svg>
);
export const IconX = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <path d="M18 6 6 18" />
    <path d="m6 6 12 12" />
  </svg>
);
export const IconAlert = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z" />
    <path d="M12 9v4" />
    <path d="M12 17h.01" />
  </svg>
);
export const IconDoc = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <path d="M14 2v6h6" />
    <path d="m9 15 2 2 4-4" />
  </svg>
);
export const IconKey = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <circle cx="7.5" cy="15.5" r="4.5" />
    <path d="m21 2-9.6 9.6" />
    <path d="m15.5 7.5 3 3L22 7l-3-3" />
  </svg>
);
export const IconUsers = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
    <circle cx="9" cy="7" r="4" />
    <path d="M22 21v-2a4 4 0 0 0-3-3.87" />
    <path d="M16 3.13a4 4 0 0 1 0 7.75" />
  </svg>
);
export const IconLock = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
  </svg>
);
export const IconPen = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <path d="M12 20h9" />
    <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z" />
  </svg>
);
export const IconBolt = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z" />
  </svg>
);
export const IconCopy = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <rect width="14" height="14" x="8" y="8" rx="2" ry="2" />
    <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" />
  </svg>
);
export const IconHash = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <path d="M4 9h16" />
    <path d="M4 15h16" />
    <path d="M10 3 8 21" />
    <path d="M16 3l-2 18" />
  </svg>
);
export const IconLink = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
    <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
  </svg>
);
export const IconClock = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <circle cx="12" cy="12" r="10" />
    <path d="M12 6v6l4 2" />
  </svg>
);
export const IconQuestion = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <circle cx="12" cy="12" r="10" />
    <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
    <path d="M12 17h.01" />
  </svg>
);
export const IconEye = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" />
    <circle cx="12" cy="12" r="3" />
  </svg>
);
export const IconLayers = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <path d="M12 2 2 7l10 5 10-5-10-5Z" />
    <path d="m2 17 10 5 10-5" />
    <path d="m2 12 10 5 10-5" />
  </svg>
);
export const IconPhone = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <path d="M15 7a2 2 0 0 1 2 2" />
    <path d="M21 9a6 6 0 0 1-7.74 5.74L11 17H9v2H7v2H4a1 1 0 0 1-1-1v-2.59a1 1 0 0 1 .29-.7L9.26 10.7A6 6 0 1 1 21 9Z" />
  </svg>
);
export const IconGrid = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <rect width="7" height="7" x="3" y="3" rx="1" />
    <rect width="7" height="7" x="14" y="3" rx="1" />
    <rect width="7" height="7" x="14" y="14" rx="1" />
    <rect width="7" height="7" x="3" y="14" rx="1" />
  </svg>
);
export const IconBar = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <path d="M3 3v18h18" />
    <path d="M7 15l4-4 4 4 5-6" />
  </svg>
);
export const IconRefresh = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <path d="M3 12a9 9 0 0 1 15.36-6.36L21 8" />
    <path d="M21 3v5h-5" />
    <path d="M21 12a9 9 0 0 1-15.36 6.36L3 16" />
    <path d="M3 21v-5h5" />
  </svg>
);
export const IconSun = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <circle cx="12" cy="12" r="4" />
    <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41" />
  </svg>
);
export const IconMoon = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
  </svg>
);
export const IconChat = ({ size = 18, className }: IconProps) => (
  <svg {...base(size, className)}>
    <path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z" />
  </svg>
);

// ----------------------------------------------------------------------------
// Small primitives
// ----------------------------------------------------------------------------

export function Button({
  children,
  variant = "ghost",
  size,
  block,
  busy,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "ink" | "seal" | "ghost" | "danger-ghost";
  size?: "sm" | "lg";
  block?: boolean;
  busy?: boolean;
}) {
  const classes = [
    "btn",
    variant === "ink" ? "btn--ink" : variant === "seal" ? "btn--seal" : variant === "danger-ghost" ? "btn--danger-ghost" : "btn--ghost",
    size === "sm" ? "btn--sm" : size === "lg" ? "btn--lg" : "",
    block ? "btn--block" : "",
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <button className={classes} disabled={busy || rest.disabled} {...rest}>
      {busy && <span className="spinner" aria-hidden="true" />}
      {children}
    </button>
  );
}

export function Pill({
  tone = "slate",
  children,
  className,
  style,
}: {
  tone?: "seal" | "danger" | "amber" | "slate" | "night";
  children: ReactNode;
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <span className={`pill pill--${tone} ${className || ""}`} style={style}>
      {children}
    </span>
  );
}

export function Kicker({ children }: { children: ReactNode }) {
  return <div className="kicker">{children}</div>;
}

export function Card({
  title,
  icon,
  aside,
  children,
  flat,
  danger,
}: {
  title?: ReactNode;
  icon?: ReactNode;
  aside?: ReactNode;
  children: ReactNode;
  flat?: boolean;
  danger?: boolean;
}) {
  return (
    <section className={`card${flat ? " card--flat" : ""}`}>
      {title !== undefined && (
        <header className="card__head">
          <span className="title">
            <span className={`sq${danger ? " sq--danger" : ""}`} aria-hidden="true" />
            {icon}
            {title}
          </span>
          {aside && <span className="aside">{aside}</span>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Field({
  label,
  children,
  className,
}: {
  label: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <label className={`field ${className || ""}`}>
      <span className="field__label">{label}</span>
      {children}
    </label>
  );
}

// ----------------------------------------------------------------------------
// Dropzone — shared by verify / signing panels
// ----------------------------------------------------------------------------

export function Dropzone({
  label,
  sub,
  multiple,
  accept,
  files,
  onFiles,
  busy,
}: {
  label: string;
  sub?: string;
  multiple?: boolean;
  accept?: string;
  files: File[];
  onFiles: (files: File[]) => void;
  busy?: boolean;
}) {
  const [dragging, setDragging] = useState(false);

  const labelText =
    files.length === 0 ? label : files.length === 1 ? files[0].name : `${files.length} files selected`;

  // A REAL <label> wrapping a visually-hidden <input type="file">. Native
  // activation means the browser opens the picker itself, so a file input
  // ALWAYS works even when explain mode or another capture-phase handler is
  // watching clicks. `htmlFor`, JS .click(), and deep fake-labels all have
  // this as the fallback; a <div role="button"> does not.
  return (
    <label
      className={`dropzone${dragging ? " drag" : ""}${busy ? " dropzone--busy" : ""}`}
      tabIndex={0}
      onDragEnter={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragOver={(e) => e.preventDefault()}
      onDragLeave={(e) => {
        e.preventDefault();
        setDragging(false);
      }}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const dropped = Array.from(e.dataTransfer.files || []);
        if (dropped.length) onFiles(dropped);
      }}
    >
      {busy && (
        <span className="dropzone__busy" aria-hidden="true">
          <span className="spinner" />
        </span>
      )}
      <input
        className="dropzone__input"
        type="file"
        multiple={multiple}
        accept={accept}
        onChange={(e) => {
          onFiles(Array.from(e.target.files || []));
          e.target.value = "";
        }}
      />
      <div className="dropzone__icon">
        <IconDoc size={20} />
      </div>
      <div className="dropzone__title">{labelText}</div>
      {sub && <div className="dropzone__sub">{sub}</div>}
    </label>
  );
}

// ----------------------------------------------------------------------------
// CountUp — eases a number to its target with rAF
// ----------------------------------------------------------------------------

export function CountUp({ target, className }: { target: number; className?: string }) {
  const [value, setValue] = useState(0);
  const prevTarget = useRef(0);

  useEffect(() => {
    const from = prevTarget.current;
    const to = target;
    if (from === to) {
      setValue(to);
      return;
    }
    const duration = 900;
    const start = performance.now();
    let raf = 0;
    const step = (now: number) => {
      const p = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      setValue(Math.round(from + (to - from) * eased));
      if (p < 1) raf = requestAnimationFrame(step);
      else prevTarget.current = to;
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target]);

  return <span className={className}>{formatCount(value)}</span>;
}

// ----------------------------------------------------------------------------
// Modal
// ----------------------------------------------------------------------------

export function Modal({
  title,
  onClose,
  children,
  footer,
  narrow,
}: {
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  narrow?: boolean;
}) {
  const onKey = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    },
    [onClose],
  );

  useEffect(() => {
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [onKey]);

  return (
    <div className="modal-overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal${narrow ? " modal--narrow" : ""}`} role="dialog" aria-modal="true">
        <header className="modal__head">
          <h3>{title}</h3>
          <button className="modal__close" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>
        <div className="modal__body">{children}</div>
        {footer && <footer className="modal__foot">{footer}</footer>}
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Count / empty-state note
// ----------------------------------------------------------------------------

export function EmptyNote({ children }: { children: ReactNode }) {
  return <div className="empty-note">{children}</div>;
}

/** Google single-ign-in script loader: resolves once the GSI lib is present. */
export function useGsiReady(): boolean {
  const [ready, setReady] = useState(false);
  useEffect(() => {
    if (window.google?.accounts?.id) {
      setReady(true);
      return;
    }
    const t = window.setInterval(() => {
      if (window.google?.accounts?.id) {
        setReady(true);
        window.clearInterval(t);
      }
    }, 200);
    return () => window.clearInterval(t);
  }, []);
  return ready;
}