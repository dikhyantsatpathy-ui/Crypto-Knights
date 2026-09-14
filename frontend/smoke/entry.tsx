// SSR smoke test: renders the whole App (with providers) to a string in Node,
// proving the module graph mounts without throwing and produces key markup.
// Used only in CI/dev — never shipped.

import { renderToString } from "react-dom/server";
import { AuthProvider, ToastProvider } from "../src/app/state";
import { App } from "../src/App";

const html = renderToString(
  <ToastProvider>
    <AuthProvider>
      <App />
    </AuthProvider>
  </ToastProvider>,
);

const checks: [string, boolean][] = [
  ["hero headline", html.includes("The time to doubt")],
  ["verify panel", html.includes("Verify it in the ledger")],
  ["bulletin board", html.includes("Bulletin board")],
  ["nav tabs", html.includes("Authority") && html.includes("Analytics")],
  ["footer team", html.includes("Dikhyant Satapathy")],
  ["status band", html.includes("PROVENANCE LEDGER")],
];

let fail = 0;
for (const [name, ok] of checks) {
  if (!ok) {
    fail += 1;
    console.error(`SMOKE FAIL: ${name}`);
  } else {
    console.log(`smoke ok: ${name}`);
  }
}
console.log(`rendered ${html.length} chars`);
process.exit(fail ? 1 : 0);