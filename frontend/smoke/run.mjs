// Smoke-test runner: bundles smoke/entry.tsx with esbuild (Vite's bundler) in
// SSR format and executes it under Node. Fails loudly on any render throw.

import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { execFileSync } from "node:child_process";

const here = path.dirname(fileURLToPath(import.meta.url));

await build({
  entryPoints: [path.join(here, "entry.tsx")],
  bundle: true,
  format: "cjs",
  platform: "node",
  jsx: "automatic",
  outfile: path.join(here, "out.cjs"),
  logLevel: "silent",
});

try {
  execFileSync(process.execPath, [path.join(here, "out.cjs")], { stdio: "inherit" });
} catch {
  process.exit(1);
}