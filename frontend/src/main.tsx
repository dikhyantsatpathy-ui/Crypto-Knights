// ============================================================================
// Entry point — mounts the App inside providers.
// ============================================================================

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { AuthProvider, ToastProvider } from "./app/state";
import { ExplainProvider } from "./app/explain";
import { App } from "./App";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ToastProvider>
      <AuthProvider>
        <ExplainProvider>
          <App />
        </ExplainProvider>
      </AuthProvider>
    </ToastProvider>
  </StrictMode>,
);