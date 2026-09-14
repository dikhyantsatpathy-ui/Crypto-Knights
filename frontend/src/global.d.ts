// Ambient declarations for the Google Identity Services script loaded from
// https://accounts.google.com/gsi/client (see index.html). Only the tiny slice
// of the API we actually use is typed here — no external typings package.

interface GsiButtonOptions {
  type?: "standard" | "icon";
  shape?: "rectangular" | "pill" | "circle" | "square";
  theme?: "outline" | "filled_blue" | "filled_black";
  text?: "signin_with" | "signup_with" | "continue_with" | "signin";
  size?: "large" | "medium" | "small";
  logo_alignment?: "left" | "center";
}

interface GsiCredentialResponse {
  credential: string;
  select_by?: string;
}

interface GsiId {
  initialize: (config: {
    client_id: string;
    callback: (response: GsiCredentialResponse) => void;
    auto_select?: boolean;
    ux_mode?: "popup" | "redirect";
    auto_prompt?: boolean;
    cancel_on_tap_outside?: boolean;
  }) => void;
  renderButton: (parent: HTMLElement, options?: GsiButtonOptions) => void;
}

interface Window {
  google?: {
    accounts?: {
      id?: GsiId;
    };
  };
}