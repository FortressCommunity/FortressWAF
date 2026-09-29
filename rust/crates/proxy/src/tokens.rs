//! Design token spine for the pages the WAF emits (the block page and the
//! challenge interstitial).
//!
//! This is the Rust port of the semantic layer in `tokens/colors.json`,
//! `tokens/spacing.json`, `tokens/borders.json` and `tokens/typography.json`.
//! It exists so the emitted HTML references **semantic CSS custom properties**
//! (`var(--surface-page)`, `var(--text-secondary)`, …) instead of raw hex — one
//! source of truth, both light and dark modes, token-by-intent.
//!
//! The primitive → semantic mapping matches the DTCG token files exactly; the
//! dark overrides match `tokens/colors.json` → `dark`.

/// A single two-tier token: light value and dark value.
struct Token {
    name: &'static str,
    light: &'static str,
    dark: &'static str,
}

/// The emitted token set. Each entry is `var(--{name})` in the CSS.
///
/// Semantic tokens only — primitives are inlined here solely as the resolved
/// values the semantic layer points at (matching the DTCG `{primitive.*}`
/// references). Pages reference `var(--semantic)` never the primitive.
const TOKENS: &[Token] = &[
    // surface (semantic.surface.*)
    Token {
        name: "surface-page",
        light: "#ffffff",
        dark: "#030712", /* gray.950 */
    },
    Token {
        name: "surface-card",
        light: "#ffffff",
        dark: "#111827", /* gray.900 */
    },
    Token {
        name: "surface-sunken",
        light: "#f9fafb",
        dark: "#000000", /* black */
    },
    // text (semantic.text.*)
    Token {
        name: "text-primary",
        light: "#111827",
        dark: "#f9fafb",
    },
    Token {
        name: "text-secondary",
        light: "#4b5563",
        dark: "#9ca3af",
    },
    Token {
        name: "text-tertiary",
        light: "#9ca3af",
        dark: "#6b7280",
    },
    // border (semantic.border.*)
    Token {
        name: "border-default",
        light: "#e5e7eb",
        dark: "#1f2937",
    },
    Token {
        name: "border-strong",
        light: "#6b7280",
        dark: "#9ca3af",
    },
    Token {
        name: "border-focus",
        light: "#3b82f6",
        dark: "#60a5fa",
    },
    Token {
        name: "border-error",
        light: "#ef4444",
        dark: "#f87171",
    },
    // feedback.error (semantic.feedback.error-*)
    Token {
        name: "error-bg",
        light: "#fef2f2",
        dark: "#450a0a",
    },
    Token {
        name: "error-text",
        light: "#991b1b",
        dark: "#fecaca",
    },
    Token {
        name: "error-border",
        light: "#fca5a5",
        dark: "#7f1d1d",
    },
    Token {
        name: "error-icon",
        light: "#dc2626",
        dark: "#f87171",
    },
    // spacing (tokens/spacing.json scale: 0,4,8,16,24,32,48,64,96)
    Token {
        name: "space-xs",
        light: "4px",
        dark: "4px",
    },
    Token {
        name: "space-sm",
        light: "8px",
        dark: "8px",
    },
    Token {
        name: "space-md",
        light: "16px",
        dark: "16px",
    },
    Token {
        name: "space-lg",
        light: "24px",
        dark: "24px",
    },
    Token {
        name: "space-xl",
        light: "32px",
        dark: "32px",
    },
    Token {
        name: "space-2xl",
        light: "48px",
        dark: "48px",
    },
    // radius (tokens/borders.json allowed: 0,2,6,10,14,20,9999)
    Token {
        name: "radius-sm",
        light: "6px",
        dark: "6px",
    },
    Token {
        name: "radius-md",
        light: "10px",
        dark: "10px",
    },
    Token {
        name: "radius-lg",
        light: "14px",
        dark: "14px",
    },
    Token {
        name: "radius-pill",
        light: "9999px",
        dark: "9999px",
    },
    // focus ring (tokens/shadows.json → focus-ring)
    Token {
        name: "focus-ring",
        light: "0 0 0 3px rgba(59,130,246,0.5)",
        dark: "0 0 0 3px rgba(96,165,250,0.6)",
    },
    // container (tokens/breakpoints.json → container widths)
    Token {
        name: "container-md",
        light: "600px",
        dark: "600px",
    },
];

/// Render the `:root` (light) and `[data-theme="dark"]` token blocks.
/// The dark block is applied automatically via `prefers-color-scheme` and can
/// be forced with `data-theme="dark"` on `<html>`.
pub fn token_css() -> String {
    let mut light = String::new();
    let mut dark = String::new();
    for t in TOKENS {
        light.push_str(&format!("    --{}: {};\n", t.name, t.light));
        dark.push_str(&format!("    --{}: {};\n", t.name, t.dark));
    }
    format!(
        ":root {{\n{light}    color-scheme: light dark;\n}}\n\
         @media (prefers-color-scheme: dark) {{\n  :root {{\n{dark}  }}\n}}\n\
         :root[data-theme=\"dark\"] {{\n{dark}}}\n"
    )
}

/// The shared stylesheet for every emitted page, built entirely from the token
/// spine. No raw hex or off-scale px appears below the token definitions.
pub fn base_page_css() -> String {
    format!(
        "{tokens}\
        *{{box-sizing:border-box}}\n\
        body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;\
        background:var(--surface-page);color:var(--text-primary);\
        font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;\
        font-size:16px;line-height:1.6}}\n\
        .card{{max-width:var(--container-md);width:90%;margin:var(--space-lg);padding:var(--space-xl);\
        border:1px solid var(--border-default);border-radius:var(--radius-lg);\
        background:var(--surface-card)}}\n\
        .badge{{display:inline-flex;align-items:center;gap:var(--space-sm);\
        padding:var(--space-xs) var(--space-sm);border-radius:var(--radius-pill);\
        font-size:12px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;\
        background:var(--error-bg);color:var(--error-text);border:1px solid var(--error-border)}}\n\
        .badge svg{{width:14px;height:14px;flex:none;color:var(--error-icon)}}\n\
        h1{{font-size:24px;line-height:1.25;margin:var(--space-md) 0 var(--space-sm)}}\n\
        h2{{font-size:20px;line-height:1.3;margin:0 0 var(--space-sm)}}\n\
        p{{color:var(--text-secondary);margin:var(--space-sm) 0}}\n\
        dl{{margin:var(--space-lg) 0 0;display:grid;grid-template-columns:auto 1fr;\
        gap:var(--space-sm) var(--space-md);font-size:14px}}\n\
        dt{{color:var(--text-tertiary)}}\n\
        dd{{margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;\
        color:var(--text-primary);word-break:break-word}}\n\
        .foot{{margin-top:var(--space-lg);font-size:13px;color:var(--text-tertiary)}}\n\
        button{{font:inherit;padding:var(--space-sm) var(--space-md);border-radius:var(--radius-md);\
        border:1px solid var(--border-strong);background:var(--surface-sunken);\
        color:var(--text-primary);cursor:pointer}}\n\
        button:hover{{background:var(--surface-page)}}\n\
        :focus-visible{{outline:none;box-shadow:var(--focus-ring);border-radius:var(--radius-sm)}}\n\
        @media (prefers-reduced-motion: reduce){{*{{animation:none!important;transition:none!important}}}}\n",
        tokens = token_css()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn token_css_defines_light_and_dark() {
        let css = token_css();
        assert!(css.contains(":root {"));
        assert!(css.contains("@media (prefers-color-scheme: dark)"));
        assert!(css.contains(":root[data-theme=\"dark\"]"));
        // Light and dark blocks both present.
        assert!(css.contains("--surface-page: #ffffff"));
        assert!(css.contains("--surface-page: #030712"));
    }

    #[test]
    fn base_css_has_no_raw_hex_outside_token_block() {
        let css = base_page_css();
        // Everything after the first closing of the token definitions (the
        // `.card` rule onward) must reference var(--…), not a raw hex.
        let body = css.split(".card{").nth(1).expect("body after tokens");
        assert!(
            !body.contains('#'),
            "raw hex leaked into the page rules: {body}"
        );
    }

    #[test]
    fn base_css_has_no_off_scale_px_in_page_rules() {
        let css = base_page_css();
        let body = css.split("*{box-sizing").nth(1).expect("page rules");
        // Only these raw px are allowed below the token layer: font sizes that
        // sit on the type scale. Everything else must be var(--…).
        let allowed: HashSet<&str> = ["1px", "12px", "13px", "14px", "16px", "20px", "24px"]
            .into_iter()
            .collect();
        // Pull every `NNpx` occurrence out of the rule text.
        let bytes = body.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                if body[i..].starts_with("px") {
                    let value = &body[start..i + 2];
                    assert!(
                        allowed.contains(value),
                        "off-scale px value in page rules: {value}"
                    );
                    i += 2;
                }
            } else {
                i += 1;
            }
        }
    }

    #[test]
    fn all_token_names_unique() {
        let names: HashSet<&str> = TOKENS.iter().map(|t| t.name).collect();
        assert_eq!(names.len(), TOKENS.len());
    }
}
