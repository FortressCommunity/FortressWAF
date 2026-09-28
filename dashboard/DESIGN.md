# FortressWAF dashboard — design direction

Direction for the admin console only. It is a filter input for UI work, not a
spec for the product's behaviour.

## Identity

**Quiet glass.** A WAF is always on and mostly silent, so the console should
read as composed rather than alarmed. The previous neo-brutalist theme shouted:
near-white 2px borders on every surface, hard offset shadows, all-caps
black-weight headings. Every screen looked like a warning.

The console is an instrument panel. It reports a state; it does not perform.

- **Personality:** precise, restrained, trustworthy. Never playful, never loud.
- **Audience:** an operator watching traffic at a booth or a desk, often for a
  whole shift. Calm beats exciting.

## Palette

Colour carries state and nothing else. Cyan is the brand accent and marks
selection and the primary action; it is not decoration.

| Token | Dark | Light | Role |
|---|---|---|---|
| background | `#0A0E13` | `#EEF2F6` | Page backdrop |
| card | glass over backdrop | glass over backdrop | Floating panel |
| foreground | `#E9EEF3` | `#0F1720` | Body and headings |
| muted-foreground | `#99A6B4` | `#55616F` | Secondary text |
| primary | `#22B8D9` | `#0E7490` | Selection, primary action |
| destructive | `#FF6B85` | `#B4233A` | Critical severity, errors |
| warning | `#F0B429` | `#8A5A00` | High severity |
| input | `#5B6A7D` | `#7A899C` | Control boundary (≥3:1, WCAG 1.4.11) |

All pairs above are verified with `contrast-check.py`. Light mode has its own
amber rather than Tailwind's `yellow-500`, which measured 1.92:1 on white.

## Typography

**IBM Plex Sans** for interface text, **IBM Plex Mono** for machine data (rule
IDs, IP addresses, hashes, timestamps, paths).

The mono is functional: those strings are compared character by character and
must not be proportional. Plex also carries an engineering heritage that suits a
security tool, and it is not the Inter/Geist default that ships with every
generated interface.

Weights: 400 body, 500 emphasis, 600 headings. No 900. Headings are sentence
case; the all-caps eyebrow is gone.

## Surfaces

One glass recipe, applied to surfaces that float:

```
background: hsl(var(--card) / 0.62);
backdrop-filter: blur(18px) saturate(150%);
border: 1px solid hsl(var(--border));
box-shadow: 0 1px 0 hsl(var(--foreground) / 0.05) inset, 0 18px 40px -28px black;
```

Content inside a panel stays flat and transparent — table rows, list items and
inputs never get their own blur. Hierarchy comes from depth, so if every layer
frosts, nothing is in front.

**Dose:** glass is the surface language here, in more than the one or two
elements the antislop default allows. That is a deliberate override of R-10 at
the product owner's request ("clean, minimal, glass"). It is kept honest by
banning the rest of the glassmorphism starter kit: no glow, no gradient orbs,
no dotted grid, no pulsing status dots, and no blur on inner content.

## Shape and elevation

- Two radii: `--radius` 14px (panels, overlays), `--radius-sm` 9px (controls).
  Nothing is a pill.
- Two elevations: surface (hairline border, soft shadow) and overlay (the same,
  stronger). There is no third.
- Borders are 1px hairlines at low alpha. Control boundaries are the exception:
  they use `--input` to clear the 3:1 non-text minimum.

## Motion

150–200ms, `ease-out`, on hover, focus and entering overlays only. No infinite
animation. `prefers-reduced-motion` disables transitions entirely.
