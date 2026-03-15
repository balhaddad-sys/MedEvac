# MedEvac — Complete UI Design Specification

> Use this document as a prompt reference to generate an accurate demo video of the MedEvac app.

---

## App Overview

**MedEvac** is a mobile-first Progressive Web App (PWA) for **Mubarak Al-Kabeer Hospital** used to manage patient triage and evacuation tracking. The interface is **Right-to-Left (RTL)** for Arabic, constrained to a **430px max-width** phone viewport, and styled with a clean medical-professional aesthetic.

---

## 1. Color Palette

### Primary Blues
| Token | Hex | Usage |
|-------|-----|-------|
| `--pri` | `#1e3a5f` | Dark navy — header gradient start |
| `--pri2` | `#1e40af` | Bright blue — header gradient end, theme color |
| `--pri3` | `#2563eb` | Light blue — links, highlights |
| `--acc` | `#2563eb` | Accent — buttons, focus rings, active states |
| `--acc2` | `#3b82f6` | Lighter accent — hover states |

### Triage / Severity Colors
| Token | Hex | Meaning |
|-------|-----|---------|
| `--g` | `#10b981` | **Green** — Code 1, stable patients |
| `--y` | `#f59e0b` | **Yellow** — Code 2, moderate severity |
| `--r` | `#ef4444` | **Red** — Code 3, critical patients |
| Critical | `#dc2626` | Darker red for animated critical state |

### Backgrounds & Neutrals
| Token | Hex | Usage |
|-------|-----|-------|
| `--bg` | `#f0f4f8` | Page background (light blue-gray) |
| `--bg2` | `#e2e8f0` | Secondary background |
| `--card` | `#ffffff` | Card surfaces |
| `--txt` | `#1e293b` | Primary text (dark slate) |
| `--muted` | `#64748b` | Secondary text |
| `--muted2` | `#94a3b8` | Tertiary/placeholder text |
| `--border` | `#e2e8f0` | Card borders |
| `--border2` | `#cbd5e1` | Input borders |

### Transparency Layers
| Token | Value | Usage |
|-------|-------|-------|
| `--acc-bg` | `rgba(37,99,235,.06)` | Accent tint backgrounds |
| `--acc-glow` | `rgba(37,99,235,.12)` | Focus glow rings |
| `--glass` | `rgba(255,255,255,.7)` | Glass-morphism panels |
| `--gbg` | `rgba(16,185,129,.07)` | Green tinted background |
| `--ybg` | `rgba(245,158,11,.07)` | Yellow tinted background |
| `--rbg` | `rgba(239,68,68,.06)` | Red tinted background |

### Gender Accent Colors
- **Male:** `#2563eb` (blue)
- **Female:** `#d946ef` (magenta/pink)

### PWA / Splash
- iOS launch background: `#0f0f1f` (very dark navy)
- PWA manifest background: `#122a57`

---

## 2. Typography

### Font
- **Family:** `Inter` (Google Fonts), fallback: `system-ui, -apple-system, BlinkMacSystemFont, sans-serif`
- **Direction:** RTL (Right-to-Left)
- **Smoothing:** Antialiased on all platforms

### Scale
| Element | Size | Weight | Notes |
|---------|------|--------|-------|
| Hero title | 44px | 900 (Black) | Letter-spacing: -2px |
| Admin heading | 26px | 900 | Letter-spacing: -0.5px |
| Page header (h1) | 17px | 800 | — |
| Patient name | 14px | 700 | — |
| Body text | 12–14px | 600–700 | — |
| Labels (uppercase) | 10px | 700 | Letter-spacing: 0.5–1.2px |
| Meta / subtitle | 10–11px | 500–600 | Muted color |
| Tiny badges | 9px | 600–700 | Uppercase |

---

## 3. Layout & Structure

### Viewport
- **Max width:** 430px, centered on screen
- **Height:** 100dvh (full dynamic viewport)
- **Background:** `--bg` with a subtle radial gradient overlay

### Screen Anatomy (top to bottom)
1. **Header bar** — gradient background (`135deg, #1e3a5f → #1e40af`), white text, safe-area padding at top. Contains: back button (left), title + subtitle (center), action button (right). Each icon button is 38×38px with semi-transparent white background.
2. **Stats row** (on ward screens) — 4-column grid showing patient counts: All / Green / Yellow / Red. Active filter has a bottom border accent.
3. **Search bar** — rounded input with a circular blue "+" add button (42×42px).
4. **Content area** — scrollable list of patient cards, no visible scrollbar.
5. **Footer area** — install banner (PWA) or action buttons, respects safe-area bottom inset.

---

## 4. Screens & Pages

### Home / Dashboard
- **Hero card:** Full-width rounded card with the same blue gradient as the header. Shows hospital name, total patient count in large white text (44px/900 weight), and a subtitle.
- **Unit cards (×5):** Each card represents a hospital unit (A–E). Card shows unit letter badge, unit name, and two gender buttons — blue (Male) and magenta (Female). Tapping a gender button navigates to that unit's patient list.
- **Header buttons:** Export (download icon) and Settings (gear icon) in the top-right.
- **Status indicator:** Small colored dot — green pulse = online, gray = offline.

### Ward View
- Lists all wards as cards. Each ward card shows: ward name, colored unit tags, and small severity count badges (green/yellow/red numbers).
- Search bar at top filters wards by name.

### Unit / Ward Patient List
- **Stats row** at top: 4 boxes showing count of All, Green, Yellow, Red patients. Tapping a color filters the list.
- **Patient cards** listed vertically, sorted critical-first.
- **Search bar** filters by name, civil ID, or ward number.

### Patient Card (the core repeating component)
- White card, 1px border, 20px border-radius, soft shadow.
- **Left edge:** 3px vertical color strip indicating triage (green/yellow/red).
- **Badge circle:** 46×46px circle with severity code number (1/2/3) and a tiny label below. Background matches triage color.
- **Center info:** Patient name (14px bold), civil ID, nationality, notes — stacked vertically in muted smaller text.
- **Right tag:** Ward/Room label in accent blue styling.
- **Critical patients:** The color strip pulses/animates.
- **Tap interaction:** Card scales to 0.98 on press.

### PIN Entry
- Full-screen overlay with dark blur backdrop (0.85 opacity).
- **4-dot indicator** at top — dots fill with accent blue as digits are entered, with a pop animation.
- **Number pad:** 3×4 grid of circular buttons (72×72px), frosted glass style with backdrop blur. Digits 1–9, then empty / 0 / backspace.
- **Error state:** Dots and pad shake horizontally (0.5s).
- **Key press:** Button scales down to 0.88 with accent glow.

### Patient Detail (View/Edit)
- Displays patient info in form layout: Civil ID and Nationality shown as read-only styled fields, Ward/Room/Code/Notes/Doctor/Diagnosis as editable inputs.
- **Code picker:** 3-column grid. Each option is a rounded box; selected option fills with its triage color and white text.
- **Footer buttons:** Blue "Save" button and red "Delete" button.

### Add Patient
- Same form layout as Detail, all fields editable.
- Validation highlights and duplicate detection.
- Blue "Save" button at bottom.

### Admin Dashboard
- **Tab bar** at top with 4 tabs: Overview, OCR, Audit, Security.
- **Overview tab:** Large stat numbers (26px/900 weight) for total patients, then collapsible accordion for each unit showing gender sections with patient row strips color-coded by triage.
- **OCR tab:** Camera/upload button, displays extracted patient data as editable cards, bulk import button.
- **Audit tab:** Scrollable event log — each entry shows timestamp, action icon, unit name, and detail text.
- **Security tab:** PIN management per unit, password change form.

---

## 5. Component Design Tokens

### Cards
- Background: white (`--card`)
- Border: 1px solid `--border`
- Border-radius: 20px
- Shadow: `0 1px 3px rgba(15,23,42,.04), 0 4px 12px rgba(15,23,42,.06)`
- Padding: 16px

### Buttons
| Type | Background | Text | Border-radius | Size |
|------|-----------|------|---------------|------|
| Primary (`.btn`) | Blue gradient | White | 14px | Full-width, 11px padding |
| Secondary (`.btn2`) | White/card | Dark text | 14px | Full-width |
| Destructive (`.btnd`) | Red tint `--rbg` | Red `--r` | 14px | Full-width |
| Floating Add | Blue gradient | White | 14px | 42×42px circle-ish |
| Header icon | Semi-transparent white | Inherited | 12px | 38×38px |

- **Press state:** Scale 0.92–0.95, slight opacity reduction
- **Disabled:** Opacity 0.3, no pointer events

### Form Inputs
- Background: `--card` (white)
- Border: 1px solid `--border`
- Border-radius: 14px
- Padding: 11px
- Font-size: 14px, weight 600
- Focus: accent border + glow shadow (`--acc-glow`)
- Labels: 10px uppercase, muted color, 0.8px letter-spacing

### Shadows
| Level | Value |
|-------|-------|
| Soft | `0 1px 3px rgba(15,23,42,.04), 0 4px 12px rgba(15,23,42,.06)` |
| Medium | `0 4px 12px rgba(15,23,42,.06), 0 12px 28px rgba(15,23,42,.08)` |
| Large | `0 8px 24px rgba(15,23,42,.08), 0 24px 48px rgba(15,23,42,.1)` |

---

## 6. Animations & Motion

| Animation | Duration | Description |
|-----------|----------|-------------|
| Screen fade-in | 0.3s | Opacity 0→1 + translateY 10px→0, cubic-bezier ease |
| Button press | 0.15s | Scale to 0.92, slight opacity drop |
| PIN key tap | 0.2s | Scale pulse with accent color flash |
| PIN dot pop | 0.25s | Scale 1→1.3→1 when digit entered |
| PIN error shake | 0.5s | Horizontal shake ±12px |
| Critical pulse | 1.5s loop | Opacity fades on red stripe |
| Online dot pulse | 2s loop | Green dot opacity pulse |
| Install banner | 0.4s | Slide up from bottom with cubic-bezier |
| Overlay | instant | Fade with backdrop blur |

### Easing
- Standard transitions: `0.2s ease`
- Entrance animations: `cubic-bezier(.4,0,.2,1)`
- Bounce/spring: `cubic-bezier(.175,.885,.32,1.275)`

---

## 7. Icons

All icons are **inline SVG**, stroke-based (not filled), using `currentColor` for theming.
- Stroke width: 2–2.5px
- Line cap/join: round
- Size: 16–22px viewBox

**Icon set used:** Back arrow, Plus, Save/floppy, Trash, Camera, Gear/cog, Lock, Eye, Eye-off, User/person, Download, Checkmark, Chevron.

---

## 8. Visual Identity Summary

> **MedEvac looks like:** A clean, modern mobile medical app with a professional navy-blue header, white card-based content on a cool gray background, and bold green/yellow/red triage color coding. The typography is tight and dense (Inter font, heavy weights), optimized for quick scanning. The feel is iOS-native — frosted glass effects, smooth micro-animations, generous rounded corners (20px), and soft layered shadows. Everything is designed for fast, one-handed use in an emergency hospital environment.

**Key visual keywords for video generation:**
- Mobile phone mockup (iPhone-style, 430px width)
- RTL (Right-to-Left) text direction
- Navy blue gradient headers
- White cards on light gray background
- Green/Yellow/Red triage color system
- Inter font, heavy weights
- Rounded corners everywhere (20px cards, 14px buttons)
- Soft shadows, glass-morphism on overlays
- Clean, minimal, medical-professional aesthetic
- Arabic text labels
