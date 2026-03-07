# MedEvac

Secure patient registry system for Mubarak Al-Kabeer Hospital, Kuwait. Manages patient triage data across hospital units with PIN-based access control, offline support, and OCR-powered data import.

## Platforms

- **Web (PWA)** - Progressive Web App hosted on Firebase Hosting
- **iOS** - Native WKWebView wrapper with offline fallback
- **Android** - Trusted Web Activity (TWA) wrapper

## Features

- **Unit-based patient management** - 5 units (A-E), each with Male/Female wards
- **Triage classification** - 4-level severity coding (Green, Yellow, Red, Critical)
- **PIN-protected access** - Server-side PBKDF2 PIN verification per unit
- **Offline-first** - Full CRUD operations offline with automatic sync on reconnect
- **OCR import** - AI-powered patient list extraction from photos (Anthropic Claude)
- **Privacy controls** - Civil ID masking, privacy blur on background, auto-lock timeout
- **Audit logging** - All security-relevant actions logged
- **Data export** - PNG backup export of patient lists
- **PWA install** - Guided install flow for iOS Safari and Android Chrome
- **Bilingual** - Arabic (primary) and English support pages

## Architecture

```
MAK_Registry/          # Web application (PWA)
  index.html           # Single-page app with inline CSS
  boot.js              # Global error handler
  app.js               # Application logic (state, rendering, Firebase)
  sw.js                # Service worker for offline caching
  functions/           # Firebase Cloud Functions (PIN verification)
    index.js           # verifyPin, setPin, hasPins
  firebase.json        # Hosting, functions, database config
  database.rules.json  # Firebase Realtime Database security rules
  privacy.html         # Privacy policy (AR/EN)
  support.html         # Support & FAQ (AR/EN)
  manifest.json        # PWA manifest

ios/MedEvac/           # iOS native wrapper
  project.yml          # XcodeGen project definition
  MedEvac/
    AppDelegate.swift   # App entry point
    ViewController.swift # WKWebView with domain allowlist
    Info.plist          # iOS configuration

.github/workflows/     # CI/CD
  deploy-web.yml       # Firebase Hosting deploy
  build-ios.yml        # iOS build & TestFlight upload
  build-apk.yml        # Android TWA build

codemagic.yaml         # Codemagic CI for production iOS/Android builds
```

## Tech Stack

- **Frontend:** Vanilla JavaScript (ES modules), CSS custom properties
- **Backend:** Firebase Realtime Database, Firebase Cloud Functions (Node.js 22)
- **Auth:** Firebase Anonymous Auth + server-side PIN verification
- **Hosting:** Firebase Hosting
- **Encryption:** AES-GCM (local storage), PBKDF2 (PIN hashing), TLS 1.2+ (transport)
- **AI:** Anthropic Claude API (OCR feature)

## Setup

### Prerequisites
- Firebase CLI (`npm install -g firebase-tools`)
- Firebase project with Realtime Database and Authentication enabled

### Local Development
```bash
cd MAK_Registry
firebase serve --only hosting
```

### Deploy Cloud Functions
```bash
cd MAK_Registry
firebase deploy --only functions
```

### Deploy Web
```bash
cd MAK_Registry
firebase deploy --only hosting
```

### iOS Build
```bash
cd ios/MedEvac
brew install xcodegen
xcodegen generate
xcodebuild build -project MedEvac.xcodeproj -scheme MedEvac -sdk iphonesimulator
```

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

MIT - See [LICENSE](LICENSE)
