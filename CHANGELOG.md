# Changelog

All notable changes to MedEvac will be documented in this file.

## [1.1.0] - 2026-03

### Added
- OCR patient import via Anthropic Claude AI
- AES-GCM encryption for local storage (replacing legacy XOR)
- PWA install walkthrough for iOS Safari
- Offline operation queue with automatic sync
- Privacy blur screen on app background
- Audit trail logging for all security-relevant actions
- Bilingual privacy policy and support pages

### Changed
- PIN verification moved to Cloud Functions (server-side PBKDF2)
- Civil ID masking enabled by default
- Service worker updated to stale-while-revalidate for HTML

### Security
- Server-side rate limiting for PIN attempts
- Content Security Policy header
- Firebase database rules with strict validation
- Input length limits enforced at database level

## [1.0.0] - 2026-02

### Added
- Initial release
- Patient registry with triage classification
- Unit-based access with PIN protection
- Firebase Realtime Database backend
- PWA with offline support
- iOS native wrapper (WKWebView)
- Android TWA wrapper
- PNG backup export
