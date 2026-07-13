# Changelog

All notable changes to Nexura Security will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.5] - 2026-07-13

### Fixed
- **Critical:** Fixed HTTP 500 error (Maximum execution time exceeded) during plugin activation by delaying the initial File Integrity Monitoring (FIM) and Google Safe Browsing scans by 1 hour.
- **Critical:** Fixed HTTP 500 error after plugin deactivation. The Web Application Firewall (WAF) `auto_prepend_file` directive is now correctly removed from `.htaccess` and `.user.ini` during deactivation.

### Changed
- Improved GitHub repository documentation and SEO metadata.
- Updated README.md with GitHub activity badges (Stars, Forks, Issues).
- Enhanced issue templates with structured labels and detailed fields.
- Added GitHub Security Advisory guidance to SECURITY.md.

### Added
- Full GPL-2.0 license text (replaces stub file).
- `FUNDING.yml` for GitHub Sponsors integration.
- `dependabot.yml` for automated dependency update monitoring.
- `ISSUE_TEMPLATE/config.yml` to guide users to the support forum.

---

## [1.0.4] - 2026-07-10

### Added
- Automated HTML security alert email when malware or threats are detected during a scan.
- Email is rate-limited to a maximum of 1 per 24 hours to prevent inbox flooding.
- Nexura Security branding logo added to alert email header.

### Changed
- Upgraded all alert notifications from plain text to fully styled HTML with CTA button.

### Fixed
- Minor stability improvements and code hardening.

---

## [1.0.3] - 2026-07-09

### Added
- Automated HTML security alert emails — when malware is detected, the site admin receives a beautifully branded email with a full threat summary and dashboard link.
- Security alert emails rate-limited to a maximum of 1 email per 24 hours.

### Changed
- Upgraded all alert notifications from plain text to fully styled HTML with Nexura Security branding.

### Fixed
- Minor stability improvements and code hardening.

---

## [1.0.2] - 2026-07-05

### Changed
- Stability improvements and performance optimizations.
- Updated scanner signature database.

### Fixed
- Improved compatibility with PHP 8.2.

---

## [1.0.1] - 2026-07-01

### Added — Initial Release
- Deep recursive malware scanner with micro-batching architecture.
- WordPress core file integrity monitoring (checksums from WordPress.org).
- Root directory integrity checker for suspicious file drops.
- Two-Factor Authentication (2FA) with TOTP support (Google Authenticator, Authy, etc.).
- Passwordless Magic Link login.
- Brute-force attack protection with configurable IP lockout.
- Pwned Password checking via HaveIBeenPwned API (k-Anonymity model).
- Anti-spam protection with Cloudflare Turnstile and Google reCAPTCHA v2/v3.
- Cloud-based Threat Intelligence sync (Nexura Threat Intel Cloud).
- Google Safe Browsing integration.
- One-click security hardening (file editor, PHP execution, XML-RPC, directory listing).
- Database security scanner (rogue admins, malicious content).
- Database backup tool (one-click before cleanup).
- Real-time upload scanning (auto-scan on media/plugin/theme upload).
- SSL & HTTPS health monitor.
- Fatal Error Auto-Heal (White Screen of Death protection via Drop-in pattern).
- Web Application Firewall (WAF) via `auto_prepend_file`.

---

[1.0.5]: https://github.com/nexurasecurity/nexura-security/releases/tag/v1.0.5
[1.0.4]: https://github.com/nexurasecurity/nexura-security/releases/tag/v1.0.4
[1.0.3]: https://github.com/nexurasecurity/nexura-security/releases/tag/v1.0.3
[1.0.2]: https://github.com/nexurasecurity/nexura-security/releases/tag/v1.0.2
[1.0.1]: https://github.com/nexurasecurity/nexura-security/releases/tag/v1.0.1
