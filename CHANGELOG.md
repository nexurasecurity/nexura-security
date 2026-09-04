# Changelog

All notable changes to Nexura Security will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.15] - 2026-09-04

### 🛠️ Critical Fixes & Stability
- **No More "Website Down" (HTTP 500):** Fixed a critical issue on CGI/FastCGI hosting environments (like Bluehost, HostGator, and SiteGround) where enabling the WAF caused server crashes. The firewall directive is now only applied when running natively as an Apache module.
- **Pro Server Lock Safety:** Applied the same Apache module detection safeguard to the Server Lock feature to ensure maximum compatibility.
- **Settings Toggle Fix:** Resolved a UI issue in Settings where the "Global Threat Intelligence" toggle switch was not functioning properly.

### 🛡️ Security Enhancements
- **Smart Auto-Recovery:** Introduced a new safety net. If a newly applied security rule written to `.htaccess` causes a server error, the plugin now automatically detects it via a background loopback check and restores the previous safe state within seconds!
- **Upgraded Comment Spam Blocker:** We've added 8 new domains (`shorturl.fm`, `t.ly`, `goo.su`, `qrco.de`, `bit.do`, `cutt.us`, `shorte.st`, `adf.ly`) actively used by spambots to our URL blocklist.

---

## [1.0.14] - 2026-09-03

### 🛡️ Enterprise WooCommerce Security & Protection
- **WooCommerce Security Module:** Complete overhaul providing granular protection against Checkout Abuse, Cart/Coupon spam, and Fake Registrations using Honeypots and advanced Rate Limiting. Blocks WooCommerce REST API scraping and account enumeration, while automatically whitelisting legitimate webhooks from Stripe, PayPal, and Mollie.

### 🔍 Advanced WordPress Malware Scanner
- **Deep Database Scanner:** The malware scanner now scans deep inside `wp_options`, `wp_postmeta`, `wp_usermeta`, and Custom Tables for hidden JavaScript injections, encoded PHP, SEO spam, and backdoor iframes.
- **Advanced Backdoor Detection:** Completely overhauled our malware signature engine! The new system is highly optimized, fully transparent, and now includes enhanced detection rules for the latest WordPress malware variants (including WP-VCD).

### ⚡ Performance & Site Maintenance
- **Database Optimization & Log Retention:** Added automatic WP-Cron log cleanup with customizable retention policies (7 days to 1 year) to prevent your WordPress database from ballooning in size.
- **Ultra-Fast Local Geo-Blocking:** Integrated the industry-standard MaxMind GeoLite2 database! Enjoy lightning-fast country detection natively on your server, acting as a robust fallback for sites not using Cloudflare.

### 🔐 Security Hardening & Access Control
- **Hardened Filesystem Operations:** Introduced a 3-layer security model for advanced filesystem operations (like `chattr`). Now strictly opt-in, properly capability checked, and fully audited.
- **Centralized Permission Engine:** Upgraded access controls across 30+ files to use a new centralized `Nexura_Security::can_manage_security()` method, making the WordPress security plugin more reliable and extensible.
- **Hardened Passwordless Logins:** Magic Link authentication is now even more secure with strict account-level rate limiting and ultra-secure session handling to prevent brute-force abuse.

---

## [1.0.11] - 2026-08-25

### 🚀 Major New Features
- **Vulnerability Scanner:** Added automated scanning for known vulnerabilities (CVEs) in installed plugins and themes.
- **Security Audit Logs:** Comprehensive tracking of user actions, login attempts, and security events with a dedicated UI.
- **Security Headers Manager:** Implement critical HTTP security headers (HSTS, X-Frame-Options, CSP, X-XSS-Protection) with one click.
- **Advanced DB Security & Cleanup:** New Safe Cleanup module to optimize the database, remove orphan data, and clear out malicious transients or spam.
- **Cron Job Auditor:** Monitor and audit WordPress scheduled tasks (Crons) to detect hidden malicious jobs or performance bottlenecks.
- **Security Score & Reporting:** Get a real-time Security Score based on your site's posture, with actionable hardening recommendations and downloadable reports.

### ⚡ Performance & Core Architecture
- **Removed Freemius SDK:** Completely decoupled from the Freemius SDK for a leaner, faster, and fully independent architecture.
- **Cloudflare D1 Integration:** Expanded Nexura Cloud Threat Intelligence with 90,000+ new zero-day and malware signatures via the Cloudflare D1 internal API. Total active signatures now exceed 100,000+.
- **Zero-Bloat Guarantee:** Removed the bulky local `Yara-Rules` folder to drastically reduce plugin download size. All signature scanning is now routed through the cloud-based API.

### 🛠️ Bug Fixes
- **Robust Loader:** Fixed a fatal error that occurred when specific plugin files were missing or manually deleted. Added `class_exists` and `file_exists` fallbacks in the plugin loader.

---

## [1.0.10] - 2026-08-05

### Security — Critical Hardening (Bulletproof Release)
- **WAF:** Added **Base64 and Hex payload decoding** to `nexura-waf.php`. The WAF now decodes encoded payloads before scanning, catching obfuscated malware that previously bypassed detection.
- **WAF:** Added dedicated **Wp2shell Zero-Day rule** (`CVE-2026-60137 / CVE-2026-63030`) to block the July 2026 WordPress core exploit chain.
- **WAF:** Increased decode passes from 3 to 4 for deeper recursive URL-decoding.
- **Input:** Sanitized all raw `$_POST` inputs in `nexura-rescue.php` using `htmlspecialchars` + `strip_tags`.
- **SQL:** Secured dynamic table names in `Plugin_Conflict_Cleaner.php` with `preg_replace('/[^a-zA-Z0-9_]/')`.
- **SQL:** Secured dynamic table names in `class-db-backup.php` with `preg_replace('/[^a-zA-Z0-9_]/')`.
- **SSL:** Fixed `CURLOPT_SSL_VERIFYPEER = false` in `nexura-rescue.php`. SSL certificate verification is now enforced (`true`) with `CURLOPT_SSL_VERIFYHOST = 2` to prevent Man-in-the-Middle (MITM) attacks.
- **Redirect:** Replaced `esc_url_raw` with `wp_validate_redirect()` in `class-two-factor-auth.php` to enforce same-site redirects and prevent Open Redirect vulnerabilities.
- **SQL:** Fixed `%%` escaping for `LIKE` clauses in `Media_Cleaner.php` to prevent `wpdb->prepare()` errors.

### Added
- **Ghost Admin Protection** (`class-ghost-admin-protection.php`): New module that detects unauthorized administrator accounts injected via SQL injection or zero-day exploits. Automatically demotes rogue admins to Subscriber and logs the event to the Live Attack Log. Runs a background scan every 12 hours.

### Changed
- Minimum stability guarantee: All known vulnerability classes are now patched (Security Score: 98/100).
- Updated documentation and SEO metadata across `readme.txt`, `README.md`, and `CHANGELOG.md`.

---

## [1.0.9] - 2026-07-21

### Fixed
- **SEO & Repository:** Resolved WordPress.org directory tag limit constraint.
- **SEO:** Optimized plugin short description to improve search visibility and user discovery.

---

## [1.0.8] - 2026-07-18

### Changed
- **Core:** Maintenance release for version synchronization and minor internal stability improvements.

---

## [1.0.7] - 2026-07-18

### Added
- **UI/UX:** Introduced an interactive admin bar notification system featuring contextual dropdown menus for streamlined security alerts.

---

## [1.0.6] - 2026-07-18

### Added
- **Engagement:** Integrated a post-publish marketing banner to improve user communication.

### Changed
- **UI/UX:** Redesigned the primary dashboard widget for better data visualization and improved aesthetic appeal.

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
