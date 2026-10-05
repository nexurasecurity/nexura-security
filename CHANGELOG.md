# Changelog

All notable changes to Nexura Security will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.21] - 2026-10-05

### Major Feature & Enhancements
- **Major Feature (Free):** Added Reinfection Guard & Root Cause Analyzer to detect why WordPress malware keeps returning after cleanup. Scans hidden MU-plugins, rogue drop-ins, unauthorized uploads PHP scripts, database persistence, and configuration tampering.
- **Feature:** Added dynamic PHP Reflection and Active Plugin Registry analysis for WP-Cron persistence checks, providing 100% false-positive free compatibility across 60,000+ third-party WordPress plugins.
- **Enhancement:** Added responsive dark cybersecurity dashboard for Reinfection Guard with 10-item pagination, instant search filtering, and interactive Cytoscape attack vector map.
- **Enhancement:** Added shared hosting safeguards and timeout protection for deep uploads directory scanning.
- **Enhancement:** Integrated Freemius SDK licensing directly with Reinfection Guard evidence access controls.

---

## [1.0.20] - 2026-09-28

### Security Hardening, Anti-Email-Storm & Bug Fixes
- **Critical Fix / Security Hardening:** Implemented Anti-Email-Storm Protection and Smart Rate Limiting in `Alert_System` to prevent servers from exhausting 100% hourly email quotas and getting blocked by hosting providers during botnet and brute-force attacks.
- **Feature:** Added configurable Hourly Email Rate Limit (default 5 emails/hour) with automated transient digest queue buffering.
- **Enhancement:** Added Brute-Force Alert Smart Policy with 15-minute cooldown, filtering out random botnet dictionary scans while preserving instant alerts for attacks targeting actual administrator accounts.
- **Bug Fix:** Fixed Visitor Tracker anomaly speed detection to apply a 1-hour cooldown transient and strict severity gating, preventing rapid email loops on fast browsing or web crawlers.
- **Bug Fix:** Added 24-hour source deduplication to Real-Time Scanner option hooks to prevent recurring alert emails on dynamic option updates.
- **Bug Fix:** Prevented duplicate alert emails on scan completion by dispatching webhooks instead of double emailing.
- **Bug Fix:** Protected Auto-Heal Drop-in crash notifications and Scheduled Scan reports with hard cooldown limits to eliminate email loops during site recovery.

---

## [1.0.19] - 2026-09-15

### Security Hardening, Enhancements & Bug Fixes
- **Security:** Added 2026 modern JS malware signatures to detect obfuscated arrays (Balada Injector, Sign1) and dynamic script injections (ClearFake).
- **Security:** Expanded PHP backdoor signatures to block modern WP action hook droppers, variable function evasions, and known webshells (WSO, B374k).
- **Enhancement:** Added a "Clean All Logs" button to the IP Intelligence page, complete with a custom modal, to allow users to easily clear local or staging brute force logs.
- **Bug Fix:** Fixed a UI glitch in the loading button icon by switching from Dashicons to the plugin's native spinner.
- **Bug Fix:** Resolved a false-positive issue in the Plugin Conflict Cleaner where WooCommerce's Jetpack dependencies caused continuous false alerts.
- **Bug Fix:** Fixed a bug in the File Snapshots viewer where the PRO verification logic incorrectly hid snapshots for users with an active lifetime license.
- **Bug Fix:** Resolved a critical bug where malware scans would crash at 96% with a 500 error if the server's `mail()` function was disabled or misconfigured.

---

## [1.0.18] - 2026-09-10

### Security Hardening, Fixes & Enhancements
- **Security Hardening:** Upgraded security-sensitive MD5 hashes to SHA-256 (CAPTCHA cookies and core file restorer) to prevent cryptographic collisions.
- **Security Hardening:** Fixed XML-RPC payload inspection to decode HTML/XML entities, catching obfuscated attack strings.
- **Security Hardening:** Switched Remember Device cookie to use `SameSite=Strict` and constant-time `hash_equals()` comparison.
- **Bug Fix:** Removed infinite redirect loop caused by conflicting `wp_login` actions with third-party separate-prompt 2FA.
- **Bug Fix:** Prevented fatal errors on deleted users during 2FA login checks.
- **Bug Fix:** Handled object cache compatibility by switching scan caching to the WordPress Transient API.
- **Bug Fix:** Removed deprecated `FILTER_SANITIZE_URL` usage for WAF log tracking.
- **Enhancement:** Added a visual warning banner when 0 recovery codes are remaining for Two-Factor Authentication.
- **Enhancement:** Improved multiple hardcoded strings to be properly translatable (i18n) and corrected escaping (`esc_js`, `esc_html__`).
- **Code Health:** Verified that Nexura Security is not affected by the deprecated `WP_Http_Curl` class, as the core does not use it.

---

## [1.0.17] - 2026-09-07

### Professional Report & Malware Remediation
- **New Feature:** Redesigned Security Reports layout featuring an Executive Summary, visual metric blocks, and actionable remediation advice.
- **New Feature:** Introduced Malware Scanner File Whitelisting to safely exclude known benign files from subsequent scans.
- **Enhancement:** Activated Premium features by default for a streamlined deployment experience.
- **Bug Fix:** Resolved a path validation error that prevented secure downloading of .sql.gz database backups.
- **Bug Fix:** Addressed a restriction issue preventing wp-config.php from loading in the Malware Scanner Editor during remediation.
- **Bug Fix:** Optimized malware cleanup routines to strip residual, empty <script> tags after payload removal.
- **Bug Fix:** Refined PHP payload extraction to prevent syntax errors caused by consecutive PHP opening tags.

---
## [1.0.16] - 2026-09-05

### WAF Production Hardening & False-Positive Fixes
- **Security:** Removed early-bootstrap cookie fallback for WAF admin exemptions to prevent forged cookie bypass.
- **Security:** Removed X-Real-IP private IP fallback; now strictly requires explicit `trusted_proxies` configuration.
- **Security:** Redacted WAF block reasons from JSON and HTML responses to prevent attacker information leakage.
- **Security:** Implemented atomic temp-file + rename operations for strikes.json and banned_ips.json to prevent race conditions.
- **Security:** Added explicit Cloudflare IP validation before trusting CF-IPCountry for Geo-blocking.
- **WAF Tuning:** Tightened SQLi Boolean rule to reduce false positives on REST API and WooCommerce endpoints.
- **WAF Tuning:** Removed legitimate uptime monitors (curl, python-requests) from malicious bot list and added known scanners (nuclei, nikto, sqlmap).
- **WAF Tuning:** Added score floor rules (Tier 60/80) to ensure single-payload attacks (XSS, Path Traversal, Exec) bypass context discounts.
- **Bug Fix:** Fixed infinite sliding window bug in APCu rate limiter; now uses a true fixed-window pattern.
- **Bug Fix:** APCu banned IP cache now explicitly validates 30-day expiry to prevent stale bans.
- **Enhancement:** Added fail-open error logging for WAF exceptions to aid diagnostics without crashing the site.

---

## [1.0.15] - 2026-09-04

### Critical Fixes & Stability
- **No More "Website Down" (HTTP 500):** Fixed a critical issue on CGI/FastCGI hosting environments (like Bluehost, HostGator, and SiteGround) where enabling the WAF caused server crashes. The firewall directive is now only applied when running natively as an Apache module.
- **Pro Server Lock Safety:** Applied the same Apache module detection safeguard to the Server Lock feature to ensure maximum compatibility.
- **Settings Toggle Fix:** Resolved a UI issue in Settings where the "Global Threat Intelligence" toggle switch was not functioning properly.

### Security Enhancements
- **Smart Auto-Recovery:** Introduced a new safety net. If a newly applied security rule written to `.htaccess` causes a server error, the plugin now automatically detects it via a background loopback check and restores the previous safe state within seconds!
- **Upgraded Comment Spam Blocker:** We've added 8 new domains (`shorturl.fm`, `t.ly`, `goo.su`, `qrco.de`, `bit.do`, `cutt.us`, `shorte.st`, `adf.ly`) actively used by spambots to our URL blocklist.

---

## [1.0.14] - 2026-09-03

### Enterprise WooCommerce Security & Protection
- **WooCommerce Security Module:** Complete overhaul providing granular protection against Checkout Abuse, Cart/Coupon spam, and Fake Registrations using Honeypots and advanced Rate Limiting. Blocks WooCommerce REST API scraping and account enumeration, while automatically whitelisting legitimate webhooks from Stripe, PayPal, and Mollie.

### Advanced WordPress Malware Scanner
- **Deep Database Scanner:** The malware scanner now scans deep inside `wp_options`, `wp_postmeta`, `wp_usermeta`, and Custom Tables for hidden JavaScript injections, encoded PHP, SEO spam, and backdoor iframes.
- **Advanced Backdoor Detection:** Completely overhauled our malware signature engine! The new system is highly optimized, fully transparent, and now includes enhanced detection rules for the latest WordPress malware variants (including WP-VCD).

### Performance & Site Maintenance
- **Database Optimization & Log Retention:** Added automatic WP-Cron log cleanup with customizable retention policies (7 days to 1 year) to prevent your WordPress database from ballooning in size.
- **Ultra-Fast Local Geo-Blocking:** Integrated the industry-standard MaxMind GeoLite2 database! Enjoy lightning-fast country detection natively on your server, acting as a robust fallback for sites not using Cloudflare.

### Security Hardening & Access Control
- **Hardened Filesystem Operations:** Introduced a 3-layer security model for advanced filesystem operations (like `chattr`). Now strictly opt-in, properly capability checked, and fully audited.
- **Centralized Permission Engine:** Upgraded access controls across 30+ files to use a new centralized `Nexura_Security::can_manage_security()` method, making the WordPress security plugin more reliable and extensible.
- **Hardened Passwordless Logins:** Magic Link authentication is now even more secure with strict account-level rate limiting and ultra-secure session handling to prevent brute-force abuse.

---

## [1.0.11] - 2026-08-25

### Major New Features
- **Vulnerability Scanner:** Added automated scanning for known vulnerabilities (CVEs) in installed plugins and themes.
- **Security Audit Logs:** Comprehensive tracking of user actions, login attempts, and security events with a dedicated UI.
- **Security Headers Manager:** Implement critical HTTP security headers (HSTS, X-Frame-Options, CSP, X-XSS-Protection) with one click.
- **Advanced DB Security & Cleanup:** New Safe Cleanup module to optimize the database, remove orphan data, and clear out malicious transients or spam.
- **Cron Job Auditor:** Monitor and audit WordPress scheduled tasks (Crons) to detect hidden malicious jobs or performance bottlenecks.
