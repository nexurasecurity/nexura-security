# Changelog

All notable changes to Nexura Security will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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