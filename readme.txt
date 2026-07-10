=== Nexura Security ===
Contributors: nexurasecurity
Tags: security, malware scanner, firewall, two factor authentication, brute force protection
Requires at least: 5.8
Tested up to: 7.0
Stable tag: 1.0.2
Requires PHP: 7.4
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

The most complete free WordPress security plugin. Malware scanner, firewall, 2FA, brute-force protection, file integrity monitoring, and more.

== Description ==

**Nexura Security** is a complete, all-in-one WordPress security plugin that protects your website from hackers, malware, and brute-force attacks — **completely free**.

Whether you run a personal blog, an online store, or a business website, Nexura Security gives you enterprise-level protection without slowing your site down.

= ⚡ Why Choose Nexura Security? =

Looking for a **lightweight, faster alternative** to Wordfence, Sucuri, or MalCare? Tired of heavy security plugins that slow down your site and bloat your database?

Nexura Security is different:

* **Zero Database Bloat** — Uses smart micro-batching so scans run quietly in the background without slowing down your server.
* **Easy to Use** — One-click setup. No technical knowledge required.
* **100% Free Core** — All essential security features are included at no cost.

== 🛡️ Free Features (Included with This Plugin) ==

**🔍 Deep Malware Scanner**
Automatically scans your entire WordPress installation — themes, plugins, uploads, and core files — for hidden backdoors, obfuscated PHP code, suspicious JavaScript, and known malware patterns. Clean infected files with a single click.

**📂 WordPress Core File Integrity Monitor**
Compares your WordPress core files against clean, official versions to detect any unauthorized changes. If a hacker modifies `wp-login.php`, `wp-config.php`, or any other core file, you will know instantly.

**📁 Root Directory Integrity Checker**
Detects suspicious and unknown files dropped directly into your WordPress root folder — a common technique used by attackers to plant backdoors and web shells.

**🔐 Two-Factor Authentication (2FA)**
Add an extra layer of protection to your admin login. Works with Google Authenticator, Authy, Microsoft Authenticator, or any TOTP-compatible app. Includes QR code setup.

**🔗 Passwordless Magic Link Login**
Allow trusted users to log in via a secure, time-limited link sent to their email — no password required.

**🚫 Brute-Force Attack Protection**
Automatically blocks IP addresses after too many failed login attempts. Configurable lockout duration and attempt limits.

**🔑 Pwned Password Checker**
When users set or change their passwords, the plugin securely checks against the HaveIBeenPwned database to make sure the password has not been exposed in a data breach. Uses k-Anonymity — your full password is never sent anywhere.

**🤖 Anti-Spam & Bot Protection**
Protects your comment forms, login pages, and registration pages from automated spam bots using Cloudflare Turnstile or Google reCAPTCHA integration.

**🌍 Cloud-Based Threat Intelligence**
Syncs with the Nexura Threat Intel Cloud to receive up-to-date malicious IP blocklists and attack signatures, keeping your firewall rules current.

**🛠️ Security Hardening (One-Click)**
Apply best-practice WordPress security settings with one click:

* Disable the built-in file editor (prevents hackers from editing your files from the dashboard)
* Block PHP execution in the uploads folder
* Disable directory listing
* Block XML-RPC (stops brute-force attacks via XML-RPC)

**🛠️ Extended WAF & Core Auto-Restore**
Uses an advanced `.htaccess` `auto_prepend_file` directive to load the Web Application Firewall *before* WordPress even boots. If a hacker deletes critical WordPress core files (like `wp-settings.php` or `wp-login.php`), this feature automatically downloads a fresh copy of WordPress from the official WordPress.org API in the background and instantly restores the missing files — keeping your site online without manual intervention.

**🚑 Fatal Error Auto-Heal**
Utilizes the official WordPress Drop-in pattern (`wp-content/fatal-error-handler.php`) to catch PHP fatal errors before they crash your entire site. If a newly installed plugin or theme causes a "White Screen of Death," Nexura automatically detects the faulty plugin, safely disables it, and reloads the page.

**🗄️ Database Security Scanner**
Scans your WordPress database for hidden administrator accounts and suspicious configurations that may have been injected by attackers.

**💾 Database Backup**
Create a quick backup of your database before performing any cleanup or changes — so you can always roll back.

**📊 Real-Time Upload Scanning**
Every file uploaded through WordPress (media, plugins, themes) is automatically scanned for malware before it reaches your server.

**🔍 Google Safe Browsing Check**
Verifies whether your website has been flagged by Google as containing malware or phishing content.

== 🌟 Pro Features (Upgrade to Unlock) ==

Want to go further? **Nexura Security Pro** adds powerful automation and advanced protection:

* **Web Application Firewall (WAF)** — Blocks SQLi/XSS/Bot attacks and loads before WordPress to stop threats at the lowest server level using `auto_prepend_file`.
* **Tokenizer-Based Smart Scanner** — Uses PHP's `token_get_all()` to detect zero-day backdoors that evade regex-based scanners.
* **Automated Malware Cleanup** — Automatically strips malware injections and restores your files without manual intervention.
* **WordPress Core Auto-Restore** — Downloads clean copies of modified core files directly from WordPress.org and replaces them using atomic (crash-safe) file writes.
* **File Quarantine** — Moves suspicious files to a secure, locked quarantine zone where they cannot execute.
* **Custom Login URL** — Hide `wp-login.php` and `wp-admin` behind a secret URL to stop 99% of automated brute-force bots.
* **HTTP Security Headers** — Add Content-Security-Policy, HSTS, X-Frame-Options, Permissions-Policy, and more with presets (Recommended, Strict, or Custom).
* **REST API Security** — Block user enumeration and restrict unauthenticated REST API access.
* **WooCommerce Security** — Anti-card-testing protection for checkout pages and account takeover prevention.
* **Vulnerability Audit** — Instantly detect outdated plugins, themes, and core versions with known vulnerabilities.
* **Database Optimizer** — Clean up post revisions, transients, orphaned metadata, and optimize database tables.
* **Storage Cleanup Scanner (Enterprise)** — Safely detect and remove unused images, PDFs, and orphan files from your uploads directory to save disk space and improve backup speed.
* **Plugin Conflict Cleaner** — Safely remove database leftovers from old or conflicting security plugins.
* **Security Trust Badge** — Display a "Protected by Nexura Security" seal on your website to build visitor trust.
* **📡 Active Monitoring** — Real-time visitor tracking dashboard with live stats, 4 interactive charts (Traffic Trend, Browser, Device, OS), auto-refreshing visitor table, and bot detection.
* **📌 Visitor Stats Shortcodes** — 5 beautiful shortcodes (`[nexura_visitors]`, `[nexura_stats]`, `[nexura_live]`, `[nexura_popular]`, `[nexura_page_views]`) to display visitor stats anywhere on your site with premium glassmorphism design and Nexura branding.
* **Scheduled Automatic Scans** — Set scans to run every 2 hours, daily, weekly, or monthly — fully automatic.
* **Advanced Audit Logs** — Detailed logs of every security event, login, file change, and admin action.
* **Priority Support** — Get direct help from our security team.

[Upgrade to Pro →](https://nexurasecurity.com)

= 🔗 Third-Party Services & External API Connections =

To provide comprehensive security, Nexura Security connects to several trusted third-party services. **No connections are made automatically — each feature must be enabled by you in the plugin settings.** Here is a complete list of external services this plugin may connect to:

**1. Cloudflare Turnstile**
*Used for:* Human verification (CAPTCHA) on login, registration, and comment forms to block spam bots.
*Data sent:* Visitor's browser fingerprint and interaction data (processed by Cloudflare, not stored by us).
*When:* Only when you enable Turnstile integration in the Anti-Spam settings.
*Service links:* [Cloudflare Privacy Policy](https://www.cloudflare.com/privacypolicy/) | [Cloudflare Terms](https://www.cloudflare.com/website-terms/)

**2. Google reCAPTCHA**
*Used for:* Alternative CAPTCHA option for blocking automated bots on login and registration pages.
*Data sent:* Visitor's browser data and interaction signals (processed by Google).
*When:* Only when you enable Google reCAPTCHA in the Anti-Spam settings.
*Service links:* [Google Privacy Policy](https://policies.google.com/privacy) | [Google Terms](https://policies.google.com/terms)

**3. HaveIBeenPwned API (Pwned Passwords)**
*Used for:* Checking whether a user's password has appeared in known data breaches.
*Data sent:* Only the first 5 characters of a SHA-1 hash of the password (k-Anonymity model). Your actual password is NEVER sent.
*When:* Only when the Pwned Passwords feature is enabled and a user sets or changes their password.
*Service links:* [HaveIBeenPwned Privacy Policy](https://haveibeenpwned.com/Privacy) | [API Terms](https://haveibeenpwned.com/API/v3#Terms)

**4. Google Safe Browsing API**
*Used for:* Checking whether your website URL has been flagged by Google as containing malware or phishing.
*Data sent:* Your website's URL.
*When:* Only when you manually trigger a Safe Browsing check from the dashboard.
*Service links:* [Google Privacy Policy](https://policies.google.com/privacy) | [Safe Browsing Terms](https://developers.google.com/safe-browsing/terms)

**5. VirusTotal API**
*Used for:* Scanning file hashes against 70+ antivirus engines to detect malware.
*Data sent:* Only the SHA-256 cryptographic hash of the file. The actual file is NEVER uploaded.
*When:* Only during a manual malware scan when unknown files are detected.
*Service links:* [VirusTotal Privacy Policy](https://docs.virustotal.com/docs/privacy-policy) | [VirusTotal Terms](https://docs.virustotal.com/docs/terms-of-service)

**6. Nexura Threat Intel Cloud (sgs-db-worker.sentinel-guard-security.workers.dev)**
*Used for:* Syncing the latest WAF rules, malicious IP blocklists, and malware detection signatures with your site. Also used for anonymous threat reporting to help protect the community.
*Data sent:* Blocked attacker IP addresses and blocked payload patterns (anonymized). No personal user data is ever collected.
*When:* When the Global Threat Intelligence feature is enabled in settings.
*Service links:* [Nexura Privacy Policy](https://nexurasecurity.com/privacy-policy.html) | [Nexura Terms](https://nexurasecurity.com/terms-conditions.html)

**7. WordPress.org API**
*Used for:* Downloading official WordPress core file checksums for integrity scans, and downloading the latest WordPress core ZIP file for the Core Auto-Restore WAF feature.
*Data sent:* Your WordPress version number.
*When:* During core file integrity checks, or automatically in the background if Core Auto-Restore is enabled.
*Service links:* [WordPress Privacy Policy](https://wordpress.org/about/privacy/)

**8. FlagCDN (flagpedia.net)**
*Used for:* Displaying country flag icons next to IP addresses in the Blocked IPs table for visual identification.
*Data sent:* Country code (derived from IP). No personal data is sent.
*When:* Only when viewing the Blocked IPs page in the admin dashboard.
*Service links:* [FlagCDN Privacy Policy](https://flagpedia.net/privacy-policy) | [FlagCDN Terms](https://flagpedia.net/terms)

**9. Freemius SDK**
*Used for:* Plugin licensing, activation, opt-in analytics, and in-dashboard upgrade flow for the Pro version.
*Data sent:* Site URL, WordPress version, plugin version, admin email (only if user opts in during activation).
*When:* On plugin activation (opt-in dialog) and when checking license status.
*Service links:* [Freemius Privacy Policy](https://freemius.com/privacy/) | [Freemius Terms](https://freemius.com/terms/)

= 📜 Privacy Policy & Terms of Use =

We believe in complete transparency about how your data is handled.

**What We Collect:**
Nexura Security does NOT collect any personal data from your website visitors. We do not track your users, we do not sell any data, and we do not place any tracking cookies.

**What We May Report:**
When the Web Application Firewall blocks a malicious attack, the attacker's IP address and the type of blocked payload may be anonymously reported to the Nexura Threat Intel Cloud. This helps protect other WordPress websites using Nexura Security. **You can disable this feature at any time** in the plugin settings under "Global Threat Intelligence."

**Your Data, Your Control:**
All scan results, logs, and settings are stored locally in your own WordPress database. Nothing is sent to any external server unless you explicitly enable a cloud feature.

**Compliance:**
Our data handling practices comply with GDPR (EU), CCPA (California), and other major international privacy regulations. By installing and activating this plugin, you agree to the usage of the third-party services listed above when you choose to enable them.

**Full Policy:** [Privacy Policy](https://nexurasecurity.com/privacy-policy.html) | [Terms & Conditions](https://nexurasecurity.com/terms-conditions.html)

== Installation ==

1. Go to **Plugins → Add New** in your WordPress dashboard.
2. Search for **"Nexura Security"**.
3. Click **Install Now**, then click **Activate**.
4. Navigate to the **Nexura Security** menu in your sidebar to run your first security scan.

Or, if installing manually:

1. Download the plugin zip file.
2. Upload it via **Plugins → Add New → Upload Plugin**.
3. Activate the plugin.

== Frequently Asked Questions ==

= Is Nexura Security really free? =
Yes! All the core security features — malware scanning, file integrity monitoring, 2FA, brute-force protection, hardening, and more — are completely free. The Pro version adds advanced automation features for users who need even more protection.

= Can it clean a hacked WordPress site? =
Yes. The built-in malware scanner detects backdoors, obfuscated code, and known malware patterns. You can remove detected threats with a single click. For automated cleanup and core file restoration, upgrade to Pro.

= Will it slow down my website? =
No. Nexura Security uses a micro-batching architecture that runs scans quietly in the background. Your website visitors will not experience any slowdown.

= Does it work with WooCommerce? =
Yes. The free version protects WooCommerce sites just like any WordPress site. The Pro version adds WooCommerce-specific features like checkout fraud protection and account takeover prevention.

= Does it send my data to external servers? =
Only when you explicitly enable a cloud feature (like Threat Intelligence or Pwned Passwords). All connections are documented in the Third-Party Services section above. By default, everything stays on your own server.

= Is it compatible with other security plugins? =
Nexura Security is designed to be a complete standalone solution. Running multiple security plugins simultaneously is not recommended as it can cause conflicts. If you are switching from another plugin, Nexura Pro includes a Plugin Conflict Cleaner to safely remove leftover data.

= What PHP version do I need? =
PHP 7.4 or higher is required. PHP 8.0+ is recommended for optimal performance.

== Screenshots ==

1. **Security Dashboard** — Your complete security overview at a glance showing scan status, threat summary, and quick actions.
2. **Malware Scanner** — Deep heuristic scanner in action, detecting suspicious files across your entire WordPress installation.
3. **Security Hardening** — One-click hardening options to lock down your WordPress site in seconds.
4. **Two-Factor Authentication** — Easy QR code setup for Google Authenticator and other TOTP apps.
5. **Login Protection** — Brute-force protection settings with configurable lockout rules.

== Changelog ==

= 1.0.1 =
* Initial release.
* Deep recursive malware scanner with micro-batching architecture.
* WordPress core file integrity monitoring.
* Root directory integrity checker.
* Two-Factor Authentication (2FA) with TOTP support.
* Passwordless Magic Link login.
* Brute-force attack protection with IP lockout.
* Pwned Password checking via HaveIBeenPwned API.
* Anti-spam protection with Cloudflare Turnstile and Google reCAPTCHA.
* Cloud-based Threat Intelligence sync.
* Google Safe Browsing integration.
* One-click security hardening (file editor, directory listing, PHP execution, XML-RPC).
* Database security scanner for hidden admin accounts.
* Database backup tool.
* Real-time upload scanning.
* Session management.

== Upgrade Notice ==
= 1.0.1 =
First stable release. Install now to protect your WordPress website with enterprise-level security features — completely free.


