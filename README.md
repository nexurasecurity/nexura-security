# Nexura Security

<div align="center">
  <a href="https://wordpress.org/plugins/nexura-security/"><img src="https://img.shields.io/badge/WordPress.org-Download%20Free-blue.svg?style=for-the-badge&logo=wordpress" alt="Download on WordPress.org"></a>
  <br><br>
  <img src="https://img.shields.io/badge/Requires_WP-5.8+-blue.svg?style=for-the-badge" alt="Requires WP">
  <img src="https://img.shields.io/badge/Requires_PHP-7.4+-blue.svg?style=for-the-badge" alt="Requires PHP">
  <img src="https://img.shields.io/badge/Tested_up_to-7.0.1-green.svg?style=for-the-badge" alt="Tested WP">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPLv2-blue.svg?style=for-the-badge" alt="License"></a>
  <br>
  <a href="https://github.com/nexurasecurity/nexura-security/actions/workflows/ci.yml"><img src="https://github.com/nexurasecurity/nexura-security/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/github/stars/nexurasecurity/nexura-security?style=social" alt="Stars">
  <img src="https://img.shields.io/github/forks/nexurasecurity/nexura-security?style=social" alt="Forks">
  <img src="https://img.shields.io/github/issues/nexurasecurity/nexura-security" alt="Issues">
</div>

> **The most complete free WordPress security plugin.** Malware scanner, firewall, 2FA, brute-force protection, file integrity monitoring, and more.

**Nexura Security** is a complete, all-in-one WordPress security plugin that protects your website from hackers, malware, and brute-force attacks — **completely free**.

Whether you run a personal blog, an online store, or a business website, Nexura Security gives you enterprise-level protection without slowing your site down.

🔗 **[Download Free on WordPress.org](https://wordpress.org/plugins/nexura-security/)** | 🌐 **[nexurasecurity.com](https://nexurasecurity.com)** | 📋 **[Changelog](CHANGELOG.md)**

## ⚡ Why Choose Nexura Security?

Looking for a **lightweight, faster alternative** to Wordfence, Sucuri, or MalCare? Tired of heavy security plugins that slow down your site and bloat your database?

* **Zero Database Bloat** — Uses smart micro-batching so scans run quietly in the background without slowing down your server.
* **Easy to Use** — One-click setup. No technical knowledge required.
* **100% Free Core** — All essential security features are included at no cost.

## 🛡️ Free Features (Included with This Plugin)

* **🔍 Deep Malware Scanner:** Automatically scans your entire WordPress installation — themes, plugins, uploads, and core files — for hidden backdoors, obfuscated PHP code, suspicious JavaScript, and known malware patterns.
* **📂 File Integrity Monitor:** Compares your WordPress core files against clean, official versions to detect any unauthorized changes, and checks the root directory for suspicious drops.
* **🔐 Advanced Login Protection:** Includes Two-Factor Authentication (2FA) with TOTP support and passwordless magic link logins.
* **🚫 Brute-Force & Bot Protection:** Automatically blocks IP addresses after failed login attempts, checks for Pwned Passwords, and stops spam bots with Cloudflare Turnstile or Google reCAPTCHA.
* **🌍 Cloud-Based Threat Intelligence:** Syncs with the Nexura Threat Intel Cloud to receive up-to-date malicious IP blocklists and attack signatures.
* **🛠️ Security Hardening (One-Click):** Disable the built-in file editor, block PHP execution in the uploads folder, disable directory listing, and block XML-RPC.
* **🚑 Extended WAF & Auto-Heal:** Advanced `.htaccess` WAF, Core Auto-Restore, and Fatal Error Auto-Heal features keep your site online and resilient against crashes or core file deletions.
* **🗄️ Database & Upload Scanning:** Scans for hidden administrator accounts and automatically scans uploads for malware before they reach the server.
* **🔍 Google Safe Browsing Check:** Verifies whether your website has been flagged for malware or phishing.

## 🌟 Pro Features (Upgrade to Unlock)

Want to go further? **Nexura Security Pro** adds powerful automation and advanced protection:

* **Web Application Firewall (WAF)** — Blocks SQLi/XSS/Bot attacks before WordPress even boots.
* **Automated Malware Cleanup & Core Auto-Restore** — Automatically strips malware injections and replaces modified core files with clean copies from WordPress.org.
* **Custom Login URL & File Quarantine** — Hide your login page behind a secret URL and securely quarantine suspicious files.
* **HTTP Security Headers & REST API Security**
* **WooCommerce Security** — Anti-card-testing protection and account takeover prevention.
* **Vulnerability Audit & Database Optimizer** — Detect outdated plugins/themes and optimize database tables.
* **📡 Active Monitoring & Visitor Stats** — Real-time visitor tracking dashboard and beautiful glassmorphism shortcodes for visitor stats.
* **Scheduled Automatic Scans & Advanced Audit Logs**

[**Upgrade to Nexura Security Pro →**](https://nexurasecurity.com)

## 🚀 Installation

### ✅ Automatic (Recommended)
1. Go to **Plugins → Add New** in your WordPress dashboard.
2. Search for **"Nexura Security"**.
3. Click **Install Now**, then click **Activate**.
4. Navigate to the **Nexura Security** menu in your sidebar to run your first security scan.

👉 **[Install directly from WordPress.org →](https://wordpress.org/plugins/nexura-security/)**

### 📦 Manual Installation
1. Download the plugin zip file from [WordPress.org](https://wordpress.org/plugins/nexura-security/).
2. Upload it via **Plugins → Add New → Upload Plugin**.
3. Activate the plugin.

## 🔗 Third-Party Services & Privacy

To provide comprehensive security, Nexura Security connects to several trusted third-party services (e.g., Cloudflare, HaveIBeenPwned, VirusTotal, WordPress.org API, and the Nexura Threat Intel Cloud). **No connections are made automatically — each feature must be enabled by you in the plugin settings.**

We believe in complete transparency about how your data is handled:
* Nexura Security does **NOT** collect any personal data from your website visitors.
* All scan results, logs, and settings are stored locally in your own WordPress database.
* Our data handling practices comply with GDPR, CCPA, and major international privacy regulations.

For full details, please review our [Privacy Policy](https://nexurasecurity.com/privacy-policy.html) and [Terms & Conditions](https://nexurasecurity.com/terms-conditions.html).

---
*Developed by the [Nexura Security Team](https://nexurasecurity.com)*

## License

Nexura Security is released under the [GPL v2 or later](LICENSE) license.
This software is provided "as is", without warranty of any kind.
