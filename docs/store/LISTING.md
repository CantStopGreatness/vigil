# Chrome Web Store listing

Everything the Chrome Web Store developer dashboard asks for, ready to paste. Images are in this folder.

## Package

```bash
cd extension && zip -r ../vigil-extension.zip . -x '.*' && cd ..
```

Upload `vigil-extension.zip`. Bump `version` in `extension/manifest.json` for every update you publish.

## Store listing tab

**Name** (from the manifest): Vigil: Website Security Grade

**Summary** (from the manifest, 132 characters max):
Grade the site you're on in seconds: security headers, TLS, cookies, known CVEs and email spoofing, with a fix for every finding.

**Category:** Developer Tools
**Language:** English

**Description:**

```
Click the Vigil eye on any website and get an A–F security grade in seconds, with a plain-English fix for every problem it finds.

WHAT IT CHECKS
• Security headers: HSTS, Content-Security-Policy, clickjacking protection, MIME sniffing, Referrer-Policy and more
• HTTPS and TLS: plain-HTTP pages, missing redirects, invalid or expiring certificates, obsolete TLS 1.0/1.1
• Cookies: missing Secure, HttpOnly and SameSite flags
• Known vulnerabilities: software versions the site reveals (nginx, Apache, PHP, OpenSSL, WordPress, Drupal…) matched against the National Vulnerability Database
• Information disclosure: version banners in headers and page markup
• Email spoofing: missing or weak SPF and DMARC records

WHAT YOU GET
• A 0–100 score and A–F grade
• Every finding ranked by severity, with what's wrong, the evidence, and exactly how to fix it
• A full online report and a ready-to-share PDF

PASSIVE AND PRIVATE BY DESIGN
• Vigil only reads what the site already shows every visitor. It never probes for hidden files or sends attack payloads. For a deeper audit of a site you own, the extension links to the full scanner.
• It does nothing until you click the icon, and never runs in the background.
• Only the site's address (like https://example.com) is sent, never the page path, its content, your cookies or your browsing history.
• No account, no ads, no tracking.

Vigil is open source: https://github.com/CantStopGreatness/vigil
```

**Graphic assets:**
- Store icon (128×128): `extension/icons/128.png`
- Screenshot (1280×800): `docs/store/screenshot-1280x800.png`
- Small promo tile (440×280): `docs/store/promo-tile-440x280.png`

**Additional fields:**
- Official URL / homepage: https://vigil-psi-liard.vercel.app
- Support URL: https://github.com/CantStopGreatness/vigil/issues

## Privacy practices tab

**Single purpose:**
Vigil grades the security of the website open in the current tab and explains how to fix what it finds.

**Permission justifications:**
- `activeTab`: Reads the address of the current tab only when the user clicks the Vigil icon, so that site can be graded. The extension never reads tabs in the background.
- Host permission `https://vigil-psi-liard.vercel.app/*`: Sends the site's address to Vigil's own scanning API and receives the security report. This is the only host the extension contacts.

**Remote code:** No, I am not using remote code. (The extension only downloads JSON scan results; all of its code ships in the package.)

**Data usage:** tick **Web history**.
The extension sends the origin (e.g. `https://example.com`) of the page the user chose to grade. That's a single site the user picked, not their history, but Google's definition of web history covers visited sites, so declaring it is the safe and honest choice. Leave every other category unticked: it collects no personal, financial, health, authentication, communication, location or activity data, and no page content.

**Certifications:** tick all three:
- I do not sell or transfer user data to third parties, outside of the approved use cases
- I do not use or transfer user data for purposes that are unrelated to my item's single purpose
- I do not use or transfer user data to determine creditworthiness or for lending purposes

**Privacy policy URL:** https://github.com/CantStopGreatness/vigil/blob/main/PRIVACY.md

## Before you submit

- Merge the branch with this file first, so the privacy policy URL above resolves.
- If you move Vigil to a custom domain, update `API` in `extension/popup.js`, `host_permissions` in `manifest.json`, and the URLs here and in `PRIVACY.md`.
