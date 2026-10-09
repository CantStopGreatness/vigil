# Privacy Policy

_Last updated: 9 October 2026_

This policy covers the **Vigil Chrome extension** and the **Vigil website** ([vigil-psi-liard.vercel.app](https://vigil-psi-liard.vercel.app)). Vigil is an open-source website security scanner; all of its code is public at [github.com/CantStopGreatness/vigil](https://github.com/CantStopGreatness/vigil).

## The short version

- The extension does nothing until you click its icon. It never runs in the background and never reads your browsing history.
- When you click it, it sends **only the address of the site you're on** (for example `https://example.com`) to Vigil's server. The page path, query string, page content, cookies and form data never leave your browser.
- Vigil has no accounts, sells no data, shows no ads, and uses no tracking cookies.

## What the extension sends

When you click the Vigil icon, the extension reads the current tab's URL (using Chrome's `activeTab` permission, which only grants access at the moment you click) and sends its **origin**, the scheme and host such as `https://example.com`, to `https://vigil-psi-liard.vercel.app/api/scans`.

The extension does not collect or send:

- the rest of the URL (path, query string or fragment), which can contain private details such as tokens or search terms
- the content of the page, your cookies, passwords, form entries or keystrokes
- any other tabs, your browsing history, or anything when you haven't clicked the icon

The extension stores nothing on your device.

## What Vigil's server does with it

To grade the site, Vigil's server makes a few ordinary requests to that site's public address, the same requests any visitor's browser makes, plus public DNS lookups. Scans started from the extension are **passive**: they skip Vigil's checks for exposed files.

The server keeps:

- **The scan report**: the site's address, its grade and the findings. It is stored under a random, unguessable link and deleted automatically after **30 days**. Anyone you share that link with can view the report. Reports are never listed publicly.
- **A short-lived rate-limit counter**: your IP address (or, for IPv6, its network prefix) is used as a counter key to limit how many scans one visitor can run per minute. The counter expires within **2 minutes**.

Vigil does not build profiles, link scans to individuals, or use the data for anything other than producing the report you asked for.

## Service providers

Vigil runs on infrastructure from a few providers, who process data only to run the service:

- **Vercel** hosts the website and API. Like any web host, it handles requests (including your IP address) and keeps standard request logs under its own retention policy. See [Vercel's privacy policy](https://vercel.com/legal/privacy-policy).
- **Upstash** stores scan reports and rate-limit counters (Redis). See [Upstash's privacy policy](https://upstash.com/trust/privacy.pdf).
- **The National Vulnerability Database (NIST)**: when a scanned site reveals software versions, Vigil looks those product names and versions up to find known vulnerabilities. Nothing about you is sent.

## The website

In addition to the above, the website:

- keeps your recent scans and chosen report options in your own browser's local storage. They never leave your device, and clearing your browser data removes them.
- uses **Vercel Web Analytics and Speed Insights** to count page views and measure page speed. These are cookieless and report aggregated, anonymised statistics.

## Your choices

- Don't click the extension icon on a site you don't want graded. Nothing is sent otherwise.
- Remove the extension at any time from `chrome://extensions`.
- To have a report deleted before its 30 days are up, open an issue (below) with the report link.

## Children

Vigil is a tool for website owners and developers. It isn't directed at children and doesn't knowingly collect information from them.

## Changes

If this policy changes, the updated version will be published at this address with a new "Last updated" date. The full history of changes is visible in the repository.

## Contact

Questions or requests: open an issue at [github.com/CantStopGreatness/vigil/issues](https://github.com/CantStopGreatness/vigil/issues).
