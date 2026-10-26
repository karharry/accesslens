# Changelog

All notable changes to AccessLens are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.2] - 2026-10-25

### Changed
- The app version is now taken from the git tag at image build time instead of being typed in the code.
- Docker tags: `latest` now moves only when a release tag (`vX.Y.Z`) is pushed, so it always points at the newest
  release. Pushes to `main` build an `edge` image instead.

### Fixed
- The version shown in the sidebar (and used to refresh cached CSS/JS) no longer lags behind the release.

## [1.2.1] - 2026-10-25

### Added
- The sidebar entries for Dashboard, Insights, Users, Settings and My account can be expanded to list their sections;
  clicking a section jumps to it, from any page. The open/closed state is remembered per browser.
- The section you are viewing is highlighted in the sidebar while scrolling.

### Changed
- Saving a form keeps the scroll position instead of jumping to the top of the page.
- Result messages ("Settings saved", errors) are shown as dismissible pop-ups; success messages fade out.

### Fixed
- Running the container without the `DAC_READ_SEARCH` capability logged a full error trace every few seconds. The
  Direct connections panel now shows an explanatory message instead.

## [1.2.0] - 2026-10-25

### Added
- Recognition of common internet scanners in the user-agent (Palo Alto Cortex Xpanse, Censys, Shodan, ZGrab, masscan,
  Nmap, Nuclei, Nikto, sqlmap, LeakIX and other internet-survey crawlers). They are labelled `Scanner: <name>` with
  device `Bot`.
- Events already stored are re-labelled once, automatically, the first time this version starts.

## [1.1.0] - 2026-10-24

First release.

### Added
- Three data sources, kept separate throughout the UI: Nginx Proxy Manager / nginx / Apache access logs (read-only),
  Cloudflare tunnel traffic via the Cloudflare GraphQL Analytics API, and direct connections to host `ip:port` read
  from the kernel connection-tracking table.
- Network path (LAN, Tailscale, Internet), device, OS and app per event, derived from the client address and user-agent.
- Live dashboard, event table with filters, Explore, Aggregate, Insights and Uptime pages.
- Weekly email report for the previous Monday-Sunday week (SMTP configured in the UI).
- Web UI authentication: `admin` with a random password generated on first start, additional admin and viewer users,
  any admin can delete any other user.
- CSV export of events, Explore tables and Aggregate matrices.
- Optional ingest API, extra log files and HTTP uptime probes.
- Light, dark and system themes; mobile layout.
- Docker image for `linux/amd64` and `linux/arm64`, running as a non-root user with a bind-mounted `/config` folder.

[Unreleased]: https://github.com/karharry/accesslens/compare/v1.2.2...HEAD
[1.2.2]: https://github.com/karharry/accesslens/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/karharry/accesslens/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/karharry/accesslens/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/karharry/accesslens/releases/tag/v1.1.0
