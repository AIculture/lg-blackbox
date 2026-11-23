# LG Black Box

A WordPress plugin that records what a server was doing when a site went down, and shields the site from the most common bot traffic. Built for a shared 4 GB Cloudways server where one app's PHP workers repeatedly exhausted memory and killed MariaDB.

Current version: **1.13.0**. Admin page: **Tools > LG Black Box**.

## What it does

**Flight recorder (read-only)**
- Every ~30 s: load, memory, swap, pressure (PSI), MariaDB state, and memory per PHP-FPM pool (which app on the server was using the RAM).
- Logs slow / heavy requests and the cron hooks that ran in them, detects MariaDB restarts, and records the server state while the database is down (`db-error.php` drop-in).
- Request recorder and a text report you can download or paste.

**Shield (an mu-plugin gate, installed from the admin page, off until you switch it on)**
- Login protection: N failed logins in M minutes blocks the IP.
- Country filter for login pages (needs Cloudflare's `CF-IPCountry` header).
- Probe shield: instant 404 for scanner paths (`/.env`, `/actuator`, `credentials.json`, JS config / bundle hunts), then a block after a few probes.
- Site-wide block list, and an allow list that always wins.
- User-name privacy: no public user list, author pages or "unknown user" login errors.
- Static-site mode (off by default): for a static / cached site, refuses wp-login, xmlrpc, wp-cron, `/wp-admin/` and direct `.php` files for IPs not on the allow list, before WordPress loads. Never use it on an app that needs the REST API or webhooks.

## Install

**Quick install:** download [`lg-blackbox.zip`](lg-blackbox.zip) (open it on GitHub and press Download raw file), then in WordPress go to Plugins > Add New > Upload Plugin, choose the zip, install and activate. The zip is built from the files in this repo and already has the `lg-blackbox/` folder WordPress expects. To rebuild it after changing a file, run `build-zip.ps1` (PowerShell) and commit the new zip.

**Manual install:** the folder name must be `lg-blackbox`.

1. Put `gate.php`, `lg-blackbox.php`, `probe.php` and `assets/` in `wp-content/plugins/lg-blackbox/` (upload only these files, not a whole development folder).
2. Activate it, then open **Tools > LG Black Box**.
3. Switch on the protections you want. Enabling one adds your current IP to the allow list.

The plugin keeps its data in `wp-content/lg-blackbox/` as `<?php exit; ?>`-headed files with unguessable names, so nothing in it can be read over HTTP.

## Files

| File | Purpose |
|---|---|
| `lg-blackbox.php` | The plugin: recorder, report, admin page, switches. |
| `gate.php` | Copied to `wp-content/mu-plugins/lg-blackbox-gate.php` when a shield is enabled; runs before other plugins. |
| `probe.php` | Scanner-path detection, process / pool sampling helpers. |
| `assets/` | Admin page stylesheet and script. |

## Status

Checked in a PHP test harness (gate cases) and on a live shared server. Not tested inside a freshly installed WordPress end to end. No license file yet: all rights reserved until one is added.
