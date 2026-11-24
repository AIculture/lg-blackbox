# Security checks and alerts (2.3)

Black Box used to stop attacks as they arrived. Version 2.3 adds noticing that something is wrong, and telling you.
Page: **Tools > LG Black Box > Security checks and alerts**. Everything keeps its state in plain files under
`wp-content/lg-blackbox/sec` (never the database: the database may be what is struggling), and every check has a time
budget so a scheduled tick never overruns. Written for PHP 7.4 and later.

## What it does

| Feature | How it works |
|---|---|
| **Alerts** | Email to the site admin address (or the addresses you set on the page). The same event is not repeated inside its cooldown (critical 1 h, warning 6 h, info 24 h) and at most 25 mails go out per 24 h (critical ones may exceed that by 10). The mail leaves after the visitor already has the page. SMS: the action `lg_bb_alert_critical` fires for every critical alert, no sender is attached. |
| **Cron watch** | Records every scheduled tick, learns the usual gap, and on a web request raises "scheduled jobs stopped" after four usual gaps (never under 5 minutes). Says so again when ticks resume. A scheduler cannot report its own death, so the check runs on visitor requests. |
| **File integrity** | Every 15 min: PHP files in `uploads/` that are not a PHP-guarded log or a "silence is golden" index, and `.htaccess` files there that turn PHP on. Every 6 h: malware patterns in plugins, themes, mu-plugins and drop-ins (only changed files are re-read) and any added, changed or removed mu-plugin. Daily: WordPress core and wordpress.org plugin files against the official checksums, extra PHP files inside `wp-admin/` and `wp-includes/`, and new or changed PHP files in the site root. |
| **Exposure scan** | Daily: requests the site's own public URLs as a stranger would (readme and license, sitemaps, author redirect, REST index, XML-RPC, debug and backup files, folder listings) and lists files in `uploads/` that are backups, exports, logs or keys. It sends scanner-style URLs only when the installed gate is v9 or newer (older gates could count the server itself as a scanner). |
| **404 / refused-link flood** | Many page misses (default 40 in 10 min) or refused signed-link/webhook calls (default 15) from one address add it to the automatic block list. Search-engine crawlers, allow-listed addresses, the server itself and known signed-in addresses are exempt. |
| **WordPress events** | New administrator or promotion to administrator, deleted administrator, administrator sign-in from a new address, plugin or theme activated, deactivated or installed, application password created, changes to `siteurl`, `home`, `admin_email`, open registration or a risky default role. |
| **Under-attack mode (gate v9)** | While the load average is at or above `ua_load` (default 3), anonymous visitors get a quarter of their request limit. Visitors presenting a Bearer token or a login cookie, and tenant webhook paths, keep the normal limit (these are claims, not proof, which is why they are limited rather than exempt). Follows the request-rate limit unless switched explicitly. |
| **Certificate, PHP, updates, DNS** | Daily: TLS certificate days left, PHP security-support window, pending WordPress and plugin updates, SPF and DMARC present. |
| **Weekly summary** | One mail a week with the state of every check. |
| **Shared block list** | `server/lgbb-sync.php` copies each app's automatic blocks into the other apps of the same server (see the header of the script for the rules and the cron line). |

## Notes

- **Gate v9 fix:** the probe shield only exempted `SERVER_ADDR`, which is `127.0.0.1` behind Apache, so the server's own public address (cron and self-checks reach the site through the public name) could be counted as a scanner. It now also exempts the addresses in `rl/self.php`.
- **Trust on first use** for mu-plugins and for non-WordPress PHP files in the site root: the first run records what exists (and still scans it for malware patterns); later additions or changes raise a critical alert until you press "I made these changes".
- **The first day is noisy:** the first run reports what already exists. Add paths you accept to `LG_BB_SEC_IGNORE` in `wp-config.php`.
- **Settings:** `LG_BB_ALERT_TO` (default recipients), the alert form on the admin page (recipients, flood limits, certificate warning days), `LG_BB_ALERT_DAILY_CAP`.
- **Item left to the application:** one account attacked from many addresses, and a "new address" alert for application users, belong in the application's own login code.

## Roll back

Restore the previous plugin folder and, if it changed, `wp-content/mu-plugins/lg-blackbox-gate.php`. Remove the sync cron line if you installed it.
