<?php
/*
Plugin Name: LG Black Box login gate
Description: Managed by the LG Black Box plugin (Tools > LG Black Box), multi-tenant CRM edition. Before the other plugins load it can: refuse login requests from IPs that failed too often, refuse login pages for countries outside an allowed list, and answer scanner probes for junk files (.env, /actuator, credentials.json...) with an instant 404. Delete this file, or use the Disable buttons, to remove it.
*/
/* LG-BLACKBOX-GATE v9 */
if (!defined('ABSPATH')) {
    return;
}

if (!function_exists('lg_bb_gate_run')) {

    function lg_bb_gate_deny($code, $msg, $retry = 0)
    {
        if (!headers_sent()) {
            http_response_code($code);
            header('Content-Type: application/json; charset=utf-8');
            header('Cache-Control: no-store');
            if ($retry > 0) {
                header('Retry-After: ' . (int) $retry);
            }
        }
        echo json_encode(['code' => 'too_many_attempts', 'message' => $msg, 'data' => ['status' => $code]]);
        exit;
    }

    /** Plain 404 for a scanner probe: a few bytes instead of a full WordPress boot. */
    function lg_bb_gate_notfound()
    {
        if (!headers_sent()) {
            http_response_code(404);
            header('Content-Type: text/plain; charset=utf-8');
            header('Cache-Control: no-store');
        }
        echo "Not found\n";
        exit;
    }

    /**
     * Is the TCP peer a proxy whose forwarded headers may be believed? Same rule as the CRM's CRM_Rate_Limit::client_ip():
     * loopback / private peers (nginx, Varnish on the same box) or an address / CIDR in LG_CRM_TRUSTED_PROXIES.
     * CF-Connecting-IP, X-Forwarded-For and CF-IPCountry are plain headers anyone can send; believing them from an
     * untrusted peer would let an attacker choose which IP gets blocked, or pose as an allowed country.
     */
    function lg_bb_gate_trusted($peer)
    {
        if (!filter_var($peer, FILTER_VALIDATE_IP)) {
            return false;
        }
        if (!filter_var($peer, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return true;
        }
        if (!defined('LG_CRM_TRUSTED_PROXIES')) {
            return false;
        }
        $list = LG_CRM_TRUSTED_PROXIES;
        if (is_string($list)) {
            $list = array_map('trim', explode(',', $list));
        }
        $pb = @inet_pton($peer);
        foreach ((array) $list as $entry) {
            $entry = (string) $entry;
            if ($entry === '') {
                continue;
            }
            if (strpos($entry, '/') === false) {
                if ($peer === $entry) {
                    return true;
                }
                continue;
            }
            list($net, $bits) = explode('/', $entry, 2);
            $nb = @inet_pton($net);
            $bits = (int) $bits;
            if ($pb === false || $nb === false || strlen($pb) !== strlen($nb) || $bits < 0 || $bits > strlen($pb) * 8) {
                continue;
            }
            $bytes = intdiv($bits, 8);
            if ($bytes > 0 && strncmp($pb, $nb, $bytes) !== 0) {
                continue;
            }
            $rem = $bits % 8;
            $mask = (0xFF << (8 - $rem)) & 0xFF;
            if ($rem === 0 || (ord($pb[$bytes]) & $mask) === (ord($nb[$bytes]) & $mask)) {
                return true;
            }
        }
        return false;
    }

    /** Public client IP. '' when unknown or private/loopback: never act on those. */
    function lg_bb_gate_ip()
    {
        $peer = isset($_SERVER['REMOTE_ADDR']) ? trim((string) $_SERVER['REMOTE_ADDR']) : '';
        $cand = filter_var($peer, FILTER_VALIDATE_IP) ? $peer : '';
        if (lg_bb_gate_trusted($peer)) {
            foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR'] as $k) {
                if (!empty($_SERVER[$k])) {
                    $h = trim(explode(',', (string) $_SERVER[$k])[0]);
                    if (filter_var($h, FILTER_VALIDATE_IP)) {
                        $cand = $h;
                        break;
                    }
                }
            }
        }
        if ($cand === '') {
            return '';
        }
        return filter_var($cand, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) ? $cand : '';
    }

    /** Visitor country from Cloudflare's CF-IPCountry, only when the peer is a trusted proxy. '' otherwise. */
    function lg_bb_gate_cc()
    {
        $peer = isset($_SERVER['REMOTE_ADDR']) ? trim((string) $_SERVER['REMOTE_ADDR']) : '';
        if (!lg_bb_gate_trusted($peer)) {
            return '';
        }
        return isset($_SERVER['HTTP_CF_IPCOUNTRY']) ? strtoupper(substr(trim((string) $_SERVER['HTTP_CF_IPCOUNTRY']), 0, 2)) : '';
    }

    /**
     * Is this path something only a vulnerability scanner asks for? A request only reaches PHP when
     * no such file exists, so every match is a guaranteed 404 that would otherwise boot WordPress.
     * Deliberately narrow: nothing WordPress, Elementor, the CRM or a normal page slug uses.
     */
    function lg_bb_gate_is_probe($path)
    {
        if ($path === '' || $path[0] !== '/') {
            return false;
        }
        static $exact = [
            '/phpinfo', '/phpinfo.php', '/info.php', '/metrics', '/elmah.axd', '/web.config', '/dockerfile', '/jenkinsfile',
            '/makefile', '/gemfile', '/composer.json', '/composer.lock', '/package.json', '/package-lock.json', '/yarn.lock',
            '/app.js', '/env.js', '/__env.js', '/env.txt', '/litellm.yaml', '/litellm.yml', '/wp-config.txt',
            '/app/etc/local.xml', '/js/config.js', '/datafiles/env.js',
        ];
        static $prefix = [
            '/actuator', '/symfony/', '/_profiler', '/_ignition', '/telescope', '/server-status', '/server-info',
            '/phpmyadmin', '/pma/', '/adminer', '/v2/_catalog', '/vendor/phpunit', '/cgi-bin/', '/boaform', '/manager/html',
        ];
        if (in_array($path, $exact, true)) {
            return true;
        }
        foreach ($prefix as $p) {
            if (strpos($path, $p) === 0) {
                return true;
            }
        }
        // Dotfiles / VCS / cloud credential folders at any depth. /.well-known is not in the list.
        if (preg_match('#(^|/)\.(env|git|svn|hg|aws|ssh|docker|vscode|idea|ds_store|npmrc|htpasswd|bash_history|travis)(/|\.|$)#', $path)) {
            return true;
        }
        // Config / secrets / backup files by name + extension (an extension is required: /settings is a page, /settings.json is a probe).
        if (strpos($path, '/wp-content/') === 0 || strpos($path, '/wp-includes/') === 0 || strpos($path, '/wp-admin/') === 0) {
            return false; // theme/plugin assets: never second-guess WordPress' own folders by file name
        }
        $base = basename($path);
        return (bool) preg_match('#^(wp-config|config|configuration|settings|secrets?|credentials?|client_secrets?|service[_-]?account|appsettings(\.[a-z]+)?|parameters|serverless|docker-compose|compose|netlify|vercel|terraform|azure-pipelines|bitbucket-pipelines|env|__env|app\.config|master|production|aws|local|litellm|database|db|dump|backup)(\.[a-z0-9_-]+)*\.(json|ya?ml|toml|ini|env|key|pem|txt|js|xml|bak|old|save|orig|swp|sql|zip|gz|tar|rar|7z|tfstate|tfvars|backup)$#', $base);
    }

    function lg_bb_gate_auto_path($dir, $ip)
    {
        return $dir . '/auto-' . substr(sha1($ip), 0, 20) . '.php';
    }

    /** Has this IP made logged-in CRM API calls (a real user or app) in the request recorder? Then it is never auto-blocked. */
    function lg_bb_gate_known_good($dir, $ip)
    {
        $needle = '"ip":' . json_encode($ip);
        foreach ((array) @glob(dirname($dir) . '/rec-*') as $f) {
            $h = @fopen($f, 'r');
            if (!$h) {
                continue;
            }
            while (($line = fgets($h)) !== false) {
                if (strpos($line, $needle) !== false && strpos($line, '"a":1') !== false) {
                    fclose($h);
                    return true;
                }
            }
            fclose($h);
        }
        return false;
    }

    /** Put a repeat offender on the automatic block list (one small file per IP, capped, expires by itself). */
    function lg_bb_gate_auto_add($cfg, $dir, $ip, $why, $cc, $days = 0)
    {
        // Never the server itself: its own cron and loopback requests come from its public address.
        if (empty($cfg['auto']) || $ip === '' || in_array($ip, lg_bb_gate_self_ips($dir), true) || lg_bb_gate_known_good($dir, $ip)) {
            return;
        }
        $f = lg_bb_gate_auto_path($dir, $ip);
        if (is_file($f)) {
            return;
        }
        $many = @glob($dir . '/auto-*.php');
        if ($many && count($many) >= 500) {
            return;
        }
        $now = time();
        $days = $days > 0 ? (int) $days : max(1, isset($cfg['auto_days']) ? (int) $cfg['auto_days'] : 30);
        @file_put_contents($f, '<?php exit;?>' . json_encode(['ip' => $ip, 'cc' => $cc, 'why' => $why, 'first' => $now, 'last' => 0, 'n' => 0, 'until' => $now + $days * 86400]), LOCK_EX);
    }

    /** Public addresses of this server itself (written by the plugin into rl/self.php). Empty when unknown. */
    function lg_bb_gate_self_ips($dir)
    {
        $j = json_decode(substr((string) @file_get_contents($dir . '/self.php'), 13), true);
        return is_array($j) && !empty($j['ips']) && is_array($j['ips']) ? $j['ips'] : [];
    }

    /** Counter key of a client: the IP, or the /64 network for IPv6 (an attacker owns a whole /64, so per-address counting is useless). */
    function lg_bb_gate_rate_key($ip)
    {
        if (strpos($ip, ':') !== false) {
            $b = @inet_pton($ip);
            if ($b !== false) {
                $ip = bin2hex(substr($b, 0, 8));
            }
        }
        return substr(sha1($ip), 0, 12);
    }

    /**
     * Count one request for this key in the current minute and return the count so far. Fixed set of slot files (no directory scans):
     * each holds the counts of up to 40 clients for one minute. Fails open (returns 0) when it cannot lock or the slot is full.
     */
    function lg_bb_gate_rate_hit($dir, $key)
    {
        $d = $dir . '/rate';
        if (!is_dir($d)) {
            @mkdir($d, 0775, true);
        }
        $file = $d . '/s' . (hexdec(substr($key, 0, 6)) % 2048) . '.php';
        $minute = (int) floor(time() / 60);
        $h = @fopen($file, 'c+');
        if (!$h) {
            return 0;
        }
        $count = 0;
        if (flock($h, LOCK_EX)) {
            $raw = (string) stream_get_contents($h);
            $j = strlen($raw) > 13 ? json_decode(substr($raw, 13), true) : null;
            if (!is_array($j) || !isset($j['m'], $j['e']) || $j['m'] !== $minute || !is_array($j['e'])) {
                $j = ['m' => $minute, 'e' => []];
            }
            if (isset($j['e'][$key]) || count($j['e']) < 40) {
                $j['e'][$key] = (isset($j['e'][$key]) ? (int) $j['e'][$key] : 0) + 1;
                $count = $j['e'][$key];
            }
            ftruncate($h, 0);
            rewind($h);
            fwrite($h, '<?php exit;?>' . json_encode($j));
            fflush($h);
            flock($h, LOCK_UN);
        }
        fclose($h);
        return $count;
    }

    /**
     * Request-rate limit, before WordPress loads. Limits per minute per client: anonymous, logged-in / CRM API (Bearer token or
     * WordPress login cookie, which are only claims, hence a higher limit and not an exemption), and aggressive crawlers (low).
     * Over the limit: 429 with Retry-After. Five over-limit minutes within an hour put a non-crawler on the automatic block list for a day.
     */
    function lg_bb_gate_rate_check($cfg, $dir, $path, $l0)
    {
        $ip = lg_bb_gate_ip();
        if ($ip === '' || (isset($_SERVER['SERVER_ADDR']) && $_SERVER['SERVER_ADDR'] === $ip) || (!empty($l0['allow']) && in_array($ip, $l0['allow'], true))) {
            return; // private / allow-listed
        }
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
        $bad = (bool) preg_match('/bytespider|mj12bot|dotbot|blexbot|semrushbot|ahrefsbot|petalbot|dataforseo|barkrowler|serpstatbot|zoominfobot|megaindex|seekport|ccbot|claudebot|gptbot|amazonbot|imagesiftbot|omgili/i', $ua);
        $good = !$bad && (bool) preg_match('/googlebot|bingbot|applebot|duckduckbot|facebookexternalhit|meta-externalagent|yandex|baiduspider/i', $ua);
        $bearer = (!empty($_SERVER['HTTP_AUTHORIZATION']) && stripos((string) $_SERVER['HTTP_AUTHORIZATION'], 'bearer ') === 0)
            || (!empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) && stripos((string) $_SERVER['REDIRECT_HTTP_AUTHORIZATION'], 'bearer ') === 0);
        $cookie = false;
        foreach ($_COOKIE as $k => $v) {
            if (strpos((string) $k, 'wordpress_logged_in_') === 0) {
                $cookie = true;
                break;
            }
        }
        $webhook = strpos($path, '/lg-crm/v1/t/') !== false || strpos($path, 'qb-webhook') !== false;
        $limit = $bad ? (isset($cfg['rate_limit_bot']) ? (int) $cfg['rate_limit_bot'] : 20)
            : (($bearer || $cookie || $webhook) ? (isset($cfg['rate_limit_auth']) ? (int) $cfg['rate_limit_auth'] : 600)
                : (isset($cfg['rate_limit']) ? (int) $cfg['rate_limit'] : 120));
        // Under-attack mode: while the server is struggling (load average at or above ua_load, default 3 on this
        // 1-core box), anonymous visitors get a quarter of their limit. Signed-in CRM users (Bearer token or login
        // cookie) and the Twilio / QuickBooks webhooks keep their normal limit. On by default whenever the rate limit is.
        if (!isset($cfg['ua']) || !empty($cfg['ua'])) {
            if (!$bearer && !$cookie && !$webhook && function_exists('sys_getloadavg')) {
                $la = @sys_getloadavg();
                if (is_array($la) && $la[0] >= (isset($cfg['ua_load']) ? (float) $cfg['ua_load'] : 3.0)) {
                    $limit = (int) floor($limit / 4);
                }
            }
        }
        $limit = max(10, $limit);
        $key = lg_bb_gate_rate_key($ip);
        $n = lg_bb_gate_rate_hit($dir, $key);
        if ($n <= $limit) {
            return;
        }
        if (in_array($ip, lg_bb_gate_self_ips($dir), true)) {
            return; // the server's own requests (cron, loopbacks) are never limited
        }
        if ($n === $limit + 1 && !$good && !$bad) {
            // First request over the limit in this minute: remember it; repeated minutes make a repeat offender.
            $of = $dir . '/over-' . substr(sha1($ip), 0, 20) . '.php';
            $rec = is_file($of) ? json_decode(substr((string) @file_get_contents($of), 13), true) : null;
            $now = time();
            if (!is_array($rec) || empty($rec['first']) || $rec['first'] < $now - 3600) {
                $many = @glob($dir . '/over-*.php');
                if (!is_array($rec) && $many && count($many) >= 300) {
                    $rec = null;
                } else {
                    $rec = ['ip' => $ip, 'n' => 0, 'first' => $now, 'last' => 0, 'p' => ''];
                }
            }
            if (is_array($rec)) {
                $rec['n'] = (int) $rec['n'] + 1;
                $rec['last'] = $now;
                $rec['p'] = substr($path, 0, 60);
                $rec['limit'] = $limit;
                @file_put_contents($of, '<?php exit;?>' . json_encode($rec), LOCK_EX);
                if ($rec['n'] >= 5) {
                    lg_bb_gate_auto_add($cfg, $dir, $ip, 'request flood: over ' . $limit . ' requests/min in ' . $rec['n'] . ' separate minutes', '', max(1, isset($cfg['rate_auto_days']) ? (int) $cfg['rate_auto_days'] : 1));
                }
            }
        }
        lg_bb_gate_deny(429, 'Too many requests. Slow down.', 60 - (time() % 60));
    }

    /**
     * Probe shield. Answers scanner probes with a 404 and, after N probes in M minutes from one IP,
     * refuses that IP everywhere for K minutes (admins with a login cookie, allow-listed IPs, search and
     * link-preview crawlers, and the server itself are never blocked).
     */
    function lg_bb_gate_probe($cfg, $dir, $path, $read, $lists_cb)
    {
        $is_probe = lg_bb_gate_is_probe($path);
        foreach ($_COOKIE as $k => $v) {
            if (strpos((string) $k, 'wordpress_logged_in_') === 0) {
                return; // never touch logged-in browsers (a missing file for them is a normal WordPress 404)
            }
        }
        $ip = lg_bb_gate_ip();
        // SERVER_ADDR is 127.0.0.1 behind Apache, so the server's own public address (its self-checks and cron
        // reach the site through the public name) is also known from rl/self.php. Neither is ever counted as a scanner.
        if ($ip === '' || (isset($_SERVER['SERVER_ADDR']) && $_SERVER['SERVER_ADDR'] === $ip) || in_array($ip, lg_bb_gate_self_ips($dir), true)) {
            if ($is_probe) {
                lg_bb_gate_notfound();
            }
            return;
        }
        $file = $dir . '/probe-' . substr(sha1($ip), 0, 20) . '.php';
        $rec = is_file($file) ? $read($file) : null;
        $now = time();

        if (is_array($rec) && !empty($rec['until']) && $rec['until'] > $now) {
            $lists = $lists_cb();
            if (empty($lists['allow']) || !in_array($ip, $lists['allow'], true)) {
                $rec['denied'] = (isset($rec['denied']) ? (int) $rec['denied'] : 0) + 1;
                @file_put_contents($file, '<?php exit;?>' . json_encode($rec), LOCK_EX);
                lg_bb_gate_deny(403, 'Blocked.', (int) $rec['until'] - $now);
            }
            if ($is_probe) {
                lg_bb_gate_notfound(); // allow-listed IP: still no reason to boot WordPress for a junk path
            }
            return;
        }
        if (!$is_probe) {
            return;
        }

        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
        $trusted = (bool) preg_match('/googlebot|bingbot|applebot|duckduckbot|facebookexternalhit|meta-externalagent|yandex|baiduspider/i', $ua);
        $lists = $lists_cb();
        $allowed = !empty($lists['allow']) && in_array($ip, $lists['allow'], true);
        if (!$trusted && !$allowed) {
            $cc = lg_bb_gate_cc();
            if (!is_array($rec)) {
                $many = @glob($dir . '/probe-*.php');
                $rec = ($many && count($many) >= 300) ? null : ['ip' => $ip, 'cc' => $cc, 'ua' => substr($ua, 0, 80), 'n' => 0, 'f' => [], 'until' => 0, 'denied' => 0, 'first' => $now, 'last' => 0, 'paths' => []];
            }
            if (is_array($rec)) {
                $win = max(1, isset($cfg['probe_window']) ? (int) $cfg['probe_window'] : 10) * 60;
                $f = [];
                foreach ((array) (isset($rec['f']) ? $rec['f'] : []) as $t) {
                    if ($t >= $now - $win) {
                        $f[] = $t;
                    }
                }
                $f[] = $now;
                $rec['f'] = $f;
                $rec['n'] = (isset($rec['n']) ? (int) $rec['n'] : 0) + 1;
                $rec['last'] = $now;
                $rec['cc'] = $cc !== '' ? $cc : (isset($rec['cc']) ? $rec['cc'] : '');
                $p = substr($path, 0, 60);
                $paths = isset($rec['paths']) && is_array($rec['paths']) ? $rec['paths'] : [];
                if (count($paths) < 5 && !in_array($p, $paths, true)) {
                    $paths[] = $p;
                }
                $rec['paths'] = $paths;
                if (count($f) >= max(2, isset($cfg['probe_limit']) ? (int) $cfg['probe_limit'] : 5)) {
                    $rec['until'] = $now + max(1, isset($cfg['probe_block']) ? (int) $cfg['probe_block'] : 60) * 60;
                    $rec['f'] = [];
                    $rec['denied'] = 0;
                    $rec['nb'] = (isset($rec['nb']) ? (int) $rec['nb'] : 0) + 1;
                    if ($rec['nb'] >= 2) {
                        // Blocked for scanning twice: a repeat offender, refuse it everywhere for a while.
                        lg_bb_gate_auto_add($cfg, $dir, $ip, 'scanner, blocked ' . $rec['nb'] . ' times by the probe shield', $cc);
                    }
                }
                @file_put_contents($file, '<?php exit;?>' . json_encode($rec), LOCK_EX);
            }
        }
        lg_bb_gate_notfound();
    }

    function lg_bb_gate_run()
    {
        if (!defined('WP_CONTENT_DIR') || !isset($_SERVER['REQUEST_METHOD'])) {
            return;
        }
        $dir = WP_CONTENT_DIR . '/lg-blackbox/rl';
        $read = function ($f) {
            $s = @file_get_contents($f);
            if (!is_string($s) || strlen($s) < 14) {
                return null;
            }
            $j = json_decode(substr($s, 13), true);
            return is_array($j) ? $j : null;
        };
        $cfg = $read($dir . '/config.php');
        if (!$cfg) {
            return;
        }
        $prot = !empty($cfg['enabled']);                              // failed-login rate limit
        $geo = isset($cfg['geo']) && $cfg['geo'] === 'block';          // country filter
        $probe = isset($cfg['probe']) && $cfg['probe'] === 'on';       // scanner-probe shield
        $lists_cache = null;
        $lists_cb = function () use ($read, $dir, &$lists_cache) {
            if ($lists_cache === null) {
                $l = $read($dir . '/lists.php');
                $lists_cache = is_array($l) ? $l : [];
            }
            return $lists_cache;
        };
        $l0 = $lists_cb();
        $blockall = !empty($l0['block_all']) && is_array($l0['block_all']);   // IPs refused on every request
        $auto = !empty($cfg['auto']);                                   // automatic block list of repeat offenders
        $rate = !empty($cfg['rate']);                                   // per-IP request-rate limit
        $cronguard = !empty($cfg['cron_guard']);                        // wp-cron.php answers only the server itself
        if (!$prot && !$geo && !$probe && !$blockall && !$auto && !$rate && !$cronguard) {
            return;
        }

        $uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '';
        $path = strtolower((string) parse_url($uri, PHP_URL_PATH));
        // Collapse "//" and "/./" tricks so /a//.env cannot slip past the matcher.
        $path = preg_replace('#/+#', '/', str_replace('/./', '/', $path));

        // Site-wide block list (set by hand from the admin page). Runs first and applies to every
        // request, but never to an allow-listed IP, so the owner cannot lock themselves out.
        // lg_bb_gate_ip() only believes forwarded headers from a trusted proxy (see lg_bb_gate_trusted).
        if ($blockall) {
            $bip = lg_bb_gate_ip();
            if ($bip !== '' && in_array($bip, $l0['block_all'], true) && (empty($l0['allow']) || !in_array($bip, $l0['allow'], true))) {
                $bf = $dir . '/blk-' . substr(sha1($bip), 0, 20) . '.php';
                $brec = $read($bf);
                $brec = is_array($brec) ? $brec : ['ip' => $bip, 'n' => 0, 'first' => time()];
                $brec['n'] = (isset($brec['n']) ? (int) $brec['n'] : 0) + 1;
                $brec['last'] = time();
                $brec['p'] = substr($path, 0, 60);
                @file_put_contents($bf, '<?php exit;?>' . json_encode($brec), LOCK_EX);
                lg_bb_gate_deny(403, 'Blocked.');
            }
        }
        // Automatic block list: the gate itself adds an IP after repeated scanning (and the plugin after repeated login
        // lockouts). Never for an allow-listed IP; every entry expires on its own, or Unblock on the admin page removes it.
        if ($auto) {
            $aip = lg_bb_gate_ip();
            if ($aip !== '') {
                $af = lg_bb_gate_auto_path($dir, $aip);
                if (is_file($af)) {
                    $arec = $read($af);
                    if (is_array($arec) && !empty($arec['until']) && $arec['until'] > time()) {
                        if (empty($l0['allow']) || !in_array($aip, $l0['allow'], true)) {
                            $anow = time();
                            if (empty($arec['last']) || $arec['last'] <= $anow - 30) { // not a write on every hit of a flood
                                $arec['n'] = (isset($arec['n']) ? (int) $arec['n'] : 0) + 1;
                                $arec['last'] = $anow;
                                $arec['p'] = substr($path, 0, 60);
                                @file_put_contents($af, '<?php exit;?>' . json_encode($arec), LOCK_EX);
                            }
                            lg_bb_gate_deny(403, 'Blocked.');
                        }
                    } else {
                        @unlink($af); // expired
                    }
                }
            }
        }
        // wp-cron.php runs all of WordPress for whoever asks. This server's cron calls it from the server itself (or by WP-CLI, which
        // never reaches the gate), so any other address is refused before WordPress loads.
        if ($cronguard && substr($path, -12) === '/wp-cron.php') {
            $cip = lg_bb_gate_ip();
            $selfs = lg_bb_gate_self_ips($dir);
            // Fail open: with no known server address (self.php not written yet) the guard does nothing, so it can never stop the server's own cron.
            if ($selfs && $cip !== '' && !in_array($cip, $selfs, true) && !(isset($_SERVER['SERVER_ADDR']) && $_SERVER['SERVER_ADDR'] === $cip) && (empty($l0['allow']) || !in_array($cip, $l0['allow'], true))) {
                lg_bb_gate_deny(403, 'Not allowed.');
            }
        }
        if ($rate) {
            lg_bb_gate_rate_check($cfg, $dir, $path, $l0);
        }
        if (!$prot && !$geo && !$probe) {
            return;
        }

        if ($probe) {
            lg_bb_gate_probe($cfg, $dir, (string) $path, $read, $lists_cb);
        }
        if (!$prot && !$geo) {
            return;
        }

        $rest = isset($_GET['rest_route']) && is_string($_GET['rest_route']) ? strtolower($_GET['rest_route']) : '';
        $is_post = $_SERVER['REQUEST_METHOD'] === 'POST';
        $is_xmlrpc = strpos($path, 'xmlrpc.php') !== false;
        $is_wplogin = strpos($path, 'wp-login.php') !== false;
        $is_crm = $is_post && (strpos($path, '/lg-crm/v1/auth/login') !== false || strpos($rest, '/lg-crm/v1/auth/login') !== false);
        // Password-protected pages post to wp-login.php?action=postpass: customers, never a login attack.
        $postpass = $is_wplogin && isset($_GET['action']) && $_GET['action'] === 'postpass';

        $is_login = $is_post && ($is_wplogin || $is_xmlrpc || $is_crm);          // rate-limit scope
        $geo_target = $geo && !$postpass && ($is_wplogin || $is_xmlrpc || $is_crm); // country-filter scope
        if (!($prot && $is_login) && !$geo_target) {
            return;
        }
        if ($prot && $is_post && $is_xmlrpc && !empty($cfg['block_xmlrpc'])) {
            lg_bb_gate_deny(403, 'XML-RPC is disabled.');
        }

        $ip = lg_bb_gate_ip();
        // Never act on private/loopback addresses: behind a proxy that would mean "everyone".
        if ($ip === '') {
            return;
        }

        $lists = $lists_cb();
        if (!empty($lists['allow']) && in_array($ip, $lists['allow'], true)) {
            return; // allow list beats everything
        }
        if ($prot && $is_login && !empty($lists['block']) && in_array($ip, $lists['block'], true)) {
            lg_bb_gate_deny(403, 'Blocked.');
        }

        // Country filter. Cloudflare sends the visitor's country as CF-IPCountry. An absent
        // header, XX (unknown) and T1 (Tor) are let through: the filter only refuses what it
        // positively knows to be outside the allowed list.
        if ($geo_target) {
            $cc = lg_bb_gate_cc();
            $allowed = !empty($cfg['geo_countries']) && is_array($cfg['geo_countries']) ? $cfg['geo_countries'] : ['CA', 'US'];
            if (preg_match('/^[A-Z]{2}$/', $cc) && $cc !== 'XX' && $cc !== 'T1' && !in_array($cc, $allowed, true)) {
                // Remember who was refused (one small file per IP, capped) so the admin page can show it.
                $file = $dir . '/geo-' . substr(sha1($ip), 0, 20) . '.php';
                $rec = $read($file);
                if (!is_array($rec)) {
                    $many = @glob($dir . '/geo-*.php');
                    $rec = ($many && count($many) >= 300) ? null : ['ip' => $ip, 'cc' => $cc, 'n' => 0, 'first' => time(), 'last' => 0, 'k' => ''];
                }
                if (is_array($rec)) {
                    $rec['n'] = (isset($rec['n']) ? (int) $rec['n'] : 0) + 1;
                    $rec['last'] = time();
                    $rec['cc'] = $cc;
                    $rec['k'] = $is_xmlrpc ? 'xmlrpc.php' : ($is_wplogin ? 'wp-login.php' : 'auth/login');
                    @file_put_contents($file, '<?php exit;?>' . json_encode($rec), LOCK_EX);
                }
                lg_bb_gate_deny(403, 'Access from your country is not permitted.');
            }
        }

        if ($prot && $is_login) {
            $file = $dir . '/ip-' . substr(sha1($ip), 0, 20) . '.php';
            $rec = $read($file);
            if ($rec && !empty($rec['until']) && $rec['until'] > time()) {
                $rec['denied'] = (isset($rec['denied']) ? (int) $rec['denied'] : 0) + 1;
                @file_put_contents($file, '<?php exit;?>' . json_encode($rec), LOCK_EX);
                lg_bb_gate_deny(429, 'Too many failed login attempts. Try again later.', $rec['until'] - time());
            }
        }
    }

    try {
        lg_bb_gate_run();
    } catch (\Throwable $e) {
        // The gate must never take the site down.
    }
}
