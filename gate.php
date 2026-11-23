<?php
/*
Plugin Name: LG Black Box login gate
Description: Managed by the LG Black Box plugin (Tools > LG Black Box). Before the other plugins load it can: refuse login requests from IPs that failed too often, refuse login pages for countries outside an allowed list, answer scanner probes for junk files (.env, /actuator, credentials.json...) with an instant 404, and (static-site mode) refuse every PHP entry point except page views for IPs that are not on the allow list. Delete this file, or use the Disable buttons, to remove it.
*/
/* LG-BLACKBOX-GATE v6 */
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

    /** Public client IP (Cloudflare header first). '' when unknown or private/loopback: never act on those. */
    function lg_bb_gate_ip()
    {
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $k) {
            if (!empty($_SERVER[$k])) {
                $cand = trim(explode(',', (string) $_SERVER[$k])[0]);
                if (filter_var($cand, FILTER_VALIDATE_IP)) {
                    return filter_var($cand, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) ? $cand : '';
                }
            }
        }
        return '';
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

    /**
     * JavaScript probes. Scanners hunt for config files and bundles that leak API keys (/config.js, /aws-exports.js,
     * /main.js, /static/js/main.1a2b3c.chunk.js, *.js.map). Returns:
     *   'hard' = a name only a scanner asks for: counts like any other probe (N in M minutes blocks the IP)
     *   'soft' = any other missing .js: answered with the cheap 404 but only counts toward a block when the same IP asks for
     *            5 DIFFERENT ones in the window, so one broken asset link on the site cannot get real visitors blocked
     *   ''     = not a probe (service workers, anything under WordPress' own folders)
     */
    function lg_bb_gate_js_kind($path)
    {
        if ($path === '' || $path[0] !== '/' || !preg_match('#\.(js|mjs|map)$#', $path)) {
            return '';
        }
        foreach (['/wp-content/', '/wp-includes/', '/wp-admin/', '/wp-json/'] as $own) {
            if (strpos($path, $own) === 0) {
                return '';
            }
        }
        $base = basename($path);
        // Service workers and push workers: a browser with a stale registration asks for these by itself.
        if (preg_match('#^(sw|service-?worker|ngsw-worker|firebase-messaging-sw|pwabuilder-sw|workbox-[a-z0-9]+|onesignal[a-z]*worker|sw-[a-z0-9]+)\.js$#i', $base)) {
            return '';
        }
        if (preg_match('#\.(js|css)\.map$#', $path)) {
            return 'hard';
        }
        // Config / secrets style names at any depth: /config.js, /js/config.js, /app.config.js, /env-config.js, /aws-exports.js ...
        if (preg_match('#^(.*[-_.])?(config|configuration|settings|secrets?|credentials?|keys?|environment|env|aws-exports|firebase-?config|appsettings)(\.[a-z0-9]+)?\.m?js$#i', $base)) {
            return 'hard';
        }
        // Bundle names scanners guess at the root.
        if (preg_match('#^/(main|app|bundle|index|script|scripts|common|vendor|vendors|runtime|polyfills|analytics|global|site|custom|build|dist|static|env|config)\.m?js$#i', $path)) {
            return 'hard';
        }
        return 'soft';
    }

    /** True when the browser itself says this is a same-site page load (an asset link that is broken on our own pages). */
    function lg_bb_gate_same_site()
    {
        if (isset($_SERVER['HTTP_SEC_FETCH_SITE']) && $_SERVER['HTTP_SEC_FETCH_SITE'] === 'same-origin') {
            return true;
        }
        $ref = isset($_SERVER['HTTP_REFERER']) ? (string) $_SERVER['HTTP_REFERER'] : '';
        $host = isset($_SERVER['HTTP_HOST']) ? strtolower((string) $_SERVER['HTTP_HOST']) : '';
        if ($ref !== '' && $host !== '') {
            $rh = parse_url($ref, PHP_URL_HOST);
            return is_string($rh) && strtolower($rh) === preg_replace('#:\d+$#', '', $host);
        }
        return false;
    }

    /** Plain 403 for static-site mode: a few bytes instead of a WordPress boot. */
    function lg_bb_gate_forbidden()
    {
        if (!headers_sent()) {
            http_response_code(403);
            header('Content-Type: text/plain; charset=utf-8');
            header('Cache-Control: no-store');
        }
        echo "Forbidden
";
        exit;
    }

    /**
     * Static-site mode: is this a request for a PHP entry point that a static / cached site never needs?
     * Page views (/, /about/, /blog/post/ ...) are NOT matched: they end in no ".php" and are not under the
     * admin, REST or cron paths. Matched: wp-login.php, xmlrpc.php, wp-cron.php, anything under /wp-admin/, any other
     * direct .php file, and the REST API. When $forms is true admin-ajax.php, admin-post.php and the REST API stay open so
     * contact forms keep working.
     */
    function lg_bb_gate_static_target($path, $rest, $forms)
    {
        if ($forms && (preg_match('#/wp-admin/(admin-ajax|admin-post).php$#', $path) || strpos($path, '/wp-json/') === 0 || $path === '/wp-json' || strpos($rest, '/') === 0)) {
            return false;
        }
        if (strpos($path, '/wp-admin/') === 0 || $path === '/wp-admin' || strpos($path, '/wp-json/') === 0 || $path === '/wp-json' || $rest !== '') {
            return true;
        }
        // Any direct .php file, except the front controller (the PHP file that serves every normal page).
        if (preg_match('#.phpd?$#', $path)) {
            return !preg_match('#^/index.php$#', $path);
        }
        return false;
    }

    /** Remember (one small file per IP, capped, at most one write per 5 s) who static-site mode refused. */
    function lg_bb_gate_static_note($dir, $ip, $path)
    {
        $f = $dir . '/sblk-' . substr(sha1($ip), 0, 20) . '.php';
        $now = time();
        $rec = null;
        if (is_file($f)) {
            $s = @file_get_contents($f);
            $j = is_string($s) && strlen($s) > 13 ? json_decode(substr($s, 13), true) : null;
            $rec = is_array($j) ? $j : null;
        } else {
            $many = @glob($dir . '/sblk-*.php');
            if ($many && count($many) >= 300) {
                return;
            }
        }
        if (is_array($rec) && isset($rec['last']) && $rec['last'] >= $now - 5) {
            return;
        }
        $rec = is_array($rec) ? $rec : ['ip' => $ip, 'n' => 0, 'first' => $now, 'paths' => []];
        $rec['n'] = (isset($rec['n']) ? (int) $rec['n'] : 0) + 1;
        $rec['last'] = $now;
        $rec['cc'] = isset($_SERVER['HTTP_CF_IPCOUNTRY']) ? strtoupper(substr(trim((string) $_SERVER['HTTP_CF_IPCOUNTRY']), 0, 2)) : '';
        $paths = isset($rec['paths']) && is_array($rec['paths']) ? $rec['paths'] : [];
        $p = substr($path, 0, 60);
        if (count($paths) < 5 && !in_array($p, $paths, true)) {
            $paths[] = $p;
        }
        $rec['paths'] = $paths;
        @file_put_contents($f, '<?php exit;?>' . json_encode($rec), LOCK_EX);
    }

    /**
     * Probe shield. Answers scanner probes with a 404 and, after N probes in M minutes from one IP,
     * refuses that IP everywhere for K minutes (admins with a login cookie, allow-listed IPs, search and
     * link-preview crawlers, and the server itself are never blocked).
     */
    function lg_bb_gate_probe($cfg, $dir, $path, $read, $lists_cb)
    {
        $is_probe = lg_bb_gate_is_probe($path);
        $soft = false;
        if (!$is_probe) {
            $js = lg_bb_gate_js_kind($path);
            if ($js === 'hard') {
                $is_probe = true;
            } elseif ($js === 'soft' && !lg_bb_gate_same_site()) {
                $is_probe = true;
                $soft = true;
            }
        }
        foreach ($_COOKIE as $k => $v) {
            if (strpos((string) $k, 'wordpress_logged_in_') === 0) {
                return; // never touch logged-in browsers (a missing file for them is a normal WordPress 404)
            }
        }
        $ip = lg_bb_gate_ip();
        if ($ip === '' || (isset($_SERVER['SERVER_ADDR']) && $_SERVER['SERVER_ADDR'] === $ip)) {
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
            $cc = isset($_SERVER['HTTP_CF_IPCOUNTRY']) ? strtoupper(substr(trim((string) $_SERVER['HTTP_CF_IPCOUNTRY']), 0, 2)) : '';
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
                // Distinct "soft" JS paths asked for in the window: 5 different ones from one IP is a bundle hunt.
                $sp = [];
                foreach ((array) (isset($rec['s']) ? $rec['s'] : []) as $sk => $st) {
                    if ($st >= $now - $win) {
                        $sp[$sk] = $st;
                    }
                }
                if ($soft) {
                    if (count($sp) < 30) {
                        $sp[substr($path, 0, 80)] = $now;
                    }
                } else {
                    $f[] = $now;
                }
                $rec['s'] = $sp;
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
                if (count($f) >= max(2, isset($cfg['probe_limit']) ? (int) $cfg['probe_limit'] : 5) || ($soft && count($sp) >= 5)) {
                    $rec['until'] = $now + max(1, isset($cfg['probe_block']) ? (int) $cfg['probe_block'] : 60) * 60;
                    $rec['f'] = [];
                    $rec['denied'] = 0;
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
        $static = !empty($cfg['static']);                               // static-site mode: PHP entry points other than page views
        if (!$prot && !$geo && !$probe && !$blockall && !$static) {
            return;
        }

        $uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '';
        $path = strtolower((string) parse_url($uri, PHP_URL_PATH));
        // Collapse "//" and "/./" tricks so /a//.env cannot slip past the matcher.
        $path = preg_replace('#/+#', '/', str_replace('/./', '/', $path));

        // Site-wide block list (set by hand from the admin page). Runs first and applies to every
        // request, but never to an allow-listed IP, so the owner cannot lock themselves out.
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
        // Static-site mode. Everything except page views is refused for any IP that is not on the allow list,
        // before WordPress loads. The server's own requests (self-cron) and unknown addresses are never touched.
        if ($static) {
            $srest = isset($_GET['rest_route']) && is_string($_GET['rest_route']) ? strtolower($_GET['rest_route']) : '';
            if (lg_bb_gate_static_target((string) $path, $srest, !isset($cfg['static_forms']) || !empty($cfg['static_forms']))) {
                $sip = lg_bb_gate_ip();
                $own = $sip !== '' && isset($_SERVER['SERVER_ADDR']) && $_SERVER['SERVER_ADDR'] === $sip;
                if ($sip !== '' && !$own && (empty($l0['allow']) || !in_array($sip, $l0['allow'], true))) {
                    lg_bb_gate_static_note($dir, $sip, (string) $path);
                    lg_bb_gate_forbidden();
                }
            }
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
            $cc = isset($_SERVER['HTTP_CF_IPCOUNTRY']) ? strtoupper(trim((string) $_SERVER['HTTP_CF_IPCOUNTRY'])) : '';
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
