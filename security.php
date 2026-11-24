<?php
/**
 * LG Black Box security checks (added in 2.3.0).
 *
 * The first versions of Black Box stop attacks as they arrive. This file adds the other half: noticing
 * that something is wrong, and saying so.
 *
 *   - Alerts by email (SMS is a hook, off until a number is chosen)
 *   - Cron watch: tells you when scheduled jobs stop (this host was silently dead for six months)
 *   - File integrity: PHP files that do not belong in uploads/, known malware patterns, changes in mu-plugins,
 *     WordPress core and wordpress.org plugin checksums
 *   - Exposure scan: requests this site's own sensitive URLs and lists loose backup/log/export files in uploads/
 *   - 404 and refused-link flood detection feeding the automatic block list
 *   - WordPress security events: new administrator, admin login from a new address, plugin and theme changes,
 *     risky option changes
 *   - Certificate, PHP end-of-life and pending-update checks, SPF/DMARC presence
 *   - Under-attack alert (the gate itself tightens the anonymous rate limit, see gate.php)
 *
 * Everything here keeps its state in plain files under wp-content/lg-blackbox/sec (never the database: the
 * database may be what is struggling), and every job has a time budget so a tick never overruns.
 * Written to run on PHP 7.4 and later.
 */
if (!defined('ABSPATH')) {
    exit;
}

if (!defined('LG_BB_ALERT_DAILY_CAP')) {
    define('LG_BB_ALERT_DAILY_CAP', 25);   // alert mails per 24 h (critical ones may go 10 over)
}

// ---------------------------------------------------------------- state and settings

function lg_bb_sec_dir()
{
    static $d = null;
    if ($d !== null) {
        return $d;
    }
    $d = lg_bb_dir() . '/sec';
    if (!is_dir($d)) {
        @mkdir($d, 0755, true);
    }
    return $d;
}

function lg_bb_sec_read($name, $default = [])
{
    $j = lg_bb_rl_read(lg_bb_sec_dir() . '/' . $name . '.php');
    return is_array($j) ? $j : $default;
}

function lg_bb_sec_write($name, $data)
{
    lg_bb_rl_write(lg_bb_sec_dir() . '/' . $name . '.php', $data);
}

function lg_bb_sec_cfg()
{
    $d = ['alert_to' => '', 'alert_from' => '', 'flood' => null, 'flood_limit' => 40, 'flood_window' => 10, 'forbid_limit' => 15, 'cert_days' => 14, 'ignore' => []];
    $c = lg_bb_sec_read('config');
    $c = array_merge($d, $c);
    if (defined('LG_BB_SEC_IGNORE') && is_array(LG_BB_SEC_IGNORE)) {
        $c['ignore'] = array_merge((array) $c['ignore'], LG_BB_SEC_IGNORE);
    }
    return $c;
}

/** 404 / refused-link flood watch: follows the automatic block list unless switched explicitly. */
function lg_bb_sec_flood_on()
{
    $c = lg_bb_sec_cfg();
    if ($c['flood'] !== null) {
        return !empty($c['flood']);
    }
    $r = lg_bb_rl_cfg();
    return !empty($r['auto']);
}

/** Under-attack tightening in the gate: follows the request-rate limit unless switched explicitly. */
function lg_bb_sec_ua_on()
{
    $r = lg_bb_rl_cfg();
    return isset($r['ua']) && $r['ua'] !== null ? !empty($r['ua']) : !empty($r['rate']);
}

/** The server's own public addresses (rl/self.php, written by the plugin). */
function lg_bb_sec_is_self($ip)
{
    static $ips = null;
    if ($ips === null) {
        $j = lg_bb_rl_read(lg_bb_rl_dir() . '/self.php');
        $ips = is_array($j) && !empty($j['ips']) ? (array) $j['ips'] : [];
    }
    return in_array($ip, $ips, true);
}

/** Counter key of a client: the IP, or its /64 for IPv6 (an attacker owns the whole /64). */
function lg_bb_sec_ip_key($ip)
{
    if (strpos($ip, ':') !== false) {
        $b = @inet_pton($ip);
        if ($b !== false) {
            $ip = bin2hex(substr($b, 0, 8));
        }
    }
    return substr(sha1($ip), 0, 12);
}

// ---------------------------------------------------------------- alerts

function lg_bb_alert_recipients()
{
    $c = lg_bb_sec_cfg();
    $raw = $c['alert_to'] !== '' ? $c['alert_to'] : (defined('LG_BB_ALERT_TO') ? (string) LG_BB_ALERT_TO : (string) get_option('admin_email'));
    $out = [];
    foreach (preg_split('/[\s,;]+/', $raw) as $e) {
        if ($e !== '' && is_email($e) && !in_array($e, $out, true)) {
            $out[] = $e;
        }
    }
    return array_slice($out, 0, 5);
}

/**
 * Queue an alert. The same key is not sent again within its cooldown (critical 1 h, warning 6 h, info 24 h), and at
 * most LG_BB_ALERT_DAILY_CAP are sent per 24 h, so a flood of events can never become a flood of mail. The mail
 * leaves after the visitor already has the response (fastcgi_finish_request), so an alert never slows a page.
 *
 * @return bool true when it was queued
 */
function lg_bb_alert($key, $subject, $body, $level = 'warn')
{
    if (!in_array($level, ['crit', 'warn', 'info'], true)) {
        $level = 'warn';
    }
    $cool = ['crit' => 3600, 'warn' => 21600, 'info' => 86400];
    $now = time();
    $st = lg_bb_sec_read('alerts');
    $sent = isset($st['sent']) && is_array($st['sent']) ? $st['sent'] : [];
    if (isset($sent[$key]) && $now - (int) $sent[$key] < $cool[$level]) {
        return false;
    }
    foreach ($sent as $k => $t) {
        if ($now - (int) $t > 7 * 86400) {
            unset($sent[$k]);
        }
    }
    $times = [];
    foreach ((array) (isset($st['times']) ? $st['times'] : []) as $t) {
        if ((int) $t > $now - 86400) {
            $times[] = (int) $t;
        }
    }
    $log = isset($st['log']) && is_array($st['log']) ? $st['log'] : [];
    if (count($times) >= LG_BB_ALERT_DAILY_CAP + ($level === 'crit' ? 10 : 0)) {
        $log[] = ['t' => $now, 'key' => $key, 'level' => $level, 'subject' => substr($subject, 0, 150), 'sent' => 'daily cap'];
        $st['log'] = array_slice($log, -60);
        lg_bb_sec_write('alerts', $st);
        return false;
    }
    $sent[$key] = $now;
    $times[] = $now;
    $out = isset($st['outbox']) && is_array($st['outbox']) ? $st['outbox'] : [];
    $out[] = ['t' => $now, 'key' => $key, 'level' => $level, 'subject' => substr($subject, 0, 150), 'body' => substr($body, 0, 6000)];
    lg_bb_sec_write('alerts', ['sent' => $sent, 'times' => $times, 'outbox' => array_slice($out, -30), 'log' => array_slice($log, -60)]);

    static $registered = false;
    if (!$registered) {
        $registered = true;
        register_shutdown_function(function () {
            if (function_exists('fastcgi_finish_request')) {
                @fastcgi_finish_request();
            }
            try {
                lg_bb_alert_flush();
            } catch (\Throwable $e) {
                // an alert must never break a request
            }
        });
    }
    return true;
}

function lg_bb_alert_send($m)
{
    $to = lg_bb_alert_recipients();
    if (!$to) {
        return false;
    }
    $host = (string) wp_parse_url(home_url(), PHP_URL_HOST);
    $subject = '[Black Box ' . $host . '] ' . ($m['level'] === 'crit' ? 'CRITICAL: ' : '') . $m['subject'];
    $body = $m['body'] . "\n\n--\n" . $host . ', ' . lg_bb_date('Y-m-d H:i:s', $m['t']) . ' ' . lg_bb_tz_label()
        . "\nDetails: " . admin_url('tools.php?page=lg-blackbox#lg-sec') . "\n";
    $c = lg_bb_sec_cfg();
    $from = $c['alert_from'] !== '' && is_email($c['alert_from']) ? $c['alert_from'] : lg_bb_abuse_from(); // must be on a domain the mail add-on has verified
    try {
        return (bool) wp_mail($to, $subject, $body, ['Content-Type: text/plain; charset=UTF-8', 'From: Black Box <' . $from . '>']);
    } catch (\Throwable $e) {
        return false;
    }
}

/** Send what is queued. Safe to call from anywhere: the queue is claimed before sending. */
function lg_bb_alert_flush()
{
    $st = lg_bb_sec_read('alerts');
    $out = isset($st['outbox']) && is_array($st['outbox']) ? $st['outbox'] : [];
    if (!$out) {
        return 0;
    }
    $st['outbox'] = [];
    lg_bb_sec_write('alerts', $st); // claim
    $done = [];
    $n = 0;
    foreach ($out as $m) {
        $ok = lg_bb_alert_send($m);
        $n += $ok ? 1 : 0;
        $done[] = ['t' => $m['t'], 'key' => $m['key'], 'level' => $m['level'], 'subject' => $m['subject'], 'sent' => $ok ? 'sent' : 'FAILED'];
        if ($m['level'] === 'crit') {
            // SMS later: hook a sender here (for example the Twilio number) once a number is chosen.
            do_action('lg_bb_alert_critical', $m['subject'], $m['body'], $m['key']);
        }
    }
    $st = lg_bb_sec_read('alerts');
    $st['log'] = array_slice(array_merge(isset($st['log']) && is_array($st['log']) ? $st['log'] : [], $done), -60);
    lg_bb_sec_write('alerts', $st);
    return $n;
}

// ---------------------------------------------------------------- tick, cron watch, load watch

/** Median gap between ticks, in seconds (0 = not enough history yet). */
function lg_bb_sec_gap($ticks)
{
    $g = [];
    for ($i = 1; $i < count($ticks); $i++) {
        $g[] = $ticks[$i] - $ticks[$i - 1];
    }
    if (count($g) < 5) {
        return 0;
    }
    sort($g);
    return (int) $g[intdiv(count($g), 2)];
}

/** Silence longer than this is "cron stopped": four usual gaps, never under 5 minutes. */
function lg_bb_sec_stale_limit($gap)
{
    return max(300, 4 * (int) $gap);
}

function lg_bb_sec_note_tick()
{
    $st = lg_bb_sec_read('ticks');
    $t = [];
    foreach ((array) (isset($st['t']) ? $st['t'] : []) as $x) {
        $t[] = (int) $x;
    }
    $now = time();
    if ($t && $now - end($t) < 20) {
        return; // the same tick seen twice
    }
    $since = (int) (isset($st['stale_since']) ? $st['stale_since'] : 0);
    $t[] = $now;
    lg_bb_sec_write('ticks', ['t' => array_slice($t, -40), 'stale_since' => 0]);
    if ($since > 0) {
        lg_bb_alert('cron-back-' . $now, 'Scheduled jobs are running again', 'Cron was silent for about ' . max(1, (int) round(($now - $since) / 60)) . ' minutes and is running again.', 'info');
    }
}

/** Called on web requests (once a minute): has the tick stopped? The tick cannot report its own death. */
function lg_bb_sec_cron_check()
{
    $st = lg_bb_sec_read('ticks');
    $t = [];
    foreach ((array) (isset($st['t']) ? $st['t'] : []) as $x) {
        $t[] = (int) $x;
    }
    if (count($t) < 6) {
        return;
    }
    $gap = lg_bb_sec_gap($t);
    $age = time() - end($t);
    if ($gap > 0 && $age > lg_bb_sec_stale_limit($gap)) {
        if (empty($st['stale_since'])) {
            $st['stale_since'] = end($t);
            lg_bb_sec_write('ticks', $st);
        }
        lg_bb_alert(
            'cron-stale',
            'Scheduled jobs have stopped',
            'No scheduled tick for ' . (int) round($age / 60) . ' minutes (it normally runs every ' . max(1, (int) round($gap / 60)) . " min).\n"
            . "Until it is back: the QuickBooks queue, receipts auto-confirm, polling, nightly backups and cleanups do not run.\n"
            . 'Check the server crontab (Cloudways master user) and that DISABLE_WP_CRON is not blocking the call to wp-cron.php.',
            'crit'
        );
    }
}

function lg_bb_sec_load_watch()
{
    $la = function_exists('sys_getloadavg') ? @sys_getloadavg() : false;
    if (!is_array($la)) {
        return;
    }
    $r = lg_bb_rl_cfg();
    $thr = isset($r['ua_load']) && $r['ua_load'] ? (float) $r['ua_load'] : 3.0;
    $st = lg_bb_sec_read('load');
    $n = $la[0] >= $thr ? (int) (isset($st['n']) ? $st['n'] : 0) + 1 : 0;
    lg_bb_sec_write('load', ['n' => $n]);
    if ($n < 3) {
        return;
    }
    $top = '';
    try {
        if (function_exists('lg_bb_rec_sources')) {
            foreach (lg_bb_rec_sources(1, 5) as $s) {
                $top .= '  ' . $s['ip'] . ($s['cc'] !== '' ? ' (' . $s['cc'] . ')' : '') . ' ' . $s['n'] . ' requests' . ($s['scanner'] ? ', scanner-like' : '') . "\n";
            }
        }
    } catch (\Throwable $e) {
        $top = '';
    }
    lg_bb_alert(
        'load-high',
        'Server load is high (' . round($la[0], 1) . ')',
        'Load average ' . round($la[0], 1) . ' for at least ' . $n . ' checks (threshold ' . $thr . ").\n"
        . (lg_bb_sec_ua_on() && lg_bb_gate_installed() ? "Under-attack mode is ON: anonymous visitors are limited to a quarter of the normal rate; signed-in CRM users and the webhooks are not.\n"
            : "Under-attack mode is OFF or the gate is not installed, so nothing is being tightened automatically.\n")
        . ($top !== '' ? "Busiest sources in the last hour:\n" . $top : ''),
        'warn'
    );
}

add_action('lg_bb_tick', 'lg_bb_sec_tick', 20);
function lg_bb_sec_tick()
{
    try {
        lg_bb_sec_note_tick();
        lg_bb_sec_load_watch();
        $lock = lg_bb_sec_dir() . '/tick.lock';
        clearstatcache(true, $lock);
        if (!is_file($lock) || time() - (int) @filemtime($lock) > 120) {
            @touch($lock);
            // One check per tick keeps a minute-by-minute cron light. With a slow cron (ticks 5+ minutes apart) three
            // checks fit in a tick, so the first full pass does not take an hour.
            $tt = lg_bb_sec_read('ticks');
            $gap = lg_bb_sec_gap(array_map('intval', (array) (isset($tt['t']) ? $tt['t'] : [])));
            lg_bb_sec_run_due(time() + 25, false, $gap >= 300 ? 3 : 1);
            @unlink($lock);
        }
        lg_bb_alert_flush();
    } catch (\Throwable $e) {
        // diagnostics must never break cron
    }
}

add_action('init', function () {
    if (wp_doing_cron() || (defined('WP_CLI') && WP_CLI)) {
        return;
    }
    $stamp = lg_bb_sec_dir() . '/stale.stamp';
    clearstatcache(true, $stamp);
    if (is_file($stamp) && time() - (int) @filemtime($stamp) < 60) {
        return;
    }
    @touch($stamp);
    try {
        lg_bb_sec_cron_check();
    } catch (\Throwable $e) {
    }
}, 30);

// ---------------------------------------------------------------- 404 and refused-link flood

/**
 * Count one event for this client in a sliding window, in a fixed set of small files (no directory scans).
 *
 * @return int events in the window so far, including this one
 */
function lg_bb_sec_count($kind, $ip, $window)
{
    $key = lg_bb_sec_ip_key($ip);
    $f = lg_bb_sec_dir() . '/c-' . $kind . '-' . (hexdec(substr($key, 0, 4)) % 256) . '.php';
    $h = @fopen($f, 'c+');
    if (!$h) {
        return 0;
    }
    $n = 0;
    if (flock($h, LOCK_EX)) {
        $raw = (string) stream_get_contents($h);
        $j = strlen($raw) > 13 ? json_decode(substr($raw, 13), true) : null;
        $j = is_array($j) ? $j : [];
        $now = time();
        foreach ($j as $k => $e) {
            if (!is_array($e) || $now - (int) $e[1] > $window) {
                unset($j[$k]);
            }
        }
        if (isset($j[$key])) {
            $j[$key][0] = (int) $j[$key][0] + 1;
        } elseif (count($j) < 60) {
            $j[$key] = [1, $now];
        }
        $n = isset($j[$key]) ? (int) $j[$key][0] : 0;
        ftruncate($h, 0);
        rewind($h);
        fwrite($h, '<?php exit;?>' . json_encode($j));
        fflush($h);
        flock($h, LOCK_UN);
    }
    fclose($h);
    return $n;
}

function lg_bb_sec_flood_hit($kind, $label)
{
    if (!lg_bb_sec_flood_on()) {
        return;
    }
    $ip = lg_bb_ip();
    if (!is_string($ip) || !lg_bb_rl_public_ip($ip) || lg_bb_sec_is_self($ip)) {
        return;
    }
    $lists = lg_bb_rl_lists();
    if (in_array($ip, $lists['allow'], true)) {
        return;
    }
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
    if (preg_match('/googlebot|bingbot|applebot|duckduckbot|facebookexternalhit|meta-externalagent|yandex|baiduspider/i', $ua)) {
        return; // crawlers meet dead links; the rate limit still applies to them
    }
    $c = lg_bb_sec_cfg();
    $limit = max(5, (int) ($kind === '404' ? $c['flood_limit'] : $c['forbid_limit']));
    $win = max(1, (int) $c['flood_window']) * 60;
    $n = lg_bb_sec_count($kind, $ip, $win);
    if ($n !== $limit) {
        return; // act once per window, on the crossing request
    }
    $added = lg_bb_auto_add($ip, $label . ': ' . $n . ' in ' . (int) $c['flood_window'] . ' min');
    lg_bb_alert(
        'flood-' . $kind . '-' . substr(sha1($ip), 0, 10),
        'Many ' . $label . ' from ' . $ip,
        $ip . (lg_bb_cc() !== '' ? ' (' . lg_bb_cc() . ')' : '') . ' caused ' . $n . ' ' . $label . ' within ' . (int) $c['flood_window'] . " minutes (limit $limit).\n"
        . ($added ? 'It was added to the automatic block list.' : 'It was NOT blocked (automatic blocks are off, or it is allow-listed, or it is a known signed-in CRM address).') . "\n"
        . 'Last path: ' . lg_bb_clean(isset($_SERVER['REQUEST_URI']) ? (string) parse_url((string) $_SERVER['REQUEST_URI'], PHP_URL_PATH) : '', 100),
        'warn'
    );
}

add_action('template_redirect', function () {
    if (!is_404() || is_user_logged_in()) {
        return;
    }
    $path = strtolower((string) parse_url(isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '', PHP_URL_PATH));
    if (preg_match('#/(favicon\.ico|apple-touch-icon[^/]*|robots\.txt|sitemap[^/]*\.xml|ads\.txt)$#', $path)) {
        return;
    }
    lg_bb_sec_flood_hit('404', 'page misses (404)');
}, 99);

add_filter('rest_post_dispatch', function ($result, $server, $request) {
    if ($result instanceof WP_HTTP_Response && (int) $result->get_status() === 403 && $request instanceof WP_REST_Request
        && strpos((string) $request->get_route(), '/lg-crm/v1/') === 0 && !is_user_logged_in()) {
        $auth = (string) $request->get_header('authorization');
        if ($auth === '') { // a signed-in CRM user hitting a role guard is not a guesser
            lg_bb_sec_flood_hit('403', 'refused link or webhook calls (403)');
        }
    }
    return $result;
}, 10, 3);

// ---------------------------------------------------------------- integrity

function lg_bb_sec_patterns()
{
    return [
        'eval of an encoded payload' => '/\beval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|convert_uudecode)\s*\(/i',
        'code run from request data' => '/\b(?:assert|eval|create_function)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b/i',
        'command run from request data' => '/\b(?:system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i',
        'decoded request data' => '/\bbase64_decode\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i',
        'function called from request data' => '/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(/',
        'file included from request data' => '/\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i',
        'known web shell' => '/\b(?:c99shell|r57shell|b374k|FilesMan|WSO\s+[0-9]|IndoXploit|Web\s+Shell\s+by|ALFA\s+TEaM)\b/i',
        'obfuscated string' => '/(?:\\\\x[0-9a-f]{2}){40,}/i',
    ];
}

/** Label of the first malware pattern found in $s, or '' (a guarded log file, which starts with an exit, is never scanned: it holds visitor-supplied text). */
function lg_bb_sec_scan_content($s)
{
    if (strncmp(ltrim($s), '<?php exit', 10) === 0) {
        return '';
    }
    foreach (lg_bb_sec_patterns() as $label => $re) {
        if (preg_match($re, $s)) {
            return $label;
        }
    }
    return '';
}

/** May this PHP file sit under uploads/? Only the guarded logs and "silence is golden" index files. */
function lg_bb_sec_upload_php_ok($path, $content)
{
    if (preg_match('/^<\?php\s*(?:exit|die)\b/i', ltrim($content))) {
        return true; // a private log: PHP-guarded, starts with an exit
    }
    if (strtolower(basename($path)) === 'index.php' && strlen($content) <= 300
        && preg_match('/^\s*<\?php\s*(?:\/\/[^\n]*\n|\/\*.*?\*\/\s*)*\s*(?:\?>)?\s*$/s', $content)) {
        return true;
    }
    return false;
}

/** Directory walk with a deadline. Returns file paths; sets $cut when the deadline stopped it. */
function lg_bb_sec_walk($root, $deadline, &$cut, $skip = ['node_modules', '.git'])
{
    $out = [];
    $cut = false;
    if (!is_dir($root)) {
        return $out;
    }
    try {
        $it = new RecursiveIteratorIterator(new RecursiveCallbackFilterIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
            function ($cur) use ($skip) {
                if ($cur->isLink()) {
                    return false;
                }
                return $cur->isDir() ? !in_array($cur->getFilename(), $skip, true) : true;
            }
        ));
        $i = 0;
        foreach ($it as $f) {
            $out[] = $f->getPathname();
            if ((++$i % 500) === 0 && time() > $deadline) {
                $cut = true;
                break;
            }
        }
    } catch (\Throwable $e) {
        // unreadable folder: report what was found
    }
    return $out;
}

function lg_bb_sec_job_result($name, $ok, $summary)
{
    $st = lg_bb_sec_read('jobs');
    $st[$name] = ['t' => time(), 'ok' => (bool) $ok, 'summary' => substr($summary, 0, 300), 'v' => LG_BB_VERSION];
    lg_bb_sec_write('jobs', $st);
}

function lg_bb_sec_hits_alert($key, $title, $hits)
{
    if (!$hits) {
        return;
    }
    $lines = [];
    foreach (array_slice($hits, 0, 25) as $h) {
        $lines[] = '  ' . $h[0] . '  (' . $h[1] . ')';
    }
    lg_bb_alert(
        $key . '-' . substr(md5(json_encode($hits)), 0, 10),
        $title . ' (' . count($hits) . ')',
        $title . ":\n" . implode("\n", $lines) . (count($hits) > 25 ? "\n  ... and " . (count($hits) - 25) . ' more' : '')
        . "\n\nIf you did not put these files here, treat the site as compromised: change the admin and SFTP passwords, restore from a backup taken before the file date, and tell your host.",
        'crit'
    );
}

/** Fast check, every 15 min: PHP in uploads/ that is not a guarded log, and .htaccess files that re-enable PHP there. */
function lg_bb_sec_job_uploads($deadline)
{
    $up = wp_upload_dir();
    $base = isset($up['basedir']) ? (string) $up['basedir'] : '';
    $hits = [];
    $cut = false;
    $n = 0;
    foreach (lg_bb_sec_walk($base, $deadline, $cut) as $p) {
        $n++;
        $b = strtolower(basename($p));
        if (preg_match('/\.(php[0-9]?|phtml|phar|pht|inc)$/i', $b)) {
            $head = (string) @file_get_contents($p, false, null, 0, 400);
            if (!lg_bb_sec_upload_php_ok($p, $head)) {
                $hits[] = [substr($p, strlen(ABSPATH)), 'PHP file in uploads, ' . (int) @filesize($p) . ' bytes, ' . lg_bb_date('Y-m-d H:i', (int) @filemtime($p))];
            }
        } elseif ($b === '.htaccess') {
            $c = (string) @file_get_contents($p, false, null, 0, 4000);
            if (preg_match('/AddHandler|SetHandler|php_value|php_flag|auto_prepend_file|AddType\s+application\/x-httpd-php/i', $c)) {
                $hits[] = [substr($p, strlen(ABSPATH)), '.htaccess that enables PHP handling'];
            }
        }
    }
    lg_bb_sec_hits_alert('uploads-php', 'PHP code found in the uploads folder', $hits);
    lg_bb_sec_job_result('uploads', !$hits, $n . ' files checked' . ($cut ? ' (stopped at the time limit)' : '') . ', ' . count($hits) . ' finding(s)');
    lg_bb_sec_write('uploads-last', ['hits' => $hits]);
}

/** Every 6 h: malware patterns in plugins, mu-plugins, themes and drop-ins (only files that changed since the last run are read) and mu-plugin baseline. */
function lg_bb_sec_job_integrity($deadline)
{
    $prev = lg_bb_sec_read('files');
    $sigs = isset($prev['sig']) && is_array($prev['sig']) ? $prev['sig'] : [];
    $first = !$sigs;
    $roots = [WP_PLUGIN_DIR, WPMU_PLUGIN_DIR, get_theme_root()];
    $self = rtrim(str_replace('\\', '/', dirname(__FILE__)), '/') . '/';
    $new = [];
    $hits = [];
    $read = 0;
    $changed = [];
    $cut = false;
    $files = [];
    foreach ($roots as $r) {
        foreach (lg_bb_sec_walk($r, $deadline, $c1) as $p) {
            $files[] = $p;
        }
        $cut = $cut || $c1;
    }
    foreach ((array) glob(WP_CONTENT_DIR . '/*.php') as $p) {
        $files[] = $p; // drop-ins: advanced-cache.php, object-cache.php, db-error.php
    }
    foreach ($files as $p) {
        if (!preg_match('/\.(php[0-9]?|phtml|phar|pht|inc)$/i', $p)) {
            continue;
        }
        $rel = substr($p, strlen(ABSPATH));
        $m = (int) @filemtime($p);
        $sz = (int) @filesize($p);
        $old = isset($sigs[$rel]) ? $sigs[$rel] : null;
        if ($old && (int) $old[0] === $m && (int) $old[1] === $sz && empty($old[2])) {
            $new[$rel] = $old;
            continue;
        }
        if (time() > $deadline) {
            $cut = true;
            if ($old) {
                $new[$rel] = $old;
            }
            continue;
        }
        $label = '';
        if (strpos(str_replace('\\', '/', $p), $self) !== 0) { // this plugin's own files hold the patterns as text
            $label = lg_bb_sec_scan_content((string) @file_get_contents($p, false, null, 0, 614400));
            $read++;
        }
        $new[$rel] = [$m, $sz, $label !== '' ? 1 : 0];
        if ($label !== '') {
            $hits[] = [$rel, 'pattern: ' . $label];
        }
        if (!$first && !$old && count($changed) < 40) {
            $changed[] = $rel;
        }
    }
    if ($cut) { // unvisited files keep their old signature, so the next run picks them up
        foreach ($sigs as $rel => $o) {
            if (!isset($new[$rel])) {
                $new[$rel] = $o;
            }
        }
    }
    lg_bb_sec_write('files', ['sig' => $new, 't' => time(), 'changed' => $changed]);
    lg_bb_sec_hits_alert('malware', 'Suspicious code found in plugin, theme or drop-in files', $hits);

    // mu-plugins: nothing should appear or change there without you knowing (trust on first use, then acknowledge changes).
    $base = lg_bb_sec_read('mu-base');
    $first_mu = !isset($base['files']);
    $cur = [];
    $gate_src = @file_get_contents(dirname(LG_BB_PROBE) . '/gate.php');
    foreach ((array) glob(WPMU_PLUGIN_DIR . '/*') as $p) {
        if (!is_file($p)) {
            continue;
        }
        $s = (string) @file_get_contents($p);
        $cur[basename($p)] = sha1($s);
        if (!$first_mu && is_string($gate_src) && $gate_src !== '' && $s === $gate_src) {
            $base['files'][basename($p)] = $cur[basename($p)]; // our own gate, current version: always fine
        }
    }
    $diff = [];
    if ($first_mu) {
        $base = ['files' => $cur, 't' => time()];
        lg_bb_sec_write('mu-base', $base);
    } else {
        foreach ($cur as $f => $h) {
            if (!isset($base['files'][$f])) {
                $diff[] = [$f, 'new mu-plugin'];
            } elseif ($base['files'][$f] !== $h) {
                $diff[] = [$f, 'mu-plugin changed'];
            }
        }
        foreach ($base['files'] as $f => $h) {
            if (!isset($cur[$f])) {
                $diff[] = [$f, 'mu-plugin removed'];
            }
        }
    }
    lg_bb_sec_write('mu-diff', ['diff' => $diff]);
    if ($diff) {
        $lines = [];
        foreach ($diff as $d) {
            $lines[] = '  ' . $d[0] . '  (' . $d[1] . ')';
        }
        lg_bb_alert(
            'mu-change-' . substr(md5(json_encode($diff)), 0, 10),
            'mu-plugins changed (' . count($diff) . ')',
            "Must-use plugins load before everything else and cannot be deactivated from the admin, which makes them a favourite hiding place.\n" . implode("\n", $lines)
            . "\n\nIf you made this change, press 'I made these changes' on Tools > LG Black Box > Security checks.",
            'crit'
        );
    }
    lg_bb_sec_job_result('integrity', !$hits && !$diff, count($new) . ' PHP files watched, ' . $read . ' read this run' . ($cut ? ' (stopped at the time limit)' : '') . ', ' . count($hits) . ' pattern hit(s), ' . count($diff) . ' mu-plugin change(s)');
}

function lg_bb_sec_http_json($url, $cache, $ttl)
{
    $f = lg_bb_sec_dir() . '/' . $cache . '.php';
    if (is_file($f) && time() - (int) @filemtime($f) < $ttl) {
        $j = lg_bb_rl_read($f);
        if (is_array($j)) {
            return $j;
        }
    }
    $r = wp_remote_get($url, ['timeout' => 12, 'redirection' => 2]);
    if (is_wp_error($r) || (int) wp_remote_retrieve_response_code($r) !== 200) {
        return null;
    }
    $j = json_decode((string) wp_remote_retrieve_body($r), true);
    if (!is_array($j)) {
        return null;
    }
    lg_bb_rl_write($f, $j);
    return $j;
}

/** Daily: WordPress core files against api.wordpress.org checksums, plus extra PHP files in wp-admin/ and wp-includes/, and wordpress.org plugins. */
function lg_bb_sec_job_core($deadline)
{
    global $wp_version;
    $hits = [];
    $checked = 0;
    $note = '';
    $sums = lg_bb_sec_http_json('https://api.wordpress.org/core/checksums/1.0/?version=' . rawurlencode($wp_version) . '&locale=en_US', 'core-' . preg_replace('/[^0-9.]/', '', $wp_version), 7 * 86400);
    if ($sums && isset($sums['checksums']) && is_array($sums['checksums'])) {
        $map = $sums['checksums'];
        foreach ($map as $rel => $md5) {
            if (strpos($rel, 'wp-content/') === 0 || !preg_match('/\.(php|js|css)$/', $rel)) {
                continue;
            }
            $abs = ABSPATH . $rel;
            if (!is_file($abs)) {
                continue; // removed on purpose (readme.html, license.txt) or an unused language file
            }
            $checked++;
            if (md5_file($abs) !== $md5) {
                $hits[] = [$rel, 'WordPress core file differs from the official release'];
            }
        }
        $cut = false;
        foreach (['wp-admin', 'wp-includes'] as $dir) {
            foreach (lg_bb_sec_walk(ABSPATH . $dir, $deadline, $cut) as $p) {
                $rel = str_replace('\\', '/', substr($p, strlen(ABSPATH)));
                if (preg_match('/\.(php[0-9]?|phtml|phar)$/i', $rel) && !isset($map[$rel])) {
                    $hits[] = [$rel, 'extra PHP file inside core'];
                }
            }
        }
        // PHP files in the site root that are not part of WordPress (wp-salt.php, a stray copy, or a web shell). What is there on the
        // first run is the baseline (trust on first use) and is still scanned for malware patterns; a NEW or CHANGED one raises the alert.
        $c0 = lg_bb_sec_cfg();
        $extras = [];
        foreach ((array) glob(ABSPATH . '*.php') as $p) {
            $rel = basename($p);
            if (isset($map[$rel]) || $rel === 'wp-config.php' || in_array($rel, (array) $c0['ignore'], true)) {
                continue;
            }
            $body = (string) @file_get_contents($p, false, null, 0, 614400);
            $extras[$rel] = sha1($body);
            $lab = lg_bb_sec_scan_content($body);
            if ($lab !== '') {
                $hits[] = [$rel, 'pattern: ' . $lab];
            }
        }
        $rb = lg_bb_sec_read('root-base');
        if (!isset($rb['files'])) {
            lg_bb_sec_write('root-base', ['files' => $extras, 't' => time()]);
        } else {
            foreach ($extras as $rel => $h) {
                if (!isset($rb['files'][$rel])) {
                    $hits[] = [$rel, 'new PHP file in the site root'];
                } elseif ($rb['files'][$rel] !== $h) {
                    $hits[] = [$rel, 'PHP file in the site root changed'];
                }
            }
        }
    } else {
        $note = ' (core checksums unavailable right now)';
    }

    // wordpress.org plugins publish a checksum list per version; others (ours, premium) simply have none.
    if (!function_exists('get_plugins')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    $n_plug = 0;
    foreach (get_plugins() as $file => $data) {
        if ($n_plug >= 12 || time() > $deadline) {
            break;
        }
        $slug = dirname($file);
        if ($slug === '.' || empty($data['Version']) || $slug === 'lg-blackbox') {
            continue;
        }
        $j = lg_bb_sec_http_json('https://downloads.wordpress.org/plugin-checksums/' . rawurlencode($slug) . '/' . rawurlencode($data['Version']) . '.json', 'plug-' . preg_replace('/[^a-z0-9_.-]/i', '', $slug . '-' . $data['Version']), 7 * 86400);
        if (!$j || empty($j['files']) || !is_array($j['files'])) {
            continue;
        }
        $n_plug++;
        foreach ($j['files'] as $rel => $info) {
            $want = is_array($info) ? (isset($info['md5']) ? (array) $info['md5'] : []) : [(string) $info];
            $abs = WP_PLUGIN_DIR . '/' . $slug . '/' . $rel;
            if (!$want || !is_file($abs)) {
                continue;
            }
            $checked++;
            if (!in_array(md5_file($abs), $want, true)) {
                $hits[] = ['wp-content/plugins/' . $slug . '/' . $rel, 'differs from the wordpress.org release ' . $data['Version']];
            }
        }
    }
    lg_bb_sec_write('core-last', ['hits' => $hits]);
    lg_bb_sec_hits_alert('core', 'WordPress core or plugin files differ from the official release', $hits);
    lg_bb_sec_job_result('core', !$hits, $checked . ' files verified against wordpress.org (' . $n_plug . ' plugins), ' . count($hits) . ' finding(s)' . $note);
}

// ---------------------------------------------------------------- exposure scan

/** Is this file under uploads/ something that should never be public (a backup, an export, a log, a key)? */
function lg_bb_sec_loose_file_bad($rel)
{
    $b = strtolower(basename($rel));
    if ($b === 'index.html' || $b === 'index.php' || $b === '.htaccess' || $b === '.gitkeep') {
        return '';
    }
    if (preg_match('/\.(sql|sqlite|db|bak|old|orig|swp|zip|gz|tgz|tar|7z|rar|env|pem|key|ini|conf|ya?ml|log|csv|xlsx?|json)$/', $b)) {
        return 'a backup, export, log or key file that anyone can download';
    }
    if (preg_match('/\.txt$/', $b) && preg_match('/(log|debug|backup|dump|export|secret|password|token|key)/', $b)) {
        return 'a text log or export that anyone can download';
    }
    return '';
}

/** One URL's verdict: '' if fine, else what is wrong. */
function lg_bb_sec_judge($kind, $code, $location, $body)
{
    switch ($kind) {
        case 'absent':
            return ($code >= 200 && $code < 300) ? 'answers ' . $code . ' to anyone' : '';
        case 'author':
            if (($code === 301 || $code === 302) && stripos($location, '/author/') !== false) {
                return 'redirects to the author page, which names a login';
            }
            return ($code >= 200 && $code < 300) ? 'answers ' . $code . ' to anyone' : '';
        case 'xmlrpc':
            return ($code === 200 && stripos($body, 'XML-RPC server accepts POST') !== false) ? 'XML-RPC is open' : '';
        case 'restindex':
            $j = json_decode($body, true);
            return (is_array($j) && !empty($j['routes'])) ? 'the REST index lists ' . count($j['routes']) . ' routes to anyone' : '';
        case 'listing':
            return stripos($body, 'Index of /') !== false ? 'directory listing is on' : '';
    }
    return '';
}

function lg_bb_sec_selfscan_targets()
{
    $legacy = ['crm_qb_debug_log.txt', 'crm_debug_log.txt', 'crm_twillio_webhook_log.txt', 'crm_twillio_error_log.txt', 'crm_contract_log.txt', 'crm_receipts_unauthorized_log.txt'];
    $t = [
        ['/readme.html', 'absent'], ['/license.txt', 'absent'], ['/wp-sitemap.xml', 'absent'], ['/wp-sitemap-users-1.xml', 'absent'],
        ['/?author=1', 'author'], ['/xmlrpc.php', 'xmlrpc'], ['/wp-json/wp/v2/users', 'absent'], ['/wp-json/', 'restindex'],
        ['/wp-content/debug.log', 'absent'], ['/.env', 'absent'], ['/.git/config', 'absent'], ['/wp-config.php.bak', 'absent'],
        ['/wp-config.php~', 'absent'], ['/backup.sql', 'absent'], ['/db.sql', 'absent'], ['/phpinfo.php', 'absent'],
        ['/wp-content/uploads/', 'listing'], ['/wp-content/plugins/', 'listing'], ['/wp-content/uploads/crm-lead-backups/', 'listing'],
    ];
    foreach ($legacy as $f) {
        $t[] = ['/wp-content/uploads/' . $f, 'absent'];
    }
    return $t;
}

/** Is the installed gate new enough (v9+) not to count this server's own requests as a scanner? Without a gate there is nothing to trip. */
function lg_bb_sec_gate_selfsafe()
{
    if (!lg_bb_gate_installed()) {
        return true;
    }
    return (bool) preg_match('/LG-BLACKBOX-GATE v(\d+)/', (string) @file_get_contents(lg_bb_gate_path()), $m) && (int) $m[1] >= 9;
}

/** Daily: ask our own public URLs what a stranger would get, and list files in uploads/ that should not be public. */
function lg_bb_sec_job_exposure($deadline)
{
    $c = lg_bb_sec_cfg();
    $ignore = array_map('strval', (array) $c['ignore']);
    $found = [];

    $up = wp_upload_dir();
    $base = isset($up['basedir']) ? (string) $up['basedir'] : '';
    $cut = false;
    foreach (lg_bb_sec_walk($base, $deadline, $cut) as $p) {
        $rel = str_replace('\\', '/', substr($p, strlen($base)));
        $why = lg_bb_sec_loose_file_bad($rel);
        if ($why !== '' && !in_array($rel, $ignore, true)) {
            $found[] = ['/wp-content/uploads' . $rel, $why];
        }
    }

    $http = 0;
    $skipped = '';
    if (lg_bb_sec_gate_selfsafe()) {
        $home = untrailingslashit(home_url());
        foreach (lg_bb_sec_selfscan_targets() as $t) {
            if (time() > $deadline || in_array($t[0], $ignore, true)) {
                continue;
            }
            $url = $home . $t[0] . (strpos($t[0], '?') === false ? '?' : '&') . 'lgbb=' . time();
            $r = wp_remote_get($url, ['timeout' => 6, 'redirection' => 0, 'sslverify' => false, 'user-agent' => 'LG-BlackBox-selfcheck/1', 'limit_response_size' => 262144]);
            if (is_wp_error($r)) {
                continue;
            }
            $http++;
            $why = lg_bb_sec_judge($t[1], (int) wp_remote_retrieve_response_code($r), (string) wp_remote_retrieve_header($r, 'location'), (string) wp_remote_retrieve_body($r));
            if ($why !== '') {
                $found[] = [$t[0], $why];
            }
        }
    } else {
        $skipped = ' (URL requests skipped: the installed gate is older than v9 and could mistake this server for a scanner)';
    }
    lg_bb_sec_write('exposure-last', ['hits' => $found]);
    if ($found) {
        $lines = [];
        foreach (array_slice($found, 0, 30) as $f) {
            $lines[] = '  ' . $f[0] . '  (' . $f[1] . ')';
        }
        lg_bb_alert(
            'exposure-' . substr(md5(json_encode($found)), 0, 10),
            'Publicly reachable files or pages that should not be (' . count($found) . ')',
            "A stranger can see:\n" . implode("\n", $lines) . "\n\nThe list is checked daily; add a path to LG_BB_SEC_IGNORE in wp-config.php if one is intended.",
            'warn'
        );
    }
    lg_bb_sec_job_result('exposure', !$found, $http . ' URLs asked, uploads folder listed, ' . count($found) . ' finding(s)' . $skipped);
}

// ---------------------------------------------------------------- certificate, PHP end of life, updates, DNS

/** Days of security support left for a PHP "major.minor" (negative = already unsupported); null if unknown. */
function lg_bb_sec_php_eol_days($ver, $now = null)
{
    $eol = ['7.4' => '2022-11-28', '8.0' => '2023-11-26', '8.1' => '2025-12-31', '8.2' => '2026-12-31', '8.3' => '2027-12-31', '8.4' => '2028-12-31', '8.5' => '2029-12-31'];
    if (!isset($eol[$ver])) {
        return null;
    }
    $now = $now === null ? time() : (int) $now;
    return (int) floor((strtotime($eol[$ver] . ' 23:59:59 UTC') - $now) / 86400);
}

function lg_bb_sec_cert_days($host)
{
    if (!function_exists('openssl_x509_parse') || $host === '') {
        return null;
    }
    $ctx = stream_context_create(['ssl' => ['capture_peer_cert' => true, 'verify_peer' => false, 'verify_peer_name' => false, 'SNI_enabled' => true, 'peer_name' => $host]]);
    $c = @stream_socket_client('ssl://' . $host . ':443', $en, $es, 6, STREAM_CLIENT_CONNECT, $ctx);
    if (!$c) {
        return null;
    }
    $p = stream_context_get_params($c);
    fclose($c);
    if (empty($p['options']['ssl']['peer_certificate'])) {
        return null;
    }
    $x = openssl_x509_parse($p['options']['ssl']['peer_certificate']);
    return isset($x['validTo_time_t']) ? (int) floor(((int) $x['validTo_time_t'] - time()) / 86400) : null;
}

/** Daily: certificate expiry, PHP support window, pending WordPress/plugin updates, SPF and DMARC. */
function lg_bb_sec_job_health($deadline)
{
    $c = lg_bb_sec_cfg();
    $host = (string) wp_parse_url(home_url(), PHP_URL_HOST);
    $facts = [];

    $days = lg_bb_sec_cert_days($host);
    $facts['cert_days'] = $days;
    if ($days !== null && $days <= (int) $c['cert_days']) {
        lg_bb_alert('cert-expiry', 'The TLS certificate for ' . $host . ' expires in ' . $days . ' days', 'The certificate expires in ' . $days . " days. Visitors get a browser warning after that, and Twilio and QuickBooks webhooks start failing.\nOn Cloudways renew it from the application's SSL Certificate page.", $days <= 5 ? 'crit' : 'warn');
    }

    $ver = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
    $eol = lg_bb_sec_php_eol_days($ver);
    $facts['php'] = $ver;
    $facts['php_eol_days'] = $eol;
    if ($eol !== null && $eol <= 90) {
        lg_bb_alert('php-eol-' . $ver, 'PHP ' . $ver . ($eol < 0 ? ' is no longer supported' : ' loses security support in ' . $eol . ' days'), 'This server runs PHP ' . PHP_VERSION . '. ' . ($eol < 0 ? 'It no longer gets security fixes.' : 'Security fixes stop in ' . $eol . ' days.') . "\nChange the PHP version of the application in the Cloudways panel (Application Settings), after a test on a copy.", $eol < 0 ? 'crit' : 'warn');
    }

    $core = get_site_transient('update_core');
    $core_new = '';
    if (is_object($core) && !empty($core->updates[0]) && isset($core->updates[0]->response, $core->updates[0]->current) && $core->updates[0]->response === 'upgrade') {
        $core_new = (string) $core->updates[0]->current;
    }
    $facts['core_update'] = $core_new;
    $pl = get_site_transient('update_plugins');
    $plugs = [];
    if (is_object($pl) && !empty($pl->response) && is_array($pl->response)) {
        foreach ($pl->response as $file => $o) {
            $plugs[] = dirname($file) . ' -> ' . (isset($o->new_version) ? $o->new_version : '?');
        }
    }
    $facts['plugin_updates'] = $plugs;
    if ($core_new !== '' || $plugs) {
        lg_bb_alert('updates-' . substr(md5($core_new . implode(',', $plugs)), 0, 10), 'Updates are waiting', ($core_new !== '' ? 'WordPress ' . $core_new . " is available (running " . get_bloginfo('version') . ").\n" : '') . ($plugs ? "Plugins:\n  " . implode("\n  ", $plugs) . "\n" : '') . "\nUpdates fix known security holes; apply them after a backup.", 'warn');
    }

    $dns = [];
    if (function_exists('dns_get_record') && time() < $deadline) {
        $apex = preg_replace('/^[^.]+\./', '', $host);
        $has = function ($name, $needle) {
            $r = @dns_get_record($name, DNS_TXT);
            if (is_array($r)) {
                foreach ($r as $x) {
                    if (isset($x['txt']) && stripos($x['txt'], $needle) !== false) {
                        return true;
                    }
                }
            }
            return false;
        };
        if (!$has($host, 'v=spf1') && !($apex !== $host && $has($apex, 'v=spf1'))) {
            $dns[] = 'no SPF record for ' . $host;
        }
        if (!$has('_dmarc.' . $host, 'v=DMARC1') && !($apex !== $host && $has('_dmarc.' . $apex, 'v=DMARC1'))) {
            $dns[] = 'no DMARC record for ' . $host;
        }
    }
    $facts['dns'] = $dns;
    if ($dns) {
        lg_bb_alert('dns-mail-' . substr(md5(implode(',', $dns)), 0, 8), 'Email DNS records missing', "Mail from this site may be rejected or forged without them:\n  " . implode("\n  ", $dns), 'warn');
    }

    $facts['t'] = time();
    lg_bb_sec_write('health-last', $facts);
    lg_bb_sec_job_result('health', ($days === null || $days > (int) $c['cert_days']) && ($eol === null || $eol > 90) && !$dns, 'certificate ' . ($days === null ? 'unknown' : $days . ' days') . ', PHP ' . $ver . ($eol === null ? '' : ' (' . $eol . ' days of support)') . ', ' . count($plugs) . ' plugin update(s)' . ($dns ? ', ' . count($dns) . ' DNS finding(s)' : ''));
}

/** Weekly summary mail so a quiet week is visibly quiet rather than silently broken. */
function lg_bb_sec_job_digest($deadline)
{
    $jobs = lg_bb_sec_read('jobs');
    $al = lg_bb_sec_read('alerts');
    $week = 0;
    foreach ((array) (isset($al['log']) ? $al['log'] : []) as $l) {
        $week += isset($l['t']) && (int) $l['t'] > time() - 7 * 86400 ? 1 : 0;
    }
    $lines = ['Weekly security summary for ' . wp_parse_url(home_url(), PHP_URL_HOST), ''];
    foreach (lg_bb_sec_jobs() as $name => $_) {
        $j = isset($jobs[$name]) ? $jobs[$name] : null;
        $lines[] = sprintf('%-10s %s  %s', $name, $j ? ($j['ok'] ? 'OK  ' : 'CHECK') : 'never run', $j ? $j['summary'] : '');
    }
    $r = lg_bb_rl_cfg();
    $lists = lg_bb_rl_lists();
    $lines[] = '';
    $lines[] = 'Alerts sent or queued in the last 7 days: ' . $week;
    $lines[] = 'Blocked IPs: ' . count($lists['block_all']) . ' site-wide, ' . count(lg_bb_auto_list()) . ' automatic';
    $lines[] = 'Protections: login ' . (!empty($r['enabled']) ? 'on' : 'off') . ', probe shield ' . ($r['probe'] === 'on' ? 'on' : 'off') . ', rate limit ' . (!empty($r['rate']) ? 'on' : 'off')
        . ', under-attack ' . (lg_bb_sec_ua_on() ? 'on' : 'off') . ', 404 flood ' . (lg_bb_sec_flood_on() ? 'on' : 'off') . ', cron guard ' . (!empty($r['cron_guard']) ? 'on' : 'off');
    lg_bb_alert('digest-' . gmdate('oW'), 'Weekly security summary', implode("\n", $lines), 'info');
    lg_bb_sec_job_result('digest', true, 'sent ' . gmdate('Y-m-d'));
}

// ---------------------------------------------------------------- scheduler

function lg_bb_sec_jobs()
{
    return [
        'uploads' => ['every' => 900, 'fn' => 'lg_bb_sec_job_uploads'],
        'integrity' => ['every' => 21600, 'fn' => 'lg_bb_sec_job_integrity'],
        'core' => ['every' => 86400, 'fn' => 'lg_bb_sec_job_core'],
        'exposure' => ['every' => 86400, 'fn' => 'lg_bb_sec_job_exposure'],
        'health' => ['every' => 86400, 'fn' => 'lg_bb_sec_job_health'],
        'digest' => ['every' => 604800, 'fn' => 'lg_bb_sec_job_digest'],
    ];
}

/** Run the most overdue job (one per tick, so a tick stays short). */
function lg_bb_sec_run_due($deadline, $all = false, $max = 1)
{
    $state = lg_bb_sec_read('jobs');
    $now = time();
    $due = [];
    foreach (lg_bb_sec_jobs() as $name => $j) {
        $last = isset($state[$name]['t']) ? (int) $state[$name]['t'] : 0;
        if (isset($state[$name]) && (isset($state[$name]['v']) ? $state[$name]['v'] : '') !== LG_BB_VERSION) {
            $last = 0; // a new plugin version re-runs every check once, so its fixes show at once
        }
        if ($all || $now - $last >= $j['every']) {
            $due[$name] = ($now - $last) / $j['every'];
        }
    }
    if (!$due) {
        return [];
    }
    arsort($due);
    $ran = [];
    foreach (array_keys($due) as $name) {
        $j = lg_bb_sec_jobs();
        try {
            lg_bb_sec_job_result($name, true, 'running'); // claim, so a second tick does not repeat it
            call_user_func($j[$name]['fn'], $deadline);
        } catch (\Throwable $e) {
            lg_bb_sec_job_result($name, false, 'failed: ' . substr($e->getMessage(), 0, 120));
        }
        $ran[] = $name;
        if (!$all && (count($ran) >= $max || time() > $deadline - 5)) {
            break;
        }
    }
    return $ran;
}

// ---------------------------------------------------------------- WordPress security events

function lg_bb_sec_who()
{
    $u = function_exists('wp_get_current_user') ? wp_get_current_user() : null;
    $who = $u && !empty($u->user_login) ? $u->user_login : (defined('WP_CLI') && WP_CLI ? 'WP-CLI / server' : 'nobody signed in');
    return $who . ', IP ' . lg_bb_ip() . (lg_bb_cc() !== '' ? ' (' . lg_bb_cc() . ')' : '');
}

function lg_bb_sec_user_event($uid, $what)
{
    $u = get_userdata((int) $uid);
    if (!$u || !user_can($u, 'manage_options')) {
        return;
    }
    lg_bb_alert('admin-user-' . (int) $uid . '-' . $what, 'Administrator account ' . $what . ': ' . $u->user_login, 'Administrator "' . $u->user_login . '" (id ' . (int) $uid . ', ' . $u->user_email . ') was ' . $what . ".\nDone by: " . lg_bb_sec_who() . "\nIf nobody on your team did this, treat it as a break-in: reset every admin password and check Users.", 'crit');
}

add_action('user_register', function ($uid) {
    lg_bb_sec_user_event($uid, 'created');
});
add_action('set_user_role', function ($uid, $role) {
    if ($role === 'administrator') {
        lg_bb_sec_user_event($uid, 'given the administrator role');
    }
}, 10, 2);
add_action('add_user_role', function ($uid, $role) {
    if ($role === 'administrator') {
        lg_bb_sec_user_event($uid, 'given the administrator role');
    }
}, 10, 2);
add_action('delete_user', function ($uid) {
    lg_bb_sec_user_event($uid, 'deleted');
});

add_action('activated_plugin', function ($p) {
    lg_bb_alert('plugin-on-' . md5($p), 'Plugin activated: ' . $p, 'Plugin "' . $p . '" was activated by ' . lg_bb_sec_who() . '.', 'warn');
});
add_action('deactivated_plugin', function ($p) {
    lg_bb_alert('plugin-off-' . md5($p), 'Plugin deactivated: ' . $p, 'Plugin "' . $p . '" was deactivated by ' . lg_bb_sec_who() . '.', 'warn');
});
add_action('switch_theme', function ($name) {
    lg_bb_alert('theme-' . md5((string) $name), 'Theme switched to ' . $name, 'The active theme changed to "' . $name . '" by ' . lg_bb_sec_who() . '.', 'warn');
});
add_action('upgrader_process_complete', function ($upgrader, $opts) {
    if (is_array($opts) && isset($opts['action'], $opts['type']) && $opts['action'] === 'install') {
        lg_bb_alert('install-' . $opts['type'] . '-' . gmdate('YmdH'), 'A ' . $opts['type'] . ' was installed', 'A new ' . $opts['type'] . ' was installed by ' . lg_bb_sec_who() . '. If this was not you or your developer, treat it as a break-in.', 'warn');
    }
}, 10, 2);
add_action('wp_create_application_password', function ($uid) {
    $u = get_userdata((int) $uid);
    lg_bb_alert('app-pass-' . (int) $uid . '-' . gmdate('YmdH'), 'Application password created', 'An application password was created for ' . ($u ? $u->user_login : 'user ' . (int) $uid) . ' by ' . lg_bb_sec_who() . '. It gives API access without the normal login.', 'warn');
}, 10, 1);

function lg_bb_sec_option_event($opt, $old, $new)
{
    $risky = ['admin_email' => 'warn', 'new_admin_email' => 'warn', 'siteurl' => 'crit', 'home' => 'crit', 'users_can_register' => 'crit', 'default_role' => 'crit'];
    if (!isset($risky[$opt]) || $old === $new) {
        return;
    }
    if ($opt === 'users_can_register' && !(int) $new) {
        return;
    }
    if ($opt === 'default_role' && !in_array($new, ['administrator', 'editor', 'author'], true)) {
        return;
    }
    lg_bb_alert('opt-' . $opt . '-' . substr(md5((string) $new), 0, 8), 'Setting changed: ' . $opt, 'The WordPress setting "' . $opt . '" changed from "' . (is_scalar($old) ? $old : 'array') . '" to "' . (is_scalar($new) ? $new : 'array') . '" by ' . lg_bb_sec_who() . '.', $risky[$opt]);
}
add_action('updated_option', function ($opt, $old, $new) {
    lg_bb_sec_option_event($opt, $old, $new);
}, 10, 3);
add_action('added_option', function ($opt, $val) {
    lg_bb_sec_option_event($opt, null, $val);
}, 10, 2);

/** An administrator signing in from an address never seen for them. The first sign-in is recorded silently. */
add_action('wp_login', function ($login, $user) {
    if (!($user instanceof WP_User) || !user_can($user, 'manage_options')) {
        return;
    }
    $ip = lg_bb_ip();
    if (!is_string($ip) || $ip === '') {
        return;
    }
    $seen = get_user_meta($user->ID, 'lg_bb_admin_ips', true);
    $seen = is_array($seen) ? $seen : [];
    if (in_array($ip, $seen, true)) {
        return;
    }
    $seen[] = $ip;
    update_user_meta($user->ID, 'lg_bb_admin_ips', array_slice($seen, -15));
    if (count($seen) > 1) {
        lg_bb_alert('admin-newip-' . $user->ID . '-' . substr(sha1($ip), 0, 8), 'Administrator signed in from a new address: ' . $user->user_login, 'Administrator "' . $user->user_login . '" signed in from ' . $ip . (lg_bb_cc() !== '' ? ' (' . lg_bb_cc() . ')' : '') . ", an address not seen for this account before.\nIf that was not them, reset the password now.", 'warn');
    }
}, 10, 2);

// ---------------------------------------------------------------- admin

function lg_bb_sec_ago($t)
{
    if (!$t) {
        return 'never';
    }
    $d = time() - (int) $t;
    return $d < 90 ? $d . ' s ago' : ($d < 5400 ? (int) round($d / 60) . ' min ago' : ($d < 172800 ? (int) round($d / 3600) . ' h ago' : (int) round($d / 86400) . ' days ago'));
}

add_action('admin_post_lg_bb_sec', function () {
    lg_bb_admin_guard('lg_bb_sec');
    $op = isset($_REQUEST['op']) ? (string) $_REQUEST['op'] : '';
    $msg = '';
    if ($op === 'save') {
        $c = lg_bb_sec_read('config');
        $to = isset($_POST['alert_to']) ? sanitize_text_field(wp_unslash($_POST['alert_to'])) : '';
        $c['alert_to'] = implode(', ', array_filter(preg_split('/[\s,;]+/', $to), 'is_email'));
        foreach (['flood_limit' => [5, 1000, 40], 'flood_window' => [1, 120, 10], 'forbid_limit' => [5, 500, 15], 'cert_days' => [3, 60, 14]] as $k => $r) {
            $c[$k] = max($r[0], min($r[1], (int) (isset($_POST[$k]) ? $_POST[$k] : $r[2])));
        }
        lg_bb_sec_write('config', $c);
        $msg = 'Alert settings saved.';
    } elseif ($op === 'test') {
        lg_bb_alert('test-' . time(), 'Test alert', "This is a test alert from Black Box.\nIf you can read this, alerts reach " . implode(', ', lg_bb_alert_recipients()) . '.', 'info');
        $n = lg_bb_alert_flush();
        $msg = $n ? 'Test alert sent to ' . implode(', ', lg_bb_alert_recipients()) . '.' : 'The test alert could not be sent (check the recipient and that the site can send mail).';
    } elseif ($op === 'run') {
        $ran = lg_bb_sec_run_due(time() + 40, true);
        lg_bb_alert_flush();
        $msg = 'Checks run: ' . implode(', ', $ran) . '.';
    } elseif ($op === 'ack_mu') {
        $cur = [];
        foreach ((array) glob(WPMU_PLUGIN_DIR . '/*') as $p) {
            if (is_file($p)) {
                $cur[basename($p)] = sha1((string) @file_get_contents($p));
            }
        }
        lg_bb_sec_write('mu-base', ['files' => $cur, 't' => time()]);
        lg_bb_sec_write('mu-diff', ['diff' => []]);
        @unlink(lg_bb_sec_dir() . '/root-base.php'); // the next core check re-records the site-root PHP files
        lg_bb_sec_write('core-last', ['hits' => []]);
        $msg = 'Changes acknowledged: the current mu-plugins and site-root PHP files are the new baseline.';
    }
    wp_safe_redirect(add_query_arg(['page' => 'lg-blackbox', 'lgmsg' => rawurlencode($msg)], admin_url('tools.php')) . '#lg-sec');
    exit;
});

function lg_bb_sec_panel()
{
    $jobs = lg_bb_sec_read('jobs');
    $c = lg_bb_sec_cfg();
    $ticks = lg_bb_sec_read('ticks');
    $t = isset($ticks['t']) ? array_map('intval', (array) $ticks['t']) : [];
    $gap = lg_bb_sec_gap($t);
    $al = lg_bb_sec_read('alerts');
    $log = array_reverse(isset($al['log']) && is_array($al['log']) ? $al['log'] : []);
    $find = [];
    foreach (['uploads-last' => 'Uploads', 'exposure-last' => 'Exposure', 'core-last' => 'Core and plugin files', 'mu-diff' => 'mu-plugins'] as $f => $label) {
        $d = lg_bb_sec_read($f);
        foreach ((array) (isset($d['hits']) ? $d['hits'] : (isset($d['diff']) ? $d['diff'] : [])) as $h) {
            $find[] = [$label, $h[0], $h[1]];
        }
    }
    $fl = lg_bb_sec_read('files');
    $act = function ($op, $label, $class = '') {
        return '<a class="button ' . esc_attr($class) . '" href="' . esc_url(wp_nonce_url(admin_url('admin-post.php?action=lg_bb_sec&op=' . $op), 'lg_bb_sec')) . '">' . esc_html($label) . '</a> ';
    };
    ?>
    <h2 id="lg-sec">Security checks and alerts</h2>
    <p>Alerts go to <strong><?php echo esc_html(implode(', ', lg_bb_alert_recipients()) ?: 'nobody (no valid address)'); ?></strong> by email.
        Cron tick: <strong><?php echo $t ? esc_html(lg_bb_sec_ago(end($t))) : 'not seen yet'; ?></strong><?php echo $gap ? ' (usual gap ' . (int) round($gap / 60) . ' min, alarm after ' . (int) round(lg_bb_sec_stale_limit($gap) / 60) . ' min)' : ''; ?>.
        <?php echo $act('run', 'Run all checks now', 'button-primary'); ?><?php echo $act('test', 'Send a test alert'); ?></p>
    <table class="widefat striped" style="max-width:980px">
        <thead><tr><th style="width:110px">Check</th><th style="width:110px">Last run</th><th style="width:70px">Result</th><th>What it found</th></tr></thead>
        <tbody>
            <?php foreach (lg_bb_sec_jobs() as $name => $j): $r = isset($jobs[$name]) ? $jobs[$name] : null; ?>
                <tr>
                    <td><?php echo esc_html($name); ?><br><small>every <?php echo $j['every'] >= 86400 ? (int) ($j['every'] / 86400) . ' d' : ($j['every'] >= 3600 ? (int) ($j['every'] / 3600) . ' h' : (int) ($j['every'] / 60) . ' min'); ?></small></td>
                    <td><?php echo esc_html($r ? lg_bb_sec_ago($r['t']) : 'never'); ?></td>
                    <td><?php echo $r ? ($r['ok'] ? '<span style="color:#1a7f37">OK</span>' : '<strong style="color:#b32d2e">CHECK</strong>') : '-'; ?></td>
                    <td><?php echo esc_html($r ? $r['summary'] : ''); ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <?php if ($find): ?>
        <h3>Findings right now</h3>
        <table class="widefat striped" style="max-width:980px">
            <thead><tr><th style="width:150px">Area</th><th>Path</th><th>Why</th></tr></thead>
            <tbody>
                <?php foreach (array_slice($find, 0, 60) as $f): ?>
                    <tr><td><?php echo esc_html($f[0]); ?></td><td><code><?php echo esc_html($f[1]); ?></code></td><td><?php echo esc_html($f[2]); ?></td></tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <p><?php echo $act('ack_mu', 'I made these changes'); ?> Marks the current mu-plugins and site-root PHP files as the expected set.</p>
    <?php else: ?>
        <p>No findings at the last run of each check.</p>
    <?php endif; ?>
    <?php if (!empty($fl['changed'])): ?>
        <p><small>New PHP files since the first scan (normally your own deploys): <?php echo esc_html(implode(', ', array_slice($fl['changed'], 0, 12))); ?><?php echo count($fl['changed']) > 12 ? ' ...' : ''; ?></small></p>
    <?php endif; ?>

    <h3>Alert settings</h3>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
        <input type="hidden" name="action" value="lg_bb_sec">
        <input type="hidden" name="op" value="save">
        <?php wp_nonce_field('lg_bb_sec'); ?>
        <p><label>Send alerts to (comma separated, empty = the site admin address)<br>
                <input type="text" name="alert_to" value="<?php echo esc_attr($c['alert_to']); ?>" style="width:420px" placeholder="<?php echo esc_attr(get_option('admin_email')); ?>"></label></p>
        <p>404 flood: <input type="number" name="flood_limit" value="<?php echo (int) $c['flood_limit']; ?>" style="width:70px"> misses in
            <input type="number" name="flood_window" value="<?php echo (int) $c['flood_window']; ?>" style="width:60px"> min;
            refused links/webhooks: <input type="number" name="forbid_limit" value="<?php echo (int) $c['forbid_limit']; ?>" style="width:60px">;
            certificate warning at <input type="number" name="cert_days" value="<?php echo (int) $c['cert_days']; ?>" style="width:60px"> days.
            <button class="button button-primary" type="submit">Save</button></p>
    </form>

    <h3>Recent alerts</h3>
    <?php if (!$log): ?>
        <p>None yet.</p>
    <?php else: ?>
        <table class="widefat striped" style="max-width:980px">
            <thead><tr><th style="width:110px">When</th><th style="width:60px">Level</th><th>Alert</th><th style="width:80px">Mail</th></tr></thead>
            <tbody>
                <?php foreach (array_slice($log, 0, 15) as $l): ?>
                    <tr><td><?php echo lg_bb_t($l['t']); ?></td><td><?php echo esc_html($l['level']); ?></td><td><?php echo esc_html($l['subject']); ?></td><td><?php echo esc_html((string) $l['sent']); ?></td></tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
    <?php
}

/** Text lines for the copy-paste report. */
function lg_bb_sec_report_lines()
{
    $jobs = lg_bb_sec_read('jobs');
    $ticks = lg_bb_sec_read('ticks');
    $t = isset($ticks['t']) ? array_map('intval', (array) $ticks['t']) : [];
    $L = ['== SECURITY CHECKS (alerts to ' . (implode(', ', lg_bb_alert_recipients()) ?: 'nobody') . ') =='];
    $L[] = 'cron tick: ' . ($t ? lg_bb_sec_ago(end($t)) : 'not seen') . ($t && lg_bb_sec_gap($t) ? ', usual gap ' . (int) round(lg_bb_sec_gap($t) / 60) . ' min' : '');
    foreach (lg_bb_sec_jobs() as $name => $_) {
        $j = isset($jobs[$name]) ? $jobs[$name] : null;
        $L[] = $name . ': ' . ($j ? ($j['ok'] ? 'OK' : 'CHECK') . ', ' . lg_bb_sec_ago($j['t']) . ', ' . $j['summary'] : 'never run');
    }
    $L[] = 'under-attack mode: ' . (lg_bb_sec_ua_on() ? 'on' : 'off') . '; 404 flood watch: ' . (lg_bb_sec_flood_on() ? 'on' : 'off');
    return $L;
}
