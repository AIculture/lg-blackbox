<?php
/*
Plugin Name: LG Black Box (server diagnostics, multi-tenant CRM)
Description: Flight recorder and shield for the multi-tenant CRM host. Samples server load, memory, per-process RSS and MariaDB state every ~30 s, logs slow/heavy requests (tagged with the tenant they ran for) and cron hooks, detects database restarts, records every request compactly to spot bot bursts, and can refuse brute-force logins, off-country logins and scanner probes before WordPress loads. Safe to deactivate and delete.
Version: 2.4.2
Author: Les Gouttières
*/

if (!defined('ABSPATH'))
    exit;

define('LG_BB_VERSION', '2.4.2');
define('LG_BB_PROBE', plugin_dir_path(__FILE__) . 'probe.php');
require_once LG_BB_PROBE;
require_once plugin_dir_path(__FILE__) . 'security.php';
require_once plugin_dir_path(__FILE__) . 'hardening.php';
require_once plugin_dir_path(__FILE__) . 'recommended.php';

// Thresholds - override in wp-config.php with define() if too noisy / too quiet.
if (!defined('LG_BB_SLOW_S'))
    define('LG_BB_SLOW_S', 3.0);          // log requests slower than this
if (!defined('LG_BB_HEAVY_MB'))
    define('LG_BB_HEAVY_MB', 96);         // ...or peaking above this PHP memory
if (!defined('LG_BB_MANY_QUERIES'))
    define('LG_BB_MANY_QUERIES', 150);    // ...or running more SQL queries than this
if (!defined('LG_BB_MAX_BYTES'))
    define('LG_BB_MAX_BYTES', 10485760);  // rotate the log at 10 MB (keeps one previous file)

// Opt-in (Tools > LG Black Box): lets WordPress keep every query's timing so heavy
// requests can name their slowest SQL. Costs memory on query-heavy requests.
if (!defined('SAVEQUERIES') && get_option('lg_bb_savequeries')) {
    define('SAVEQUERIES', true);
}

// ---------------------------------------------------------------- time display

/** Every time shown on the page and in the report is Eastern (Toronto), whatever the site timezone is. define('LG_BB_TZ', 'Zone/Name') in wp-config.php to change it. */
function lg_bb_tz()
{
    try {
        return new DateTimeZone(defined('LG_BB_TZ') ? (string) LG_BB_TZ : 'America/Toronto');
    } catch (\Throwable $e) {
        return wp_timezone();
    }
}

function lg_bb_date($format, $t = null)
{
    return wp_date($format, $t === null ? time() : (int) $t, lg_bb_tz());
}

/** "America/Toronto, EST" / "EDT" - the label printed next to times. */
function lg_bb_tz_label()
{
    return lg_bb_tz()->getName() . ', ' . lg_bb_date('T');
}

// ---------------------------------------------------------------- paths

function lg_bb_token()
{
    static $t = null;
    if ($t !== null) {
        return $t;
    }
    $t = get_option('lg_bb_token');
    if (!is_string($t) || strlen($t) < 16) {
        try {
            $t = bin2hex(random_bytes(10));
        } catch (\Throwable $e) {
            $t = substr(md5(uniqid('', true)), 0, 20);
        }
        update_option('lg_bb_token', $t, true);
    }
    return $t;
}

function lg_bb_dir()
{
    static $d = null;
    if ($d !== null) {
        return $d;
    }
    $d = WP_CONTENT_DIR . '/lg-blackbox';
    if (!is_dir($d . '/inflight')) {
        @mkdir($d . '/inflight', 0755, true);
        @file_put_contents($d . '/index.php', "<?php // Silence is golden.\n");
        @file_put_contents($d . '/.htaccess', "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
    }
    return $d;
}

function lg_bb_logfile($rotated = false)
{
    return lg_bb_dir() . '/log-' . lg_bb_token() . ($rotated ? '.1' : '') . '.php';
}

// ---------------------------------------------------------------- request description

function lg_bb_clean($s, $len = 60)
{
    return substr(preg_replace('/[^\w\-\/\.]/', '', (string) $s), 0, $len);
}

/** Path + the few query keys that say WHAT ran. Never the full query string (tokens, phone numbers). */
function lg_bb_label()
{
    if (PHP_SAPI === 'cli') {
        return 'CLI ' . (isset($_SERVER['argv']) ? substr(implode(' ', array_slice($_SERVER['argv'], 0, 4)), 0, 100) : '');
    }
    $u = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '';
    $path = parse_url($u, PHP_URL_PATH);
    $out = is_string($path) ? substr($path, 0, 120) : substr($u, 0, 120);
    $extra = [];
    foreach (['action', 'rest_route', 'page'] as $k) {
        if (isset($_REQUEST[$k]) && is_scalar($_REQUEST[$k])) {
            $extra[] = $k . '=' . lg_bb_clean($_REQUEST[$k]);
        }
    }
    return $extra ? $out . '?' . implode('&', $extra) : $out;
}

/**
 * Is the TCP peer (REMOTE_ADDR) a proxy whose forwarded headers may be believed? Same rule as the CRM's own
 * CRM_Rate_Limit::client_ip(): loopback / private addresses (nginx or Varnish on the same box), or an address
 * or CIDR listed in the LG_CRM_TRUSTED_PROXIES constant (array or comma separated string; Cloudflare's ranges
 * when PHP sees them as the peer). Anyone can send CF-Connecting-IP / X-Forwarded-For / CF-IPCountry, so
 * believing them from an untrusted peer lets an attacker pick the IP that gets blocked, or dodge a block.
 */
function lg_bb_peer_trusted($peer)
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
        if ($rem === 0 || (ord($pb[$bytes]) & ((0xFF << (8 - $rem)) & 0xFF)) === (ord($nb[$bytes]) & ((0xFF << (8 - $rem)) & 0xFF))) {
            return true;
        }
    }
    return false;
}

/** Visitor IP: the forwarded header when the peer is a trusted proxy, otherwise the peer itself. */
function lg_bb_ip()
{
    $peer = isset($_SERVER['REMOTE_ADDR']) ? trim((string) $_SERVER['REMOTE_ADDR']) : '';
    if (lg_bb_peer_trusted($peer)) {
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR'] as $k) {
            if (!empty($_SERVER[$k])) {
                $ip = trim(explode(',', (string) $_SERVER[$k])[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
    }
    return filter_var($peer, FILTER_VALIDATE_IP) ? $peer : '';
}

/** What the page shows next to "your IP": the peer, whether it is trusted, and forwarded headers that were ignored. */
function lg_bb_ip_diag()
{
    $peer = isset($_SERVER['REMOTE_ADDR']) ? trim((string) $_SERVER['REMOTE_ADDR']) : '';
    $trusted = lg_bb_peer_trusted($peer);
    $fwd = false;
    foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR'] as $k) {
        if (!empty($_SERVER[$k])) {
            $h = trim(explode(',', (string) $_SERVER[$k])[0]);
            if (filter_var($h, FILTER_VALIDATE_IP) && $h !== $peer) {
                $fwd = true; // names a different address than the peer: a real proxy hop we are not believing
            }
        }
    }
    return ['peer' => $peer, 'trusted' => $trusted, 'ignored' => $fwd && !$trusted];
}

/** Visitor country as reported by Cloudflare (CF-IPCountry): 2 letters, XX = unknown, T1 = Tor, '' = header absent or not believable. */
function lg_bb_cc()
{
    $peer = isset($_SERVER['REMOTE_ADDR']) ? trim((string) $_SERVER['REMOTE_ADDR']) : '';
    if (!lg_bb_peer_trusted($peer)) {
        return '';
    }
    $c = isset($_SERVER['HTTP_CF_IPCOUNTRY']) ? strtoupper(trim((string) $_SERVER['HTTP_CF_IPCOUNTRY'])) : '';
    return preg_match('/^[A-Z0-9]{2}$/', $c) ? $c : '';
}

/** True when the code is a real country (not absent / unknown / Tor): the only case the filter may act on. */
function lg_bb_cc_known($cc)
{
    return (bool) preg_match('/^[A-Z]{2}$/', (string) $cc) && $cc !== 'XX';
}

function lg_bb_cc_name($cc)
{
    static $n = [
        'CA' => 'Canada', 'US' => 'United States', 'MX' => 'Mexico', 'GB' => 'United Kingdom', 'FR' => 'France', 'DE' => 'Germany',
        'ES' => 'Spain', 'IT' => 'Italy', 'NL' => 'Netherlands', 'BE' => 'Belgium', 'CH' => 'Switzerland', 'IE' => 'Ireland',
        'PT' => 'Portugal', 'SE' => 'Sweden', 'NO' => 'Norway', 'FI' => 'Finland', 'DK' => 'Denmark', 'PL' => 'Poland',
        'RO' => 'Romania', 'UA' => 'Ukraine', 'RU' => 'Russia', 'TR' => 'Turkey', 'IL' => 'Israel', 'AE' => 'UAE', 'SA' => 'Saudi Arabia',
        'IN' => 'India', 'PK' => 'Pakistan', 'BD' => 'Bangladesh', 'ID' => 'Indonesia', 'SG' => 'Singapore', 'HK' => 'Hong Kong',
        'CN' => 'China', 'JP' => 'Japan', 'KR' => 'South Korea', 'VN' => 'Vietnam', 'TH' => 'Thailand', 'PH' => 'Philippines',
        'MY' => 'Malaysia', 'TW' => 'Taiwan', 'AU' => 'Australia', 'NZ' => 'New Zealand', 'BR' => 'Brazil', 'AR' => 'Argentina',
        'CL' => 'Chile', 'CO' => 'Colombia', 'ZA' => 'South Africa', 'NG' => 'Nigeria', 'EG' => 'Egypt', 'MA' => 'Morocco',
        'DZ' => 'Algeria', 'TN' => 'Tunisia', 'HT' => 'Haiti', 'LT' => 'Lithuania', 'LV' => 'Latvia', 'EE' => 'Estonia',
        'BG' => 'Bulgaria', 'CZ' => 'Czechia', 'AT' => 'Austria', 'GR' => 'Greece', 'HU' => 'Hungary', 'XX' => 'unknown', 'T1' => 'Tor',
    ];
    return isset($n[$cc]) ? $n[$cc] : '';
}

/** "SG Singapore" / "SG" / "-" for display. */
function lg_bb_cc_label($cc)
{
    if ($cc === '' || $cc === null) {
        return '-';
    }
    $n = lg_bb_cc_name($cc);
    return $n !== '' ? $cc . ' ' . $n : $cc;
}

/** IPv4 as is; IPv6 reduced to its /48 (crawlers rotate inside a /64): "2a03:2880:f812::/48". */
function lg_bb_ip_group($ip)
{
    $ip = (string) $ip;
    if (strpos($ip, ':') === false) {
        return $ip === '' ? '?' : $ip;
    }
    $bin = @inet_pton($ip);
    if ($bin === false || strlen($bin) !== 16) {
        return substr($ip, 0, 20);
    }
    return implode(':', str_split(bin2hex(substr($bin, 0, 6)), 4)) . '::/48';
}

/** A bot name when one is recognisable, otherwise the first characters of the user agent. */
function lg_bb_ua_short($ua)
{
    $ua = (string) $ua;
    if (preg_match('/\b(FBAN|FBAV|FB_IAB|FBIOS)\b/', $ua)) {
        return 'facebook-app'; // Facebook / Instagram in-app browser: a visitor who tapped an ad or a post
    }
    if (stripos($ua, 'instagram') !== false) {
        return 'instagram-app';
    }
    if (preg_match('/(facebookexternalhit|meta-externalagent|semrushbot|ahrefsbot|bytespider|gptbot|claudebot|petalbot|yandex|bingbot|googlebot|applebot|mj12bot|dotbot|amazonbot|python-requests|curl|go-http-client|wordpress)/i', $ua, $m)) {
        return strtolower($m[1]);
    }
    return $ua === '' ? '-' : substr($ua, 0, 24);
}

// ---------------------------------------------------------------- tenants (multi-tenant CRM)

/** Tenant id the CRM resolved for THIS request (JWT, webhook slug, signed link), or 0 when none was set. */
function lg_bb_current_tenant()
{
    if (!class_exists('CRM_Context')) {
        return 0;
    }
    try {
        return (int) CRM_Context::tenant_id_or_throw();
    } catch (\Throwable $e) {
        return 0; // not set: the request never identified a tenant (anonymous, login, static)
    }
}

/**
 * "12 Confort CB" for a tenant id, "slug (Name)" for a slug. Falls back to the bare id / slug when the CRM plugin
 * is not loaded or the tenant is gone, so the report always prints something.
 */
function lg_bb_tenant_label($key)
{
    static $cache = [];
    $key = (string) $key;
    if (isset($cache[$key])) {
        return $cache[$key];
    }
    $label = $key;
    if (class_exists('CRM_Repo_Tenants')) {
        try {
            if (ctype_digit($key)) {
                $t = CRM_Repo_Tenants::get((int) $key);
                $label = is_array($t) && !empty($t['name']) ? $key . ' ' . trim(preg_replace('/[|\s]+/', ' ', (string) $t['name'])) : 'tenant ' . $key;
            } else {
                $t = CRM_Repo_Tenants::get_by_slug($key);
                $label = is_array($t) && !empty($t['name']) ? $key . ' (' . trim(preg_replace('/[|\s]+/', ' ', (string) $t['name'])) . ')' : $key;
            }
        } catch (\Throwable $e) {
            // the lookup must never break the page or the report
        }
    } elseif (ctype_digit($key)) {
        $label = 'tenant ' . $key;
    }
    return $cache[$key] = $label;
}

// ---------------------------------------------------------------- burst recorder
//
// One tiny line per request that reaches WordPress, written when the request STARTS (so a request
// that is later killed is still there): who (IP, country, client type), what (path with long ids
// masked, the NAMES of query parameters, never their values) and where from (referring host).
// The slow-request log only sees requests that were already slow; this one shows the quiet start
// of a burst and which clients made it. Rolling file, ~8 MB total (two files of 4 MB; define('LG_BB_REC_MAX', bytes)
// in wp-config.php for a longer memory, the CRM's own polling fills it quickly on a busy day).
//
// Multi-tenant: 'a' = the request carried a Bearer token on a CRM API path (a logged-in CRM user or app, not an
// anonymous bot; the token is NOT checked, this only separates polling from the rest), 'tn' = the tenant slug when
// the path names one (/lg-crm/v1/t/{slug}/..., the Twilio / receipt webhooks).

if (!defined('LG_BB_REC_MAX')) {
    define('LG_BB_REC_MAX', 4194304);
}

function lg_bb_rec_file($rotated = false)
{
    return lg_bb_dir() . '/rec-' . lg_bb_token() . ($rotated ? '.1' : '') . '.php';
}

function lg_bb_rec_on()
{
    return (string) get_option('lg_bb_recorder', '1') !== '0';
}

function lg_bb_rec_append($row)
{
    $json = @json_encode($row, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    if (!is_string($json)) {
        return;
    }
    $file = lg_bb_rec_file();
    $size = @filesize($file);
    if ($size === false) {
        $json = "<?php http_response_code(404); exit; ?>\n" . $json;
    } elseif ($size > LG_BB_REC_MAX) {
        @rename($file, lg_bb_rec_file(true));
        $json = "<?php http_response_code(404); exit; ?>\n" . $json;
    }
    // No LOCK_EX: a short line appended with O_APPEND is written atomically, and 40 workers must not queue on a lock.
    @file_put_contents($file, $json . "\n", FILE_APPEND);
}

function lg_bb_rec_start()
{
    if (!lg_bb_rec_on() || !isset($_SERVER['REQUEST_URI'])) {
        return;
    }
    $uri = (string) $_SERVER['REQUEST_URI'];
    $path = parse_url($uri, PHP_URL_PATH);
    $path = is_string($path) ? preg_replace('#/[A-Za-z0-9_\-]{20,}#', '/{id}', $path) : ''; // quote/lead tokens are not diagnostics
    $row = ['t' => time(), 'ip' => lg_bb_ip()];
    $cc = lg_bb_cc();
    if ($cc !== '') {
        $row['cc'] = $cc;
    }
    $row['ua'] = lg_bb_ua_short(isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '');
    $row['m'] = isset($_SERVER['REQUEST_METHOD']) ? substr((string) $_SERVER['REQUEST_METHOD'], 0, 1) : '?';
    $row['p'] = substr($path, 0, 90);
    $route = $path . ' ' . (isset($_GET['rest_route']) && is_string($_GET['rest_route']) ? $_GET['rest_route'] : '');
    if (preg_match('#/lg-crm/v1/t/([a-z0-9_-]{1,32})/#i', $route, $tm)) {
        $row['tn'] = strtolower($tm[1]);
    }
    $bearer = !empty($_SERVER['HTTP_AUTHORIZATION']) ? (string) $_SERVER['HTTP_AUTHORIZATION'] : (!empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) ? (string) $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] : '');
    if ($bearer !== '' && stripos($bearer, 'bearer ') === 0 && strpos($route, '/lg-crm/v1/') !== false && strpos($route, '/auth/') === false) {
        $row['a'] = 1;
    }
    $q = parse_url($uri, PHP_URL_QUERY);
    if (is_string($q) && $q !== '' && preg_match_all('/(?:^|&)([^=&]{1,24})/', $q, $m)) {
        $keys = [];
        foreach (array_slice(array_unique($m[1]), 0, 6) as $k) {
            $keys[] = preg_replace('/[^\w\-\.\[\]]/', '', $k);
        }
        $row['q'] = implode(',', array_filter($keys));
    }
    if (!empty($_SERVER['HTTP_REFERER'])) {
        $h = parse_url((string) $_SERVER['HTTP_REFERER'], PHP_URL_HOST);
        if (is_string($h) && $h !== '') {
            $row['r'] = substr(strtolower($h), 0, 40);
        }
    }
    lg_bb_rec_append($row);
}

/** Streams the recorder files once and aggregates: per minute, per client, query-parameter names. */
function lg_bb_rec_summary($hours)
{
    static $cache = [];
    $key = (int) $hours;
    if (isset($cache[$key])) {
        return $cache[$key];
    }
    $since = time() - $hours * 3600;
    $S = ['n' => 0, 't0' => 0, 't1' => 0, 'min' => [], 'cl' => [], 'qk' => [], 'ad' => 0, 'fb' => 0, 'ty' => [], 'au' => 0, 'tn' => []];
    foreach ([lg_bb_rec_file(true), lg_bb_rec_file()] as $file) {
        $h = @fopen($file, 'r');
        if (!$h) {
            continue;
        }
        while (($line = fgets($h)) !== false) {
            if ($line[0] !== '{') {
                continue;
            }
            $r = json_decode($line, true);
            if (!is_array($r) || !isset($r['t'], $r['ip']) || $r['t'] < $since) {
                continue;
            }
            $t = (int) $r['t'];
            $ua = isset($r['ua']) ? (string) $r['ua'] : '-';
            $g = lg_bb_ip_group($r['ip']) . ' ' . $ua;
            $q = isset($r['q']) ? (string) $r['q'] : '';
            $rf = isset($r['r']) ? (string) $r['r'] : '';
            $p = isset($r['p']) ? (string) $r['p'] : '';
            // "Ad click" = carries an ad-tracking parameter. Each such URL is unique, so a page cache keyed on the full URL misses every time.
            $ad = $q !== '' && preg_match('/(^|,)(fbclid|gclid|msclkid|ttclid|utm_[a-z]+)(,|$)/i', $q) ? 1 : 0;
            $fb = ($ua === 'facebook-app' || $ua === 'instagram-app' || $ua === 'facebookexternalhit' || $ua === 'meta-externalagent'
                || ($rf !== '' && preg_match('/(^|\.)(facebook\.com|instagram\.com|fb\.com|fb\.me)$/', $rf))) ? 1 : 0;

            $S['n']++;
            $S['t0'] = $S['t0'] ? min($S['t0'], $t) : $t;
            $S['t1'] = max($S['t1'], $t);
            $S['ad'] += $ad;
            $S['fb'] += $fb;
            $S['au'] += !empty($r['a']) ? 1 : 0;
            if (!empty($r['tn'])) {
                $tk = (string) $r['tn'];
                if (isset($S['tn'][$tk]) || count($S['tn']) < 200) {
                    $S['tn'][$tk] = (isset($S['tn'][$tk]) ? $S['tn'][$tk] : 0) + 1;
                }
            }
            // Client TYPE roll-up: ad clickers arrive from thousands of different IPs, so per-IP rows hide them.
            if (isset($S['ty'][$ua]) || count($S['ty']) < 200) {
                if (!isset($S['ty'][$ua])) {
                    $S['ty'][$ua] = ['n' => 0, 'ip' => [], 'ad' => 0];
                }
                $S['ty'][$ua]['n']++;
                $S['ty'][$ua]['ad'] += $ad;
                if (isset($S['ty'][$ua]['ip'][$r['ip']]) || count($S['ty'][$ua]['ip']) < 5000) {
                    $S['ty'][$ua]['ip'][$r['ip']] = 1;
                }
            }
            if ($q !== '') {
                foreach (explode(',', strtolower($q)) as $k) {
                    if (isset($S['qk'][$k]) || count($S['qk']) < 300) {
                        $S['qk'][$k] = (isset($S['qk'][$k]) ? $S['qk'][$k] : 0) + 1;
                    }
                }
            }
            $mk = (int) floor($t / 60) * 60;
            if (!isset($S['min'][$mk])) {
                $S['min'][$mk] = ['n' => 0, 'ip' => [], 'ad' => 0, 'fb' => 0, 'by' => [], 'pa' => []];
            }
            $M = &$S['min'][$mk];
            $M['n']++;
            $M['ad'] += $ad;
            $M['fb'] += $fb;
            if (isset($M['ip'][$r['ip']]) || count($M['ip']) < 500) {
                $M['ip'][$r['ip']] = 1;
            }
            if (isset($M['by'][$g]) || count($M['by']) < 60) {
                $M['by'][$g] = (isset($M['by'][$g]) ? $M['by'][$g] : 0) + 1;
            }
            if (isset($M['pa'][$p]) || count($M['pa']) < 60) {
                $M['pa'][$p] = (isset($M['pa'][$p]) ? $M['pa'][$p] : 0) + 1;
            }
            unset($M);
            if (isset($S['cl'][$g]) || count($S['cl']) < 3000) {
                if (!isset($S['cl'][$g])) {
                    $S['cl'][$g] = ['n' => 0, 't0' => $t, 't1' => $t, 'ad' => 0, 'fb' => 0, 'pa' => []];
                }
                $C = &$S['cl'][$g];
                $C['n']++;
                $C['t0'] = min($C['t0'], $t);
                $C['t1'] = max($C['t1'], $t);
                $C['ad'] += $ad;
                $C['fb'] += $fb;
                if (isset($C['pa'][$p]) || count($C['pa']) < 40) {
                    $C['pa'][$p] = (isset($C['pa'][$p]) ? $C['pa'][$p] : 0) + 1;
                }
                unset($C);
            }
        }
        fclose($h);
    }
    return $cache[$key] = $S;
}

function lg_bb_rec_top($map, $n)
{
    arsort($map);
    return array_slice($map, 0, $n, true);
}

/** "01:13 | requests | distinct IPs | ad clicks | from Facebook | top clients | top paths" */
function lg_bb_rec_min_line($mk, $M)
{
    $by = [];
    foreach (lg_bb_rec_top($M['by'], 3) as $g => $c) {
        $by[] = $g . ' x' . $c;
    }
    $pa = [];
    foreach (lg_bb_rec_top($M['pa'], 3) as $p => $c) {
        $pa[] = substr($p === '' ? '(none)' : $p, 0, 40) . ' x' . $c;
    }
    return lg_bb_date('H:i', $mk) . ' | ' . $M['n'] . ' | ' . count($M['ip']) . ' | ' . $M['ad'] . ' | ' . $M['fb'] . ' | ' . implode('; ', $by) . ' | ' . implode('; ', $pa);
}

/** Report lines: coverage, query parameters, top clients, busiest minutes, and the minutes before each incident. */
function lg_bb_rec_report($hours, $inc)
{
    $S = lg_bb_rec_summary($hours);
    $L = [''];
    if (!lg_bb_rec_on() && !$S['n']) {
        $L[] = '== BURST RECORDER: OFF (no data) ==';
        return $L;
    }
    if (!$S['n']) {
        $L[] = '== BURST RECORDER: no requests recorded in this window (just installed, or the log was cleared) ==';
        return $L;
    }
    $span = max(1, ($S['t1'] - $S['t0']) / 60);
    $L[] = '== ALL PHP REQUESTS (burst recorder' . (lg_bb_rec_on() ? '' : ', now OFF') . '): ' . lg_bb_date('m-d H:i', $S['t0']) . ' -> ' . lg_bb_date('m-d H:i', $S['t1']) . ', ' . $S['n'] . ' requests (avg ' . round($S['n'] / $span, 1) . '/min), '
        . $S['ad'] . ' with ad-click parameters (fbclid/gclid/utm_*), ' . $S['fb'] . ' from Facebook/Instagram/Meta, '
        . $S['au'] . ' (' . round($S['au'] * 100 / $S['n']) . '%) CRM API calls carrying a Bearer token (logged-in app traffic, the rest is anonymous) ==';
    if ($S['tn']) {
        $tn = [];
        foreach (lg_bb_rec_top($S['tn'], 8) as $k => $c) {
            $tn[] = lg_bb_tenant_label($k) . ' x' . $c;
        }
        $L[] = 'tenant webhook traffic (paths /lg-crm/v1/t/{slug}/...): ' . implode(', ', $tn);
    }
    $qk = [];
    foreach (lg_bb_rec_top($S['qk'], 8) as $k => $c) {
        $qk[] = $k . ' x' . $c;
    }
    $L[] = 'query parameter names seen: ' . ($qk ? implode(', ', $qk) : 'none');
    uasort($S['ty'], function ($a, $b) {
        return $b['n'] - $a['n'];
    });
    $ty = [];
    foreach (array_slice($S['ty'], 0, 8, true) as $name => $v) {
        $ty[] = $name . ' ' . $v['n'] . ' req/' . count($v['ip']) . ' IPs' . ($v['ad'] ? '/' . $v['ad'] . ' ad-click' : '');
    }
    $L[] = 'client types: ' . implode('; ', $ty);

    uasort($S['cl'], function ($a, $b) {
        return $b['n'] - $a['n'];
    });
    $L[] = 'client | requests | share | first-last | ad-click | from FB | distinct paths | top path';
    foreach (array_slice($S['cl'], 0, 10, true) as $g => $c) {
        $tp = lg_bb_rec_top($c['pa'], 1);
        $L[] = $g . ' | ' . $c['n'] . ' | ' . round($c['n'] * 100 / $S['n']) . '% | ' . lg_bb_date('H:i', $c['t0']) . '-' . lg_bb_date('H:i', $c['t1']) . ' | ' . $c['ad'] . ' | ' . $c['fb'] . ' | ' . count($c['pa']) . (count($c['pa']) >= 40 ? '+' : '') . ' | ' . substr((string) key($tp), 0, 40);
    }

    $mins = $S['min'];
    uasort($mins, function ($a, $b) {
        return $b['n'] - $a['n'];
    });
    $top = array_slice($mins, 0, 12, true);
    ksort($top);
    $L[] = '';
    $L[] = 'BUSIEST MINUTES: minute | requests | distinct IPs | ad-click | from FB | top clients | top paths';
    foreach ($top as $mk => $M) {
        $L[] = lg_bb_rec_min_line($mk, $M);
    }

    $last = 0;
    foreach ($inc as $i) {
        if ($i['t'] - $last < 600 && $last) {
            continue;
        }
        $last = $i['t'];
        $win = [];
        foreach ($S['min'] as $mk => $M) {
            if ($mk >= $i['t'] - 1500 && $mk <= $i['t'] + 60) {
                $win[$mk] = $M;
            }
        }
        $L[] = '';
        $L[] = 'BEFORE INCIDENT ' . lg_bb_date('m-d H:i:s', $i['t']) . ' (' . substr($i['what'], 0, 60) . '), busiest minutes in the 25 min before:';
        if (!$win) {
            $L[] = '  no requests recorded in that window';
            continue;
        }
        uasort($win, function ($a, $b) {
            return $b['n'] - $a['n'];
        });
        $win = array_slice($win, 0, 5, true);
        ksort($win);
        foreach ($win as $mk => $M) {
            $L[] = '  ' . lg_bb_rec_min_line($mk, $M);
        }
    }
    return $L;
}

function lg_bb_mask_sql($sql, $len = 220)
{
    $sql = preg_replace("/'(?:[^'\\\\]|\\\\.)*'/s", "'?'", (string) $sql); // string literals may hold client data
    $sql = preg_replace('/\s+/', ' ', $sql);
    return substr($sql, 0, $len);
}

function lg_bb_cpu_ms($ru0)
{
    if (!$ru0 || !function_exists('getrusage')) {
        return 0;
    }
    $ru = getrusage();
    $f = function ($r) {
        return ($r['ru_utime.tv_sec'] + $r['ru_stime.tv_sec']) * 1000 + ($r['ru_utime.tv_usec'] + $r['ru_stime.tv_usec']) / 1000;
    };
    return (int) round(max(0, $f($ru) - $f($ru0)));
}

// ---------------------------------------------------------------- per-request tracking

$GLOBALS['lg_bb'] = [
    'ru0' => function_exists('getrusage') ? getrusage() : null,
    'start' => isset($_SERVER['REQUEST_TIME_FLOAT']) ? (float) $_SERVER['REQUEST_TIME_FLOAT'] : microtime(true),
    't0' => microtime(true),
    'marker' => null,
    'label' => '',
    'cron' => [],
    'cron_t' => [],
    'cron_m' => [],
    'cron_slow' => false,
];

// "In flight" marker: a tiny file that exists while a request runs. A request that
// is killed by the host (OOM killer, FPM terminate timeout) never reaches shutdown,
// so its marker is left behind - that is how killed requests are found afterwards.
if (PHP_SAPI !== 'cli') {
    $lg_bb_label = lg_bb_label();
    $GLOBALS['lg_bb']['label'] = $lg_bb_label;
    $lg_bb_marker = lg_bb_dir() . '/inflight/' . getmypid() . '-' . substr(md5(uniqid('', true)), 0, 8) . '.php';
    if (@file_put_contents($lg_bb_marker, '<?php exit;?>' . json_encode(['uri' => $lg_bb_label, 'ip' => lg_bb_ip()]))) {
        $GLOBALS['lg_bb']['marker'] = $lg_bb_marker;
    }
    unset($lg_bb_label, $lg_bb_marker);
    try {
        lg_bb_rec_start();
    } catch (\Throwable $e) {
        // the recorder must never break a request
    }
} else {
    $GLOBALS['lg_bb']['label'] = lg_bb_label();
}
register_shutdown_function('lg_bb_shutdown');

// Fires for wp-login.php and xmlrpc.php credential failures (wrong or empty username/password).
add_action('wp_login_failed', function () {
    $GLOBALS['lg_bb']['login_failed'] = true;
});

/** WP-Cron: time every due hook, so a slow/heavy cron job is named instead of "wp-cron.php". */
add_action('init', function () {
    if (!(defined('DOING_CRON') && DOING_CRON) || !function_exists('_get_cron_array')) {
        return;
    }
    $crons = _get_cron_array();
    if (!is_array($crons)) {
        return;
    }
    $hooks = [];
    $now = time();
    foreach ($crons as $ts => $list) {
        if ($ts > $now) {
            break;
        }
        if (is_array($list)) {
            foreach ($list as $h => $_) {
                $hooks[$h] = true;
            }
        }
    }
    foreach (array_slice(array_keys($hooks), 0, 40) as $h) {
        add_action($h, function () use ($h) {
            $GLOBALS['lg_bb']['cron_t'][$h] = microtime(true);
            $GLOBALS['lg_bb']['cron_m'][$h] = memory_get_usage(true);
        }, PHP_INT_MIN, 0);
        add_action($h, function () use ($h) {
            $b = &$GLOBALS['lg_bb'];
            if (!isset($b['cron_t'][$h])) {
                return;
            }
            $ms = (microtime(true) - $b['cron_t'][$h]) * 1000;
            $b['cron'][] = [$h, (int) round($ms), round((memory_get_usage(true) - $b['cron_m'][$h]) / 1048576, 1)];
            if ($ms >= 2000) {
                $b['cron_slow'] = true;
            }
        }, PHP_INT_MAX, 0);
    }
}, 1);

function lg_bb_shutdown()
{
    $b = $GLOBALS['lg_bb'];
    if (!empty($b['marker'])) {
        @unlink($b['marker']);
    }

    // Login attempts are fast, so the slow-request log never sees a brute-force run.
    // Count them separately (tiny rows, own file); the heartbeat summarises the last 10 min.
    if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST' && preg_match('#(wp-login\.php|xmlrpc\.php|auth/login)#', $b['label'], $am)) {
        $st = (int) http_response_code();
        $failed = !empty($b['login_failed']) || ($am[1] === 'auth/login' && $st === 401);
        $aip = lg_bb_ip();
        lg_bb_append(lg_bb_dir() . '/auth-' . lg_bb_token() . '.php', ['t' => time(), 'ip' => $aip, 'cc' => lg_bb_cc(), 'k' => $am[1], 'st' => $st, 'f' => $failed ? 1 : 0], 1048576);
        if ($failed) {
            lg_bb_rl_record_failure($aip);
        }
    }

    $dur = (microtime(true) - $b['start']) * 1000;
    $peak = memory_get_peak_usage(true) / 1048576;
    $cpu = lg_bb_cpu_ms($b['ru0']);
    $q = function_exists('get_num_queries') ? get_num_queries() : 0;

    $fatal = null;
    $e = error_get_last();
    if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_RECOVERABLE_ERROR], true)) {
        $fatal = substr($e['message'], 0, 200) . ' @' . basename($e['file']) . ':' . $e['line'];
    }

    $why = [];
    if ($dur >= LG_BB_SLOW_S * 1000) {
        $why[] = 'slow';
    }
    if ($peak >= LG_BB_HEAVY_MB) {
        $why[] = 'mem';
    }
    if ($q >= LG_BB_MANY_QUERIES) {
        $why[] = 'queries';
    }
    if ($cpu >= 2000) {
        $why[] = 'cpu';
    }
    if ($b['cron_slow']) {
        $why[] = 'cron';
    }
    if ($fatal) {
        $why[] = 'fatal';
    }

    if ($why) {
        $row = [
            'k' => 'req',
            't' => (int) $b['start'],
            'why' => implode(',', $why),
            'uri' => $b['label'],
            'm' => isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : PHP_SAPI,
            'st' => function_exists('http_response_code') ? (int) http_response_code() : 0,
            'ms' => (int) round($dur),
            'boot' => (int) round(($b['t0'] - $b['start']) * 1000),
            'cpu' => $cpu,
            'peak' => (int) round($peak),
            'q' => $q,
            'ip' => lg_bb_ip(),
            'ua' => isset($_SERVER['HTTP_USER_AGENT']) ? substr((string) $_SERVER['HTTP_USER_AGENT'], 0, 80) : '',
            'u' => function_exists('get_current_user_id') ? get_current_user_id() : 0,
        ];
        $tn = lg_bb_current_tenant();
        if ($tn > 0) {
            $row['tn'] = $tn;
        }
        if ($b['cron']) {
            $row['cron'] = $b['cron'];
        }
        if ($fatal) {
            $row['fatal'] = $fatal;
        }
        global $wpdb;
        if (defined('SAVEQUERIES') && SAVEQUERIES && isset($wpdb->queries) && is_array($wpdb->queries)) {
            $qs = $wpdb->queries;
            usort($qs, function ($x, $y) {
                return $y[1] <=> $x[1];
            });
            $row['sq'] = [];
            foreach (array_slice($qs, 0, 3) as $x) {
                $row['sq'][] = [(int) round($x[1] * 1000), substr((string) $x[2], -150), lg_bb_mask_sql($x[0])];
            }
        }
        lg_bb_append(lg_bb_logfile(), $row, LG_BB_MAX_BYTES);
    }

    lg_bb_maybe_heartbeat();
}

// ---------------------------------------------------------------- heartbeat

function lg_bb_maybe_heartbeat($force = false)
{
    $stamp = lg_bb_dir() . '/hb.stamp';
    clearstatcache(true, $stamp);
    $age = is_file($stamp) ? time() - (int) @filemtime($stamp) : 9999;
    $la = function_exists('sys_getloadavg') ? @sys_getloadavg() : false;
    $interval = (is_array($la) && $la[0] > 4) ? 10 : 30; // sample faster while the box is struggling
    if (!$force && $age < $interval) {
        return;
    }
    @touch($stamp); // claim the slot before doing the work
    try {
        lg_bb_heartbeat();
    } catch (\Throwable $e) {
        // diagnostics must never break a request
    }
}

function lg_bb_heartbeat()
{
    global $wpdb;
    $row = ['k' => 'hb', 't' => time()];
    $row += lg_bb_sys();
    $p = lg_bb_procs(6, lg_bb_dir() . '/cpu.snap.json');
    if ($p) {
        $row['p'] = $p;
    }
    $row['inf'] = lg_bb_inflight_scan();
    $au = lg_bb_auth_summary();
    if ($au) {
        $row['auth'] = $au;
    }

    $db = ['ok' => 0];
    $busy = isset($row['load'][0], $row['cpus']) && $row['cpus'] > 0 && $row['load'][0] > 1.5 * $row['cpus'];
    if (isset($wpdb) && is_object($wpdb)) {
        $prev = $wpdb->suppress_errors(true);
        $st = $wpdb->get_results("SHOW GLOBAL STATUS WHERE Variable_name IN ('Uptime','Threads_connected','Threads_running','Max_used_connections','Slow_queries','Created_tmp_disk_tables','Innodb_row_lock_current_waits','Aborted_connects')", ARRAY_N);
        if (is_array($st) && $st) {
            $m = [];
            foreach ($st as $r) {
                $m[$r[0]] = (int) $r[1];
            }
            $db = [
                'ok' => 1,
                'up' => isset($m['Uptime']) ? $m['Uptime'] : 0,
                'conn' => isset($m['Threads_connected']) ? $m['Threads_connected'] : 0,
                'run' => isset($m['Threads_running']) ? $m['Threads_running'] : 0,
                'maxu' => isset($m['Max_used_connections']) ? $m['Max_used_connections'] : 0,
                'slow' => isset($m['Slow_queries']) ? $m['Slow_queries'] : 0,
                'tmpd' => isset($m['Created_tmp_disk_tables']) ? $m['Created_tmp_disk_tables'] : 0,
                'lockw' => isset($m['Innodb_row_lock_current_waits']) ? $m['Innodb_row_lock_current_waits'] : 0,
                'abort' => isset($m['Aborted_connects']) ? $m['Aborted_connects'] : 0,
            ];
            $v = $wpdb->get_results("SHOW GLOBAL VARIABLES WHERE Variable_name IN ('max_connections','innodb_buffer_pool_size')", ARRAY_N);
            if (is_array($v)) {
                foreach ($v as $r) {
                    if ($r[0] === 'max_connections') {
                        $db['maxc'] = (int) $r[1];
                    } else {
                        $db['bp_mb'] = (int) round($r[1] / 1048576);
                    }
                }
            }
            $busy = $busy || $db['run'] >= 3;
        } else {
            $db['err'] = substr((string) $wpdb->last_error, 0, 120);
        }
        // What is MariaDB actually running right now? Only worth asking when it is busy.
        if ($busy && $db['ok']) {
            $pl = $wpdb->get_results('SHOW FULL PROCESSLIST', ARRAY_A);
            if (is_array($pl)) {
                $run = [];
                foreach ($pl as $r) {
                    $info = isset($r['Info']) ? (string) $r['Info'] : '';
                    if (isset($r['Command']) && $r['Command'] !== 'Sleep' && (int) $r['Time'] >= 2 && stripos($info, 'PROCESSLIST') === false) {
                        $run[] = [(int) $r['Time'], isset($r['State']) ? substr((string) $r['State'], 0, 40) : '', lg_bb_mask_sql($info, 300)];
                    }
                }
                usort($run, function ($a, $b) {
                    return $b[0] - $a[0];
                });
                if ($run) {
                    $row['pl'] = array_slice($run, 0, 5);
                }
            }
        }
        $wpdb->suppress_errors($prev);
    }
    $row['db'] = $db;
    lg_bb_append(lg_bb_logfile(), $row, LG_BB_MAX_BYTES);

    // Housekeeping: drop per-IP login records that no longer block anyone, and old country-refusal records.
    foreach ((array) @glob(lg_bb_rl_dir() . '/ip-*.php') as $f) {
        if (time() - (int) @filemtime($f) > 86400) {
            $rec = lg_bb_rl_read($f);
            if (!is_array($rec) || (int) $rec['until'] < time()) {
                @unlink($f);
            }
        }
    }
    foreach ((array) @glob(lg_bb_rl_dir() . '/geo-*.php') as $f) {
        if (time() - (int) @filemtime($f) > 2 * 86400) {
            @unlink($f);
        }
    }
    foreach ((array) @glob(lg_bb_rl_dir() . '/probe-*.php') as $f) {
        if (time() - (int) @filemtime($f) > 2 * 86400) {
            $rec = lg_bb_rl_read($f);
            if (!is_array($rec) || (int) $rec['until'] < time()) {
                @unlink($f);
            }
        }
    }
}

/** Login attempts (wp-login.php, xmlrpc.php, CRM /auth/login) in the last 60 s / 10 min, with the top source IPs. */
function lg_bb_auth_summary()
{
    $f = lg_bb_dir() . '/auth-' . lg_bb_token() . '.php';
    $size = @filesize($f);
    $h = $size ? @fopen($f, 'r') : false;
    if (!$h) {
        return null;
    }
    if ($size > 131072) {
        fseek($h, $size - 131072);
        fgets($h);
    }
    $now = time();
    $n1 = 0;
    $n10 = 0;
    $f10 = 0;
    $by = [];
    while (($line = fgets($h)) !== false) {
        if ($line[0] !== '{') {
            continue;
        }
        $r = json_decode($line, true);
        if (!is_array($r) || !isset($r['t']) || $now - $r['t'] > 600) {
            continue;
        }
        $n10++;
        $f10 += !empty($r['f']) ? 1 : 0;
        if ($now - $r['t'] <= 60) {
            $n1++;
        }
        $key = $r['ip'] . (!empty($r['cc']) ? ' [' . $r['cc'] . ']' : '') . ' ' . $r['k'];
        $by[$key] = isset($by[$key]) ? $by[$key] + 1 : 1;
    }
    fclose($h);
    if (!$n10) {
        return null;
    }
    arsort($by);
    $top = [];
    foreach (array_slice($by, 0, 3, true) as $k => $n) {
        $top[] = [$k, $n];
    }
    return ['n1' => $n1, 'n10' => $n10, 'f10' => $f10, 'top' => $top];
}

function lg_bb_auth_str($a)
{
    $t = [];
    foreach ($a['top'] as $x) {
        $t[] = $x[0] . ' x' . $x[1];
    }
    return 'LOGIN ATTEMPTS ' . $a['n1'] . '/min, ' . $a['n10'] . ' in 10 min (' . (isset($a['f10']) ? $a['f10'] : '?') . ' failed); top: ' . implode(', ', $t);
}

/**
 * Counts running requests and settles the leftovers: a marker whose PHP worker no
 * longer exists belongs to a request that was killed - logged once as 'orphan'.
 */
function lg_bb_inflight_scan()
{
    $files = @glob(lg_bb_dir() . '/inflight/*.php');
    $out = ['n' => 0];
    if (!$files) {
        return $out;
    }
    $now = time();
    $have_proc = is_dir('/proc/self');
    $running = [];
    foreach ($files as $f) {
        $age = $now - (int) @filemtime($f);
        $pid = (int) strtok(basename($f), '-');
        if ($age > 120) {
            $alive = $have_proc ? is_dir('/proc/' . $pid) : null;
            if ($alive === false || $age > 900) {
                $raw = (string) @file_get_contents($f);
                $d = json_decode(substr($raw, 13), true);
                lg_bb_append(lg_bb_logfile(), [
                    'k' => 'orphan',
                    't' => $now,
                    'started' => $now - $age,
                    'age' => $age,
                    'uri' => is_array($d) && isset($d['uri']) ? $d['uri'] : '',
                    'ip' => is_array($d) && isset($d['ip']) ? $d['ip'] : '',
                ], LG_BB_MAX_BYTES);
                @unlink($f);
                continue;
            }
        }
        $out['n']++;
        if ($age >= 20) {
            $raw = (string) @file_get_contents($f);
            $d = json_decode(substr($raw, 13), true);
            $running[] = [$age, is_array($d) && isset($d['uri']) ? $d['uri'] : ''];
        }
    }
    if ($running) {
        usort($running, function ($a, $b) {
            return $b[0] - $a[0];
        });
        $out['long'] = array_slice($running, 0, 3); // requests running for 20 s or more
    }
    return $out;
}

// Backup sampling when traffic is too thin for request-driven samples.
add_filter('cron_schedules', function ($s) {
    $s['lg_bb_minute'] = ['interval' => 60, 'display' => 'LG Black Box (every minute)'];
    return $s;
});
add_action('lg_bb_tick', 'lg_bb_maybe_heartbeat');
add_action('admin_init', function () {
    if (!wp_next_scheduled('lg_bb_tick')) {
        wp_schedule_event(time() + 60, 'lg_bb_minute', 'lg_bb_tick');
    }
});

// ---------------------------------------------------------------- db-error.php drop-in

/**
 * WordPress shows wp-content/db-error.php when it cannot connect to MariaDB. Ours logs
 * the server state at that moment and answers 503 (with Retry-After) instead of the
 * stock page. Never overwrites a db-error.php that is not ours.
 */
function lg_bb_install_dropin()
{
    $target = WP_CONTENT_DIR . '/db-error.php';
    if (file_exists($target) && strpos((string) @file_get_contents($target), 'LG-BLACKBOX-DROPIN') === false) {
        return false;
    }
    $code = "<?php\n/* LG-BLACKBOX-DROPIN v1 - installed by the LG Black Box plugin, removed when it is deactivated. */\n"
        . '$lg_bb_probe = ' . var_export(LG_BB_PROBE, true) . ";\n"
        . '$lg_bb_log = ' . var_export(lg_bb_logfile(), true) . ";\n"
        . <<<'PHP'
if (is_readable($lg_bb_probe)) {
    @include_once $lg_bb_probe;
    if (function_exists('lg_bb_dropin_log')) {
        try { lg_bb_dropin_log($lg_bb_log); } catch (\Throwable $e) {}
    }
}
if (!headers_sent()) {
    http_response_code(503);
    header('Retry-After: 30');
    header('Cache-Control: no-store');
    header('Content-Type: text/html; charset=utf-8');
}
echo '<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Service temporairement indisponible / Temporarily unavailable</title></head><body style="font-family:sans-serif;text-align:center;padding:4em 1em"><h1>Service temporairement indisponible</h1><p>Veuillez réessayer dans quelques instants.</p><h2>Temporarily unavailable</h2><p>Please try again in a few moments.</p></body></html>';
exit;

PHP;
    return @file_put_contents($target, $code) !== false;
}

function lg_bb_remove_dropin()
{
    $target = WP_CONTENT_DIR . '/db-error.php';
    if (file_exists($target) && strpos((string) @file_get_contents($target), 'LG-BLACKBOX-DROPIN') !== false) {
        @unlink($target);
    }
}

register_activation_hook(__FILE__, function () {
    lg_bb_dir();
    lg_bb_install_dropin();
    // Replacing the plugin deactivates it (which removes the gate); bring the gate back if protection is configured.
    $c = lg_bb_rl_cfg();
    if (lg_bb_gate_needed($c)) {
        lg_bb_gate_install();
    }
    if (!wp_next_scheduled('lg_bb_tick')) {
        wp_schedule_event(time() + 60, 'lg_bb_minute', 'lg_bb_tick');
    }
});
register_deactivation_hook(__FILE__, function () {
    wp_clear_scheduled_hook('lg_bb_tick');
    lg_bb_remove_dropin();
    lg_bb_gate_remove(); // the gate is useless without the plugin that feeds it
});

// ---------------------------------------------------------------- login protection

/*
 * Failed logins (wp-login.php, xmlrpc.php, CRM /auth/login) are counted per IP here;
 * past the limit the IP gets a block record. A tiny mu-plugin (gate.php, copied to
 * wp-content/mu-plugins) reads those records and answers 429 before the other plugins
 * load, so a bot costs a core boot instead of a full one. State lives in plain files
 * (wp-content/lg-blackbox/rl), not the database: the DB may be what is struggling.
 * Off until enabled on the Tools > LG Black Box page.
 */

function lg_bb_rl_dir()
{
    $d = lg_bb_dir() . '/rl';
    if (!is_dir($d)) {
        @mkdir($d, 0775, true);
    }
    // Group-writable, once per request: the server's block-list sync script (a different system user in the same group)
    // writes shared entries here. Files in it are still only readable as before.
    static $opened = false;
    if (!$opened) {
        $opened = true;
        $p = @fileperms($d);
        if ($p !== false && ($p & 0020) === 0) {
            @chmod($d, 0775);
        }
    }
    return $d;
}

function lg_bb_rl_read($f)
{
    $s = @file_get_contents($f);
    if (!is_string($s) || strlen($s) < 14) {
        return null;
    }
    $j = json_decode(substr($s, 13), true);
    return is_array($j) ? $j : null;
}

function lg_bb_rl_write($f, $a)
{
    @file_put_contents($f, '<?php exit;?>' . json_encode($a), LOCK_EX);
}

function lg_bb_rl_cfg()
{
    $d = ['enabled' => 0, 'limit' => 8, 'window' => 10, 'block' => 30, 'block_xmlrpc' => 0, 'geo' => 'off', 'geo_countries' => ['CA', 'US'],
        'probe' => 'off', 'probe_limit' => 5, 'probe_window' => 10, 'probe_block' => 60, 'auto' => 0, 'auto_days' => 30,
        'rate' => 0, 'rate_limit' => 120, 'rate_limit_auth' => 600, 'rate_limit_bot' => 20, 'rate_auto_days' => 1, 'cron_guard' => 0,
        'ua' => null, 'ua_load' => 3.0]; // ua null = under-attack mode follows the rate limit
    $c = lg_bb_rl_read(lg_bb_rl_dir() . '/config.php');
    $c = is_array($c) ? array_merge($d, $c) : $d;
    if (empty($c['geo_countries']) || !is_array($c['geo_countries'])) {
        $c['geo_countries'] = ['CA', 'US'];
    }
    return $c;
}

function lg_bb_geo_on()
{
    $c = lg_bb_rl_cfg();
    return $c['geo'] === 'block';
}

function lg_bb_probe_on()
{
    $c = lg_bb_rl_cfg();
    return $c['probe'] === 'on';
}

/** The gate file must exist while ANY of its three features is switched on. */
function lg_bb_over_file($ip)
{
    return lg_bb_rl_dir() . '/over-' . substr(sha1($ip), 0, 20) . '.php';
}

/** IPs the rate limiter refused in the last hour: ip, minutes over the limit, last time, path. Old ones are removed. */
function lg_bb_over_list()
{
    $rows = [];
    foreach ((array) @glob(lg_bb_rl_dir() . '/over-*.php') as $f) {
        $r = lg_bb_rl_read($f);
        if (!is_array($r) || empty($r['ip']) || (int) $r['last'] < time() - 86400) {
            @unlink($f);
            continue;
        }
        $rows[] = $r;
    }
    usort($rows, function ($a, $b) {
        return (int) $b['last'] - (int) $a['last'];
    });
    return $rows;
}

function lg_bb_auto_file($ip)
{
    return lg_bb_rl_dir() . '/auto-' . substr(sha1($ip), 0, 20) . '.php';
}

/** An IP that has made logged-in CRM API calls (seen in the request recorder) is never auto-blocked. */
function lg_bb_auto_known_good($ip)
{
    $needle = '"ip":' . json_encode($ip);
    foreach ([lg_bb_rec_file(true), lg_bb_rec_file()] as $f) {
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

/** Add an IP to the automatic block list (used after repeated login lockouts; the gate adds repeat scanners itself). */
function lg_bb_auto_add($ip, $why)
{
    $cfg = lg_bb_rl_cfg();
    if (empty($cfg['auto']) || !lg_bb_rl_public_ip($ip)) {
        return false;
    }
    $lists = lg_bb_rl_lists();
    if (in_array($ip, $lists['allow'], true) || is_file(lg_bb_auto_file($ip)) || lg_bb_sec_is_self($ip) || lg_bb_auto_known_good($ip)) {
        return false;
    }
    $many = @glob(lg_bb_rl_dir() . '/auto-*.php');
    if ($many && count($many) >= 500) {
        return false;
    }
    $now = time();
    lg_bb_rl_write(lg_bb_auto_file($ip), ['ip' => $ip, 'cc' => lg_bb_cc(), 'why' => $why, 'first' => $now, 'last' => 0, 'n' => 0, 'until' => $now + max(1, (int) $cfg['auto_days']) * 86400]);
    return true;
}

/** Active automatic blocks, newest first; expired ones are removed here. */
function lg_bb_auto_list()
{
    $rows = [];
    foreach ((array) @glob(lg_bb_rl_dir() . '/auto-*.php') as $f) {
        $r = lg_bb_rl_read($f);
        if (!is_array($r) || empty($r['ip']) || (int) $r['until'] <= time()) {
            @unlink($f);
            continue;
        }
        $rows[] = $r;
    }
    usort($rows, function ($a, $b) {
        return (int) $b['first'] - (int) $a['first'];
    });
    return $rows;
}

/**
 * Is this address a CDN or proxy edge (Cloudflare) rather than the server? A site that sits behind Cloudflare resolves to the
 * edge, and the edge is never "the server itself": taking it for the server (2.3.2 did) made the wp-cron guard refuse the real
 * server's cron and stopped every scheduled job.
 */
function lg_bb_is_cdn_ip($ip)
{
    static $v4 = ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20',
        '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'];
    $b = @inet_pton($ip);
    if ($b === false) {
        return false;
    }
    if (strlen($b) === 16) {
        return strncmp($b, @inet_pton('2606:4700::'), 4) === 0 || strncmp($b, @inet_pton('2400:cb00::'), 4) === 0 || strncmp($b, @inet_pton('2405:b500::'), 4) === 0
            || strncmp($b, @inet_pton('2803:f800::'), 4) === 0 || strncmp($b, @inet_pton('2a06:98c0::'), 4) === 0 || strncmp($b, @inet_pton('2c0f:f248::'), 4) === 0;
    }
    $n = ip2long($ip);
    foreach ($v4 as $r) {
        list($net, $bits) = explode('/', $r);
        $mask = -1 << (32 - (int) $bits);
        if (($n & $mask) === (ip2long($net) & $mask)) {
            return true;
        }
    }
    return false;
}

/**
 * The server's own public addresses, kept in rl/self.php for the gate (its own cron and loopback requests must never be refused).
 * Behind Apache PHP sees SERVER_ADDR = 127.0.0.1, so the candidates are: the site's DNS name, the hostname, and the address the
 * machine really uses to reach the Internet (a UDP socket that sends nothing). CDN/proxy addresses are never kept. An address seen
 * before stays for 30 days, so one odd lookup can never remove the real one. Refreshed every 6 hours and whenever the plugin version
 * changes, only on a site that already has a Black Box configuration; $force skips those checks (admin button, WP-CLI).
 * Returns the list now in force.
 */
function lg_bb_self_refresh($force = false)
{
    $dir = lg_bb_rl_dir();
    $f = $dir . '/self.php';
    if (!$force && !is_file($dir . '/config.php')) {
        return [];
    }
    $old = lg_bb_rl_read($f);
    $old = is_array($old) ? $old : [];
    if (!$force && is_file($f) && filemtime($f) > time() - 6 * 3600 && isset($old['v']) && $old['v'] === LG_BB_VERSION) {
        return isset($old['ips']) && is_array($old['ips']) ? $old['ips'] : [];
    }
    $cands = [];
    $host = wp_parse_url(home_url(), PHP_URL_HOST);
    $cands[] = is_string($host) ? gethostbyname($host) : '';
    $cands[] = isset($_SERVER['SERVER_ADDR']) ? (string) $_SERVER['SERVER_ADDR'] : '';
    $cands[] = gethostbyname((string) gethostname());
    $so = @stream_socket_client('udp://192.0.2.1:53', $en, $es, 1);
    if ($so) {
        $nm = (string) @stream_socket_get_name($so, false);
        $cands[] = preg_replace('/:\d+$/', '', $nm);
        @fclose($so);
    }
    $now = time();
    $seen = [];
    foreach ((array) (isset($old['seen']) ? $old['seen'] : []) as $ip => $t) {
        if (is_string($ip) && (int) $t > $now - 30 * 86400 && filter_var($ip, FILTER_VALIDATE_IP) && !lg_bb_is_cdn_ip($ip)) {
            $seen[$ip] = (int) $t;
        }
    }
    foreach ($cands as $c) {
        if (is_string($c) && filter_var($c, FILTER_VALIDATE_IP) && lg_bb_rl_public_ip($c) && !lg_bb_is_cdn_ip($c)) {
            $seen[$c] = $now;
        }
    }
    $ips = array_keys($seen);
    lg_bb_rl_write($f, ['ips' => $ips, 'seen' => $seen, 'v' => LG_BB_VERSION, 't' => $now]);
    return $ips;
}

add_action('init', function () {
    lg_bb_self_refresh(false);
}, 2);

/**
 * WP-CLI, for fixing a stuck cron from the server in seconds (it never goes through the web gate):
 *   wp lg-bb cron-guard status|off|on|redetect
 */
if (defined('WP_CLI') && WP_CLI && class_exists('WP_CLI')) {
    WP_CLI::add_command('lg-bb cron-guard', function ($args) {
        $act = isset($args[0]) ? $args[0] : 'status';
        $dir = lg_bb_rl_dir();
        $off = $dir . '/cron-guard-off';
        if ($act === 'off') {
            @file_put_contents($off, 'switched off by WP-CLI ' . gmdate('c') . "\n");
            WP_CLI::success('wp-cron guard is off (file rl/cron-guard-off). Scheduled jobs resume on the next cron call.');
        } elseif ($act === 'on') {
            @unlink($off);
            @unlink($dir . '/cron-denied.php');
            $ips = lg_bb_self_refresh(true);
            $cfg = lg_bb_rl_cfg();
            $cfg['cron_guard'] = 1;
            lg_bb_rl_write($dir . '/config.php', $cfg);
            WP_CLI::success('wp-cron guard is on. Server addresses let through: ' . ($ips ? implode(', ', $ips) : 'none known (guard inactive)'));
        } elseif ($act === 'redetect') {
            $ips = lg_bb_self_refresh(true);
            WP_CLI::success('Server addresses: ' . ($ips ? implode(', ', $ips) : 'none found'));
        } else {
            $cfg = lg_bb_rl_cfg();
            $j = lg_bb_rl_read($dir . '/self.php');
            $d = lg_bb_rl_read($dir . '/cron-denied.php');
            WP_CLI::line('setting: ' . (!empty($cfg['cron_guard']) ? 'on' : 'off') . ' | file switch: ' . (is_file($off) ? 'OFF (rl/cron-guard-off)' : 'none')
                . ' | server addresses: ' . (is_array($j) && !empty($j['ips']) ? implode(', ', $j['ips']) : 'none')
                . ' | last refusal: ' . (is_array($d) && !empty($d['ip']) ? $d['ip'] . ' at ' . gmdate('c', (int) $d['t']) : 'none'));
        }
    });
}

/**
 * Default-on: a wp-config.php or mu-plugin that defines LG_BB_DEFAULT_ON as true makes the first request write a
 * protected configuration (login limit, probe shield, automatic blocks; country filter stays off) and install the gate.
 * Only when no configuration exists yet, so it never overrides a choice made on the admin page. Never define it on a
 * site that sits behind a CDN or proxy unless LG_CRM_TRUSTED_PROXIES lists that proxy: every visitor would look like one address.
 */
add_action('init', function () {
    if (!defined('LG_BB_DEFAULT_ON') || !LG_BB_DEFAULT_ON) {
        return;
    }
    $f = lg_bb_rl_dir() . '/config.php';
    if (is_file($f)) {
        return;
    }
    lg_bb_rl_write($f, ['enabled' => 1, 'limit' => 8, 'window' => 10, 'block' => 30, 'block_xmlrpc' => 0, 'geo' => 'off', 'geo_countries' => ['CA', 'US'],
        'probe' => 'on', 'probe_limit' => 5, 'probe_window' => 10, 'probe_block' => 60, 'auto' => 1, 'auto_days' => 30,
        'rate' => 1, 'rate_limit' => 120, 'rate_limit_auth' => 600, 'rate_limit_bot' => 20, 'rate_auto_days' => 1, 'cron_guard' => 1, 'default_on' => gmdate('c')]);
    lg_bb_gate_install();
}, 1);

function lg_bb_gate_needed($c)
{
    $l = lg_bb_rl_lists();
    return !empty($c['enabled']) || $c['geo'] === 'block' || $c['probe'] === 'on' || !empty($l['block_all']) || !empty($c['auto']) || !empty($c['rate']) || !empty($c['cron_guard']);
}

function lg_bb_probe_file($ip)
{
    return lg_bb_rl_dir() . '/probe-' . substr(sha1($ip), 0, 20) . '.php';
}

function lg_bb_rl_lists()
{
    $l = lg_bb_rl_read(lg_bb_rl_dir() . '/lists.php');
    $l = is_array($l) ? $l : [];
    return [
        'allow' => isset($l['allow']) ? array_values((array) $l['allow']) : [],
        'block' => isset($l['block']) ? array_values((array) $l['block']) : [],          // refused on login endpoints only
        'block_all' => isset($l['block_all']) ? array_values((array) $l['block_all']) : [], // refused on every request
    ];
}

define('LG_BB_BLOCKALL_MAX', 500);

function lg_bb_blk_file($ip)
{
    return lg_bb_rl_dir() . '/blk-' . substr(sha1($ip), 0, 20) . '.php';
}

/** URL of the admin action that blocks / unblocks / allows an IP (nonce included). */
function lg_bb_ip_action_url($op, $ip)
{
    return wp_nonce_url(admin_url('admin-post.php?action=lg_bb_login&op=' . $op . '&ip=' . rawurlencode($ip)), 'lg_bb_login');
}

/**
 * "Block site-wide" link for an IP shown in any table, or '' when it makes no sense: not a public IP,
 * the viewer's own IP, already allowed or already blocked.
 */
function lg_bb_block_link($ip, $label = 'Block site-wide')
{
    static $lists = null, $me = null;
    if ($lists === null) {
        $lists = lg_bb_rl_lists();
        $me = lg_bb_ip();
    }
    if (!is_string($ip) || !lg_bb_rl_public_ip($ip) || $ip === $me || in_array($ip, $lists['allow'], true)) {
        return '';
    }
    if (in_array($ip, $lists['block_all'], true)) {
        return '<span style="color:#b32d2e">blocked</span>';
    }
    return '<a href="' . esc_url(lg_bb_ip_action_url('blockall', $ip)) . '" style="color:#b32d2e" onclick="return confirm(\'Refuse every request from ' . esc_js($ip) . '?\')">' . esc_html($label) . '</a>';
}

function lg_bb_rl_public_ip($ip)
{
    return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
}

function lg_bb_rl_ipfile($ip)
{
    return lg_bb_rl_dir() . '/ip-' . substr(sha1($ip), 0, 20) . '.php';
}

/** Called at shutdown of a failed login request. */
function lg_bb_rl_record_failure($ip)
{
    $cfg = lg_bb_rl_cfg();
    if (empty($cfg['enabled']) || !lg_bb_rl_public_ip($ip)) {
        return;
    }
    $lists = lg_bb_rl_lists();
    if (in_array($ip, $lists['allow'], true)) {
        return;
    }
    $file = lg_bb_rl_ipfile($ip);
    $rec = lg_bb_rl_read($file);
    $rec = is_array($rec) ? $rec : ['ip' => $ip, 'f' => [], 'until' => 0, 'denied' => 0];
    if (lg_bb_cc() !== '') {
        $rec['cc'] = lg_bb_cc();
    }
    $now = time();
    $win = max(1, (int) $cfg['window']) * 60;
    $f = [];
    foreach ((array) $rec['f'] as $t) {
        if ($t >= $now - $win) {
            $f[] = $t;
        }
    }
    $f[] = $now;
    $rec['f'] = $f;
    if (count($f) >= (int) $cfg['limit'] && (int) $rec['until'] <= $now) {
        $rec['until'] = $now + max(1, (int) $cfg['block']) * 60;
        $rec['f'] = [];
        $rec['denied'] = 0;
        $rec['nb'] = (isset($rec['nb']) ? (int) $rec['nb'] : 0) + 1;
        if ($rec['nb'] >= 3) {
            lg_bb_auto_add($ip, 'login lockouts x' . $rec['nb']);
        }
    }
    lg_bb_rl_write($file, $rec);
}

function lg_bb_gate_path()
{
    return WP_CONTENT_DIR . '/mu-plugins/lg-blackbox-gate.php';
}

function lg_bb_gate_installed()
{
    $p = lg_bb_gate_path();
    return is_file($p) && strpos((string) @file_get_contents($p), 'LG-BLACKBOX-GATE') !== false;
}

function lg_bb_gate_install()
{
    $p = lg_bb_gate_path();
    if (file_exists($p) && !lg_bb_gate_installed()) {
        return false; // someone else's file: never overwrite
    }
    $src = @file_get_contents(dirname(LG_BB_PROBE) . '/gate.php');
    if (is_string($src) && $src !== '' && is_file($p) && @file_get_contents($p) === $src) {
        return true; // already in place and current (for example copied by SFTP): nothing to write
    }
    if (!is_dir(dirname($p))) {
        @mkdir(dirname($p), 0755, true);
    }
    return is_string($src) && $src !== '' && @file_put_contents($p, $src) !== false;
}

/** Why the last lg_bb_gate_install() failed, in words the owner can act on (the old message just listed guesses). */
function lg_bb_gate_why()
{
    $p = lg_bb_gate_path();
    $dir = dirname($p);
    if (file_exists($p) && !lg_bb_gate_installed()) {
        return 'a file named ' . $p . ' already exists and was not written by this plugin, so it is never overwritten (rename or delete it by SFTP, then try again)';
    }
    $srcfile = dirname(LG_BB_PROBE) . '/gate.php';
    $src = @file_get_contents($srcfile);
    if (!is_string($src) || $src === '') {
        return 'gate.php is missing or unreadable in the plugin folder (' . $srcfile . '); re-upload the whole plugin zip';
    }
    if (!is_dir($dir)) {
        return 'the folder ' . $dir . ' does not exist and PHP cannot create it (' . WP_CONTENT_DIR . ' is not writable by the web user); create that folder by SFTP and copy gate.php from the plugin folder into it as lg-blackbox-gate.php, or ask the host';
    }
    if (!is_writable($dir)) {
        return 'the folder ' . $dir . ' is not writable by PHP (permissions or ownership); ask the host to fix it, or copy gate.php from the plugin folder to ' . $p . ' by SFTP (the plugin then recognises it)';
    }
    $e = error_get_last();
    return 'writing ' . $p . ' failed' . ($e && !empty($e['message']) ? ' (' . $e['message'] . ')' : '') . ', for example a full disk or a security rule on the host';
}

function lg_bb_gate_remove()
{
    if (lg_bb_gate_installed()) {
        @unlink(lg_bb_gate_path());
    }
}

/** Per-country roll-up of the rows from lg_bb_auth_table(): IPs, attempts, failures, requests refused by the country filter. */
function lg_bb_geo_summary($rows)
{
    $by = [];
    foreach ($rows as $r) {
        if ($r['n'] == 0 && $r['geo'] == 0) {
            continue; // manual list entries with no traffic
        }
        $cc = $r['cc'] !== '' ? $r['cc'] : '-';
        if (!isset($by[$cc])) {
            $by[$cc] = ['cc' => $cc, 'ips' => 0, 'n' => 0, 'f' => 0, 'geo' => 0];
        }
        $by[$cc]['ips']++;
        $by[$cc]['n'] += $r['n'];
        $by[$cc]['f'] += $r['f'];
        $by[$cc]['geo'] += $r['geo'];
    }
    uasort($by, function ($a, $b) {
        return ($b['n'] + $b['geo']) - ($a['n'] + $a['geo']);
    });
    return array_values($by);
}

/** Scanner IPs seen by the probe shield (one small file per IP, written by the gate): probes, refused requests, block status. */
function lg_bb_probe_table($hours = 24)
{
    $since = time() - $hours * 3600;
    $now = time();
    $rows = [];
    foreach ((array) @glob(lg_bb_rl_dir() . '/probe-*.php') as $f) {
        $r = lg_bb_rl_read($f);
        if (!is_array($r) || empty($r['ip']) || ((int) $r['last'] < $since && (int) $r['until'] < $now)) {
            continue;
        }
        $blocked = (int) $r['until'] > $now;
        $rows[] = [
            'ip' => (string) $r['ip'],
            'cc' => isset($r['cc']) ? (string) $r['cc'] : '',
            'n' => (int) $r['n'],
            'denied' => (int) $r['denied'],
            'last' => (int) $r['last'],
            'until' => (int) $r['until'],
            'blocked' => $blocked,
            'status' => $blocked ? 'BLOCKED until ' . lg_bb_date('H:i', (int) $r['until']) . ', ' . (int) $r['denied'] . ' requests refused' : '',
            'paths' => isset($r['paths']) && is_array($r['paths']) ? implode(' ', array_slice($r['paths'], 0, 4)) : '',
            'ua' => isset($r['ua']) ? (string) $r['ua'] : '',
        ];
    }
    usort($rows, function ($a, $b) {
        return $b['n'] - $a['n'];
    });
    return $rows;
}

/** Per-IP login activity from the attempt log: attempts, failures, endpoints, last seen, block status. */
function lg_bb_auth_table($hours = 24)
{
    $since = time() - $hours * 3600;
    $cur = lg_bb_dir() . '/auth-' . lg_bb_token() . '.php';
    $by = [];
    foreach ([preg_replace('/\.php$/', '.1.php', $cur), $cur] as $file) {
        $h = @fopen($file, 'r');
        if (!$h) {
            continue;
        }
        while (($line = fgets($h)) !== false) {
            if ($line[0] !== '{') {
                continue;
            }
            $r = json_decode($line, true);
            if (!is_array($r) || !isset($r['t'], $r['ip']) || $r['t'] < $since) {
                continue;
            }
            $ip = $r['ip'];
            if (!isset($by[$ip])) {
                $by[$ip] = ['ip' => $ip, 'cc' => '', 'n' => 0, 'f' => 0, 'kinds' => [], 'last' => 0, 'status' => '', 'denied' => 0, 'geo' => 0];
            }
            if (!empty($r['cc'])) {
                $by[$ip]['cc'] = $r['cc'];
            }
            $by[$ip]['n']++;
            $by[$ip]['f'] += !empty($r['f']) ? 1 : 0;
            $by[$ip]['kinds'][$r['k']] = true;
            $by[$ip]['last'] = max($by[$ip]['last'], $r['t']);
        }
        fclose($h);
    }
    $lists = lg_bb_rl_lists();
    $now = time();
    // Blocks still in force, even when their attempts fall outside the window.
    foreach ((array) @glob(lg_bb_rl_dir() . '/ip-*.php') as $f) {
        $rec = lg_bb_rl_read($f);
        if (is_array($rec) && !empty($rec['ip']) && (int) $rec['until'] > $now && !isset($by[$rec['ip']])) {
            $by[$rec['ip']] = ['ip' => $rec['ip'], 'cc' => '', 'n' => 0, 'f' => 0, 'kinds' => [], 'last' => 0, 'status' => '', 'denied' => 0, 'geo' => 0];
        }
    }
    // Requests refused by the country filter never reach WordPress, so the gate keeps its own record of them.
    foreach ((array) @glob(lg_bb_rl_dir() . '/geo-*.php') as $f) {
        $g = lg_bb_rl_read($f);
        if (!is_array($g) || empty($g['ip']) || (int) $g['last'] < $since) {
            continue;
        }
        if (!isset($by[$g['ip']])) {
            $by[$g['ip']] = ['ip' => $g['ip'], 'cc' => '', 'n' => 0, 'f' => 0, 'kinds' => [], 'last' => 0, 'status' => '', 'denied' => 0, 'geo' => 0];
        }
        $by[$g['ip']]['geo'] = (int) $g['n'];
        $by[$g['ip']]['cc'] = (string) $g['cc'];
        if (!empty($g['k'])) {
            $by[$g['ip']]['kinds'][$g['k']] = true;
        }
        $by[$g['ip']]['last'] = max($by[$g['ip']]['last'], (int) $g['last']);
    }
    // Manual allow/block entries stay visible (and removable) even with no recent attempts.
    foreach (array_merge($lists['allow'], $lists['block'], $lists['block_all']) as $ip) {
        if (!isset($by[$ip])) {
            $by[$ip] = ['ip' => $ip, 'cc' => '', 'n' => 0, 'f' => 0, 'kinds' => [], 'last' => 0, 'status' => '', 'denied' => 0, 'geo' => 0];
        }
    }
    foreach ($by as $ip => &$row) {
        $rec = lg_bb_rl_read(lg_bb_rl_ipfile($ip));
        $row['denied'] = is_array($rec) && isset($rec['denied']) ? (int) $rec['denied'] : 0;
        if ($row['cc'] === '' && is_array($rec) && !empty($rec['cc'])) {
            $row['cc'] = (string) $rec['cc'];
        }
        if (in_array($ip, $lists['allow'], true)) {
            $row['status'] = 'ALLOWED';
        } elseif (in_array($ip, $lists['block_all'], true)) {
            $row['status'] = 'BLOCKED (site-wide)';
        } elseif (in_array($ip, $lists['block'], true)) {
            $row['status'] = 'BLOCKED (manual)';
        } elseif (is_array($rec) && (int) $rec['until'] > $now) {
            $row['status'] = 'BLOCKED until ' . lg_bb_date('H:i', (int) $rec['until']) . ' (auto), ' . $row['denied'] . ' requests refused';
        } elseif ($row['geo'] > 0) {
            $row['status'] = 'REFUSED by country filter (' . $row['cc'] . '), ' . $row['geo'] . ' requests';
        }
        $row['kinds'] = implode(',', array_keys($row['kinds']));
    }
    unset($row);
    uasort($by, function ($a, $b) {
        return $b['n'] - $a['n'];
    });
    return array_values($by);
}

add_action('admin_post_lg_bb_login', function () {
    lg_bb_admin_guard('lg_bb_login');
    $op = isset($_REQUEST['op']) ? (string) $_REQUEST['op'] : '';
    $ip = isset($_REQUEST['ip']) ? trim((string) $_REQUEST['ip']) : '';
    $msg = '';
    $cfg = lg_bb_rl_cfg();
    $lists = lg_bb_rl_lists();
    $save_lists = function () use (&$lists) {
        lg_bb_rl_write(lg_bb_rl_dir() . '/lists.php', $lists);
    };
    $without = function ($arr, $ip) {
        return array_values(array_diff($arr, [$ip]));
    };

    if ($op === 'enable') {
        if (!lg_bb_gate_install()) {
            $msg = 'Could not install the gate: ' . lg_bb_gate_why() . '.';
        } else {
            $cfg['enabled'] = 1;
            lg_bb_rl_write(lg_bb_rl_dir() . '/config.php', $cfg);
            $me = lg_bb_ip();
            if ($me && lg_bb_rl_public_ip($me) && !in_array($me, $lists['allow'], true)) {
                $lists['allow'][] = $me; // never lock out the person enabling it
                $save_lists();
            }
            $msg = 'Login protection enabled. Your current IP (' . $me . ') was added to the allow list.';
        }
    } elseif ($op === 'disable') {
        $cfg['enabled'] = 0;
        lg_bb_rl_write(lg_bb_rl_dir() . '/config.php', $cfg);
        if (lg_bb_gate_needed($cfg)) {
            $msg = 'Login protection disabled. The gate file stays because the country filter or the probe shield is still on.';
        } else {
            lg_bb_gate_remove();
            $msg = 'Login protection disabled and the gate removed.';
        }
    } elseif ($op === 'geo_enable' || $op === 'geo_save') {
        // Country filter. Refuse anything that would lock the person doing it out, or that cannot work.
        $raw = isset($_POST['countries']) ? (string) $_POST['countries'] : implode(',', $cfg['geo_countries']);
        $list = [];
        foreach (preg_split('/[\s,;]+/', strtoupper($raw)) as $c) {
            if (preg_match('/^[A-Z]{2}$/', $c) && $c !== 'XX' && !in_array($c, $list, true)) {
                $list[] = $c;
            }
        }
        $list = $list ? array_slice($list, 0, 40) : ['CA', 'US'];
        $mycc = lg_bb_cc();
        $myip = lg_bb_ip();
        $turning_on = ($op === 'geo_enable') || $cfg['geo'] === 'block';
        if ($turning_on && !lg_bb_cc_known($mycc)) {
            $dg = lg_bb_ip_diag();
            $msg = 'Not changed: the server did not receive a usable country header (CF-IPCountry) on your request, so the filter could not work. '
                . (!empty($_SERVER['HTTP_CF_IPCOUNTRY'])
                    ? 'The header is present but the connecting address ' . $dg['peer'] . ' is not a trusted proxy, so it is ignored: add the proxy ranges to LG_CRM_TRUSTED_PROXIES in wp-config.php. '
                    : 'No such header arrived at all, so this site is probably not behind Cloudflare (or IP Geolocation is off in its Network tab). ')
                . 'The country filter only works behind Cloudflare; the other protections do not need it.';
        } elseif ($turning_on && !in_array($mycc, $list, true)) {
            $msg = 'Not changed: your own visit comes from ' . lg_bb_cc_label($mycc) . ', which is not in that list. You would lock yourself out. Add ' . $mycc . ' or connect from an allowed country.';
        } elseif ($turning_on && !lg_bb_gate_install()) {
            $msg = 'Could not install the gate: ' . lg_bb_gate_why() . '.';
        } else {
            $cfg['geo_countries'] = $list;
            if ($op === 'geo_enable') {
                $cfg['geo'] = 'block';
                if ($myip && lg_bb_rl_public_ip($myip) && !in_array($myip, $lists['allow'], true)) {
                    $lists['allow'][] = $myip; // an allowed IP bypasses the country filter
                    $save_lists();
                }
            }
            lg_bb_rl_write(lg_bb_rl_dir() . '/config.php', $cfg);
            $msg = ($cfg['geo'] === 'block' ? 'Country filter ON: login pages are refused outside ' : 'Allowed countries saved: ') . implode(', ', $list) . '.';
        }
    } elseif ($op === 'geo_disable') {
        $cfg['geo'] = 'off';
        lg_bb_rl_write(lg_bb_rl_dir() . '/config.php', $cfg);
        if (!lg_bb_gate_needed($cfg)) {
            lg_bb_gate_remove();
        }
        $msg = 'Country filter disabled.';
    } elseif ($op === 'probe_enable' || $op === 'probe_save') {
        $cfg['probe_limit'] = max(2, min(100, (int) (isset($_POST['probe_limit']) ? $_POST['probe_limit'] : $cfg['probe_limit'])));
        $cfg['probe_window'] = max(1, min(120, (int) (isset($_POST['probe_window']) ? $_POST['probe_window'] : $cfg['probe_window'])));
        $cfg['probe_block'] = max(1, min(1440, (int) (isset($_POST['probe_block']) ? $_POST['probe_block'] : $cfg['probe_block'])));
        if ($op === 'probe_enable' && !lg_bb_gate_install()) {
            $msg = 'Could not install the gate: ' . lg_bb_gate_why() . '.';
        } else {
            if ($op === 'probe_enable') {
                $cfg['probe'] = 'on';
                $myip = lg_bb_ip();
                if ($myip && lg_bb_rl_public_ip($myip) && !in_array($myip, $lists['allow'], true)) {
                    $lists['allow'][] = $myip; // never lock out the person enabling it
                    $save_lists();
                }
            }
            lg_bb_rl_write(lg_bb_rl_dir() . '/config.php', $cfg);
            $msg = $op === 'probe_enable' ? 'Probe shield ON. Your current IP was added to the allow list.' : 'Probe shield settings saved.';
        }
    } elseif ($op === 'probe_disable') {
        $cfg['probe'] = 'off';
        lg_bb_rl_write(lg_bb_rl_dir() . '/config.php', $cfg);
        if (!lg_bb_gate_needed($cfg)) {
            lg_bb_gate_remove();
        }
        $msg = 'Probe shield disabled.';
    } elseif ($op === 'save') {
        $cfg['limit'] = max(3, min(100, (int) (isset($_POST['limit']) ? $_POST['limit'] : 8)));
        $cfg['window'] = max(1, min(120, (int) (isset($_POST['window']) ? $_POST['window'] : 10)));
        $cfg['block'] = max(1, min(1440, (int) (isset($_POST['block']) ? $_POST['block'] : 30)));
        $cfg['block_xmlrpc'] = empty($_POST['block_xmlrpc']) ? 0 : 1;
        lg_bb_rl_write(lg_bb_rl_dir() . '/config.php', $cfg);
        $msg = 'Settings saved.';
    } elseif ($op === 'self_refresh') {
        $ips = lg_bb_self_refresh(true);
        $msg = 'Server addresses re-detected: ' . ($ips ? implode(', ', $ips) : 'none found (the wp-cron guard stays out of the way until one is known)') . '.';
    } elseif (in_array($op, ['rate_on', 'rate_off', 'cron_on', 'cron_off'], true)) {
        $key = strpos($op, 'rate') === 0 ? 'rate' : 'cron_guard';
        $cfg[$key] = substr($op, -3) === '_on' ? 1 : 0;
        if ($op === 'cron_on') {
            // Turning the guard on starts from a fresh look at the server's own addresses and a clean slate.
            @unlink(lg_bb_rl_dir() . '/cron-guard-off');
            @unlink(lg_bb_rl_dir() . '/cron-denied.php');
            lg_bb_self_refresh(true);
        }
        foreach (['rate_limit' => 120, 'rate_limit_auth' => 600, 'rate_limit_bot' => 20, 'rate_auto_days' => 1] as $k => $v) {
            if (empty($cfg[$k])) {
                $cfg[$k] = $v;
            }
        }
        lg_bb_rl_write(lg_bb_rl_dir() . '/config.php', $cfg);
        if ($cfg[$key] && !lg_bb_gate_install()) {
            $msg = 'Saved, but the gate could not be installed: ' . lg_bb_gate_why() . '.';
        } else {
            $msg = ($key === 'rate' ? 'Request-rate limit' : 'wp-cron guard') . ($cfg[$key] ? ' is on.' : ' is off.');
        }
    } elseif ($op === 'recommended') {
        $r = lg_bb_reco_apply();
        $msg = $r['msg'];
    } elseif ($op === 'reco_dismiss') {
        update_user_meta(get_current_user_id(), 'lg_bb_reco_dismissed', 1);
        wp_safe_redirect(admin_url('index.php'));
        exit;
    } elseif ($op === 'ua_on' || $op === 'ua_off') {
        $cfg['ua'] = $op === 'ua_on' ? 1 : 0;
        $cfg['ua_load'] = isset($cfg['ua_load']) && $cfg['ua_load'] ? (float) $cfg['ua_load'] : 3.0;
        lg_bb_rl_write(lg_bb_rl_dir() . '/config.php', $cfg);
        if ($cfg['ua'] && empty($cfg['rate'])) {
            $msg = 'Under-attack mode is on, but it works through the request-rate limit, which is off: turn that on too.';
        } elseif ($cfg['ua'] && !lg_bb_gate_install()) {
            $msg = 'Saved, but the gate could not be installed: ' . lg_bb_gate_why() . '.';
        } else {
            $msg = $cfg['ua'] ? 'Under-attack mode is on: while the load average is ' . $cfg['ua_load'] . ' or more, anonymous visitors get a quarter of the normal rate. Signed-in CRM users and webhooks are not affected.' : 'Under-attack mode is off.';
        }
    } elseif ($op === 'flood_on' || $op === 'flood_off') {
        $sc = lg_bb_sec_read('config');
        $sc['flood'] = $op === 'flood_on' ? 1 : 0;
        lg_bb_sec_write('config', $sc);
        $msg = $sc['flood'] ? '404 flood watch is on: an address causing many page misses or refused links is added to the automatic block list (needs automatic blocks on).' : '404 flood watch is off.';
    } elseif ($op === 'auto_on' || $op === 'auto_off') {
        $cfg['auto'] = $op === 'auto_on' ? 1 : 0;
        $cfg['auto_days'] = max(1, (int) (isset($cfg['auto_days']) ? $cfg['auto_days'] : 30));
        lg_bb_rl_write(lg_bb_rl_dir() . '/config.php', $cfg);
        if ($cfg['auto'] && !lg_bb_gate_install()) {
            $msg = 'Automatic blocks are on, but the gate could not be installed: ' . lg_bb_gate_why() . '.';
        } else {
            $msg = $cfg['auto'] ? 'Automatic blocks are on: repeat scanners and repeat login failures are refused for ' . $cfg['auto_days'] . ' days.' : 'Automatic blocks are off (entries already on the list stay until they expire or you unblock them).';
        }
    } elseif (in_array($op, ['block', 'blockall', 'allow', 'unblock', 'unallow', 'allowme', 'unauto'], true)) {
        if ($op === 'allowme') {
            $op = 'allow';
            $ip = lg_bb_ip();
        }
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $msg = 'Invalid IP address.';
        } elseif ($op === 'unauto') {
            @unlink(lg_bb_auto_file($ip));
            @unlink(lg_bb_over_file($ip));
            $msg = $ip . ' removed from the automatic block list.';
        } elseif ($op === 'blockall') {
            // Site-wide block: every request from this IP is refused by the gate before WordPress loads.
            if (!lg_bb_rl_public_ip($ip)) {
                $msg = 'Not blocked: ' . $ip . ' is a private or reserved address (blocking it could block everyone).';
            } elseif ($ip === lg_bb_ip()) {
                $msg = 'Not blocked: that is your own IP address, you would lock yourself out.';
            } elseif (in_array($ip, $lists['allow'], true)) {
                $msg = 'Not blocked: ' . $ip . ' is on the "never block" list. Press Reset on it first if you really want to block it.';
            } elseif (count($lists['block_all']) >= LG_BB_BLOCKALL_MAX && !in_array($ip, $lists['block_all'], true)) {
                $msg = 'Not blocked: the site-wide list is full (' . LG_BB_BLOCKALL_MAX . ' IPs). Block a range in Cloudflare instead.';
            } else {
                if (!in_array($ip, $lists['block_all'], true)) {
                    $lists['block_all'][] = $ip;
                }
                $lists['block'] = $without($lists['block'], $ip);
                $save_lists();
                if (!is_file(lg_bb_rl_dir() . '/config.php')) {
                    lg_bb_rl_write(lg_bb_rl_dir() . '/config.php', $cfg); // the gate needs a config file to run at all
                }
                if (!lg_bb_gate_install()) {
                    $msg = $ip . ' is on the list, but the gate could not be installed: ' . lg_bb_gate_why() . ', so it is NOT being refused yet.';
                } else {
                    $msg = $ip . ' blocked site-wide: every request from it is now refused with a 403 before WordPress loads. For a heavy attacker also block it in Cloudflare.';
                }
            }
        } elseif ($op === 'block') {
            $lists['allow'] = $without($lists['allow'], $ip);
            if (!in_array($ip, $lists['block'], true)) {
                $lists['block'][] = $ip;
            }
            // (login-only block; "Block site-wide" refuses every request)
            $save_lists();
            $msg = $ip . ' blocked from logging in.';
        } elseif ($op === 'allow') {
            $lists['block'] = $without($lists['block'], $ip);
            $lists['block_all'] = $without($lists['block_all'], $ip);
            if (!in_array($ip, $lists['allow'], true)) {
                $lists['allow'][] = $ip;
            }
            $save_lists();
            @unlink(lg_bb_rl_ipfile($ip));
            @unlink(lg_bb_probe_file($ip));
            @unlink(lg_bb_blk_file($ip));
            @unlink(lg_bb_auto_file($ip));
            @unlink(lg_bb_over_file($ip));
            $msg = $ip . ' will never be blocked.';
        } else { // unblock / unallow
            $lists['block'] = $without($lists['block'], $ip);
            $lists['block_all'] = $without($lists['block_all'], $ip);
            $lists['allow'] = $without($lists['allow'], $ip);
            $save_lists();
            @unlink(lg_bb_rl_ipfile($ip));
            @unlink(lg_bb_probe_file($ip));
            @unlink(lg_bb_blk_file($ip));
            @unlink(lg_bb_auto_file($ip));
            @unlink(lg_bb_over_file($ip));
            if (!lg_bb_gate_needed(lg_bb_rl_cfg())) {
                lg_bb_gate_remove(); // nothing left that needs the gate
            }
            $msg = $ip . ' reset.';
        }
    }
    wp_safe_redirect(add_query_arg(['page' => 'lg-blackbox', 'lgmsg' => rawurlencode($msg)], admin_url('tools.php')) . ($op === 'recommended' ? '#lg-recommended' : '#lg-login'));
    exit;
});

function lg_bb_login_panel()
{
    $cfg = lg_bb_rl_cfg();
    $installed = lg_bb_gate_installed();
    if ($installed && strpos((string) @file_get_contents(lg_bb_gate_path()), 'LG-BLACKBOX-GATE v8') === false) {
        lg_bb_gate_install(); // an older copy of our own gate: refresh it
    }
    $on = !empty($cfg['enabled']) && $installed;
    $rows = lg_bb_auth_table(24);
    $lists = lg_bb_rl_lists();
    $me = lg_bb_ip();
    $link = function ($op, $ip = '') {
        return esc_url(wp_nonce_url(admin_url('admin-post.php?action=lg_bb_login&op=' . $op . '&ip=' . rawurlencode($ip)), 'lg_bb_login'));
    };
    ?>
    <h2 id="lg-login">Login protection</h2>
    <?php if (!empty($_GET['lgmsg'])): ?>
        <div class="notice notice-info inline"><p><?php echo esc_html(wp_unslash(rawurldecode((string) $_GET['lgmsg']))); ?></p></div>
    <?php endif; ?>
    <p>
        Status: <strong><?php echo $on ? 'ON' : 'OFF'; ?></strong>
        <?php if (!empty($cfg['enabled']) && !$installed): ?> - enabled in settings but the gate file is missing; press Enable again.<?php endif; ?>
        <?php if ($on): ?>
            - an IP with <?php echo (int) $cfg['limit']; ?> failed logins in <?php echo (int) $cfg['window']; ?> min is refused for
            <?php echo (int) $cfg['block']; ?> min (wp-login.php, xmlrpc.php and the CRM login only; the rest of the site keeps
            working for them).
        <?php endif; ?>
        Your IP as seen by the server: <code><?php echo esc_html($me ?: 'unknown'); ?></code>
        <?php $dg = lg_bb_ip_diag(); ?>
        (TCP peer <code><?php echo esc_html($dg['peer'] ?: 'unknown'); ?></code>, <?php echo $dg['trusted'] ? 'a trusted proxy: forwarded IP and country headers are believed' : 'not a trusted proxy: forwarded headers are ignored'; ?>)
        <?php if ($me && !lg_bb_rl_public_ip($me)): ?>
            <strong>This is a private address, which means the server cannot see real visitor IPs; protection would be
                ineffective, so it ignores private addresses.</strong>
        <?php endif; ?>
        <?php if ($dg['ignored']): ?>
            <br><strong>This request carried CF-Connecting-IP / X-Forwarded-For but the TCP peer is not trusted, so they were
                ignored and every visitor looks like the peer. If the site is behind Cloudflare and PHP sees Cloudflare's address as
                the peer, add Cloudflare's published ranges to <code>LG_CRM_TRUSTED_PROXIES</code> in wp-config.php (the CRM's own
                login limits use the same rule) before enabling protection.</strong>
        <?php endif; ?>
    </p>
    <p>
        <?php if ($on): ?>
            <a class="button" href="<?php echo $link('disable'); ?>" onclick="return confirm('Disable login protection?')">Disable
                protection</a>
        <?php else: ?>
            <a class="button button-primary" href="<?php echo $link('enable'); ?>">Enable protection</a>
            <span>(installs a small file in wp-content/mu-plugins and adds your current IP to the allow list)</span>
        <?php endif; ?>
        <a class="button" href="<?php echo $link('allowme'); ?>">Always allow my IP</a>
    </p>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-bottom:1em">
        <input type="hidden" name="action" value="lg_bb_login">
        <input type="hidden" name="op" value="save">
        <?php wp_nonce_field('lg_bb_login'); ?>
        Block after <input type="number" name="limit" value="<?php echo (int) $cfg['limit']; ?>" min="3" max="100" style="width:60px">
        failed logins within <input type="number" name="window" value="<?php echo (int) $cfg['window']; ?>" min="1" max="120" style="width:60px"> min,
        for <input type="number" name="block" value="<?php echo (int) $cfg['block']; ?>" min="1" max="1440" style="width:70px"> min.
        <label><input type="checkbox" name="block_xmlrpc" value="1" <?php checked(!empty($cfg['block_xmlrpc'])); ?>> refuse all
            xmlrpc.php requests</label>
        <button class="button">Save</button>
    </form>
    <h3 id="lg-probe">Probe shield (scanners hunting for .env, credentials.json, /actuator…)</h3>
    <?php
    $probe_on = lg_bb_probe_on() && $installed;
    $probe_rows = lg_bb_probe_table(24);
    ?>
    <p>
        Status: <strong><?php echo $probe_on ? 'ON' : 'OFF'; ?></strong>
        <?php if (lg_bb_probe_on() && !$installed): ?> - enabled in settings but the gate file is missing; press Enable again.<?php endif; ?>
        - a request for a file that does not exist and that only a vulnerability scanner asks for (<code>/.env</code>,
        <code>/actuator/…</code>, <code>credentials.json</code>, <code>terraform.tfstate</code>, <code>wp-config.txt</code>…) is answered with a
        3-byte 404 <em>before WordPress loads</em> instead of a 0.6 CPU-second page build. An IP that sends
        <?php echo (int) $cfg['probe_limit']; ?> such requests within <?php echo (int) $cfg['probe_window']; ?> min is refused everywhere for
        <?php echo (int) $cfg['probe_block']; ?> min. Never affects: logged-in browsers, allow-listed IPs, Google/Bing/Apple/Facebook crawlers
        (they get the cheap 404 but are never blocked), or the server itself.
    </p>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-bottom:1em">
        <input type="hidden" name="action" value="lg_bb_login">
        <?php wp_nonce_field('lg_bb_login'); ?>
        Block after <input type="number" name="probe_limit" value="<?php echo (int) $cfg['probe_limit']; ?>" min="2" max="100" style="width:60px">
        probes within <input type="number" name="probe_window" value="<?php echo (int) $cfg['probe_window']; ?>" min="1" max="120" style="width:60px"> min,
        for <input type="number" name="probe_block" value="<?php echo (int) $cfg['probe_block']; ?>" min="1" max="1440" style="width:70px"> min.
        <?php if ($probe_on): ?>
            <button class="button" name="op" value="probe_save">Save</button>
            <button class="button" name="op" value="probe_disable" onclick="return confirm('Turn the probe shield off?')">Disable probe shield</button>
        <?php else: ?>
            <button class="button button-primary" name="op" value="probe_enable">Enable probe shield</button>
            <button class="button" name="op" value="probe_save">Save settings only</button>
        <?php endif; ?>
    </form>
    <?php if ($probe_rows): ?>
        <table class="widefat striped" style="margin-bottom:1em">
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Country</th>
                    <th>Probes</th>
                    <th>Last seen</th>
                    <th>Status</th>
                    <th>Paths tried (sample)</th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach (array_slice($probe_rows, 0, 20) as $r): ?>
                    <tr>
                        <td><?php echo esc_html($r['ip']); ?></td>
                        <td><?php echo esc_html(lg_bb_cc_label($r['cc'])); ?></td>
                        <td><?php echo (int) $r['n']; ?></td>
                        <td><?php echo $r['last'] ? lg_bb_t($r['last']) : ''; ?></td>
                        <td><?php echo esc_html($r['status']); ?></td>
                        <td><code><?php echo esc_html($r['paths']); ?></code></td>
                        <td>
                            <?php $bl = lg_bb_block_link($r['ip']); echo $bl !== '' ? $bl . ' · ' : ''; $al = lg_bb_abuse_link($r['ip']); echo $al !== '' ? $al . ' · ' : ''; ?>
                            <a href="<?php echo $link('allow', $r['ip']); ?>">Never block</a> ·
                            <a href="<?php echo $link('unblock', $r['ip']); ?>">Reset</a>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php else: ?>
        <p>No scanner probes recorded by the shield yet.</p>
    <?php endif; ?>
    <h3 id="lg-geo">Country filter</h3>
    <?php
    $geo_on = lg_bb_geo_on() && $installed;
    $mycc = lg_bb_cc();
    ?>
    <p>
        Status: <strong><?php echo $geo_on ? 'ON' : 'OFF'; ?></strong>
        <?php if (lg_bb_geo_on() && !$installed): ?> - enabled in settings but the gate file is missing; press Enable again.<?php endif; ?>
        <?php if ($geo_on): ?>
            - wp-login.php, xmlrpc.php and the CRM login are refused (403) for visitors outside
            <strong><?php echo esc_html(implode(', ', $cfg['geo_countries'])); ?></strong>. Password-protected-page
            forms, the rest of the site, and allow-listed IPs are not affected. Unknown or missing country is let through.
        <?php else: ?>
            - off: nothing is refused by country. The table below still shows where login attempts come from.
        <?php endif; ?>
        <br>Your country as seen by the server:
        <?php if (lg_bb_cc_known($mycc)): ?>
            <code><?php echo esc_html(lg_bb_cc_label($mycc)); ?></code>
        <?php else: ?>
            <strong>not received</strong> (the CF-IPCountry header is missing, so the filter cannot work until Cloudflare
            sends it)
        <?php endif; ?>
    </p>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-bottom:1em">
        <input type="hidden" name="action" value="lg_bb_login">
        <?php wp_nonce_field('lg_bb_login'); ?>
        Allowed countries (2-letter codes, comma separated):
        <input type="text" name="countries" value="<?php echo esc_attr(implode(', ', $cfg['geo_countries'])); ?>" style="width:220px">
        <?php if ($geo_on): ?>
            <button class="button" name="op" value="geo_save">Save list</button>
            <button class="button" name="op" value="geo_disable" onclick="return confirm('Turn the country filter off?')">Disable country filter</button>
        <?php else: ?>
            <button class="button button-primary" name="op" value="geo_enable">Enable country filter</button>
            <button class="button" name="op" value="geo_save">Save list only</button>
        <?php endif; ?>
    </form>
    <?php $geo_rows = lg_bb_geo_summary($rows); ?>
    <?php if ($geo_rows): ?>
        <table class="widefat striped" style="max-width:640px;margin-bottom:1em">
            <thead>
                <tr>
                    <th>Country</th>
                    <th>IPs</th>
                    <th>Login attempts</th>
                    <th>Failed</th>
                    <th>Refused by filter</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach (array_slice($geo_rows, 0, 15) as $g): ?>
                    <tr>
                        <td><?php echo esc_html($g['cc'] === '-' ? '- (not reported)' : lg_bb_cc_label($g['cc'])); ?></td>
                        <td><?php echo (int) $g['ips']; ?></td>
                        <td><?php echo (int) $g['n']; ?></td>
                        <td><?php echo (int) $g['f']; ?></td>
                        <td><?php echo (int) $g['geo']; ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
    <p>Login sources, last 24 h (failures are wrong passwords; a normal user shows a few attempts, a bot shows hundreds).</p>
    <?php if (!$rows): ?>
        <p>No login attempts recorded yet.</p>
    <?php else: ?>
        <table class="widefat striped">
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Country</th>
                    <th>Attempts</th>
                    <th>Failed</th>
                    <th>Endpoints</th>
                    <th>Last seen</th>
                    <th>Status</th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach (array_slice($rows, 0, 25) as $r): ?>
                    <tr>
                        <td><?php echo esc_html($r['ip']); ?></td>
                        <td><?php echo esc_html(lg_bb_cc_label($r['cc'])); ?></td>
                        <td><?php echo (int) ($r['n'] + $r['geo']); ?><?php echo $r['geo'] ? ' (' . (int) $r['geo'] . ' refused by country)' : ''; ?></td>
                        <td><?php echo (int) $r['f']; ?></td>
                        <td><?php echo esc_html($r['kinds']); ?></td>
                        <td><?php echo $r['last'] ? lg_bb_t($r['last']) : ''; ?></td>
                        <td><?php echo esc_html($r['status']); ?></td>
                        <td>
                            <?php if ($r['status'] === '' || strpos($r['status'], 'BLOCKED') === false): ?>
                                <a href="<?php echo $link('block', $r['ip']); ?>" title="Refuse logins from this IP only">Block logins</a> ·
                                <?php $bl = lg_bb_block_link($r['ip']); echo $bl !== '' ? $bl . ' · ' : ''; $al = lg_bb_abuse_link($r['ip']); echo $al !== '' ? $al . ' · ' : ''; ?>
                            <?php endif; ?>
                            <?php if ($r['status'] !== 'ALLOWED'): ?>
                                <a href="<?php echo $link('allow', $r['ip']); ?>">Never block</a>
                            <?php endif; ?>
                            <?php if ($r['status'] !== ''): ?>
                                · <a href="<?php echo $link('unblock', $r['ip']); ?>">Reset</a>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
    <?php
    lg_bb_blocked_panel();
}

/**
 * Per-IP roll-up of the request recorder: who is sending the most requests, and which IPs look like
 * scanners (many different paths, several of them paths only a scanner asks for). Scanner-like first.
 * Search/link-preview crawlers are never flagged.
 */
function lg_bb_rec_sources($hours = 24, $limit = 25)
{
    static $cache = [];
    $key = $hours . '/' . $limit;
    if (isset($cache[$key])) {
        return $cache[$key];
    }
    $since = time() - $hours * 3600;
    $by = [];
    foreach ([lg_bb_rec_file(true), lg_bb_rec_file()] as $file) {
        $h = @fopen($file, 'r');
        if (!$h) {
            continue;
        }
        while (($line = fgets($h)) !== false) {
            if ($line[0] !== '{') {
                continue;
            }
            $r = json_decode($line, true);
            if (!is_array($r) || !isset($r['t'], $r['ip']) || $r['t'] < $since || !lg_bb_rl_public_ip((string) $r['ip']) || lg_bb_sec_is_self((string) $r['ip'])) {
                continue; // (the server's own self-checks and cron are not "sources")
            }
            $ip = (string) $r['ip'];
            if (!isset($by[$ip])) {
                if (count($by) >= 3000) {
                    continue; // bound memory on a very large window
                }
                $by[$ip] = ['ip' => $ip, 'cc' => '', 'ua' => '', 'n' => 0, 'paths' => [], 'probe' => [], 'last' => 0, 'au' => 0, 'tn' => []];
            }
            $b = &$by[$ip];
            $b['n']++;
            $b['au'] += !empty($r['a']) ? 1 : 0;   // requests carrying a CRM Bearer token (a logged-in app, not a bot)
            if (!empty($r['tn']) && count($b['tn']) < 5) {
                $b['tn'][(string) $r['tn']] = true;
            }
            $b['last'] = max($b['last'], (int) $r['t']);
            if (!empty($r['cc'])) {
                $b['cc'] = (string) $r['cc'];
            }
            $b['ua'] = isset($r['ua']) ? (string) $r['ua'] : $b['ua'];
            $p = isset($r['p']) ? (string) $r['p'] : '';
            if (count($b['paths']) < 200) {
                $b['paths'][$p] = true;
            }
            if (lg_bb_looks_like_probe($p) && count($b['probe']) < 40) {
                $b['probe'][$p] = true;
            }
            unset($b);
        }
        fclose($h);
    }
    $trusted = '/googlebot|bingbot|applebot|duckduckbot|facebookexternalhit|meta-externalagent|yandex|baiduspider|semrushbot|ahrefsbot/i';
    $rows = [];
    foreach ($by as $b) {
        $np = count($b['probe']);
        $scanner = $np >= 3 && !preg_match($trusted, $b['ua']);
        $rows[] = [
            'ip' => $b['ip'], 'cc' => $b['cc'], 'ua' => $b['ua'], 'n' => $b['n'], 'last' => $b['last'],
            'paths' => count($b['paths']), 'probes' => $np, 'scanner' => $scanner, 'auth' => $b['au'], 'tenants' => array_keys($b['tn']),
            'sample' => implode(' ', array_slice(array_keys($np ? $b['probe'] : $b['paths']), 0, 4)),
        ];
    }
    usort($rows, function ($a, $b) {
        if ($a['scanner'] !== $b['scanner']) {
            return $a['scanner'] ? -1 : 1;
        }
        return $b['n'] - $a['n'];
    });
    return $cache[$key] = array_slice($rows, 0, $limit);
}

// ---------------------------------------------------------------- abuse reports (manual, one click after a preview)

define('LG_BB_ABUSE_REPEAT_DAYS', 7);   // the same IP is not reported twice within this many days
define('LG_BB_ABUSE_PER_DAY', 20);      // hard cap on reports sent per 24 h from this install

/** Reports already sent: ip => ['t' => unix time, 'to' => address]. */
function lg_bb_abuse_log()
{
    $l = get_option('lg_bb_abuse_log', []);
    return is_array($l) ? $l : [];
}

/** The address the report is sent FROM. Must be on a domain verified in the host's mail add-on (Elastic Email on this server). */
function lg_bb_abuse_from()
{
    if (defined('LG_BB_ABUSE_FROM') && is_email((string) LG_BB_ABUSE_FROM)) {
        return (string) LG_BB_ABUSE_FROM;
    }
    $host = wp_parse_url(home_url(), PHP_URL_HOST);
    return 'security@' . (is_string($host) && $host !== '' ? $host : 'localhost');
}

/** "Report abuse" link for an IP in any table, a "reported" note, or '' when reporting makes no sense (private, allow-listed, you). */
function lg_bb_abuse_link($ip)
{
    static $lists = null, $me = null;
    if ($lists === null) {
        $lists = lg_bb_rl_lists();
        $me = lg_bb_ip();
    }
    if (!is_string($ip) || !lg_bb_rl_public_ip($ip) || $ip === $me || in_array($ip, $lists['allow'], true)) {
        return '';
    }
    $log = lg_bb_abuse_log();
    if (isset($log[$ip]) && (int) $log[$ip]['t'] > time() - LG_BB_ABUSE_REPEAT_DAYS * 86400) {
        return '<span style="color:#555" title="' . esc_attr('Sent to ' . $log[$ip]['to']) . '">reported ' . esc_html(lg_bb_date('M j', (int) $log[$ip]['t'])) . '</span>';
    }
    return '<a href="' . esc_url(wp_nonce_url(admin_url('admin-post.php?action=lg_bb_abuse&op=preview&ip=' . rawurlencode($ip)), 'lg_bb_abuse')) . '">Report abuse</a>';
}

/** First e-mail address of an RDAP entity's vCard, or ''. */
function lg_bb_abuse_vcard_email($ent)
{
    if (empty($ent['vcardArray'][1]) || !is_array($ent['vcardArray'][1])) {
        return '';
    }
    foreach ($ent['vcardArray'][1] as $item) {
        if (is_array($item) && isset($item[0], $item[3]) && $item[0] === 'email' && is_string($item[3]) && is_email($item[3])) {
            return $item[3];
        }
    }
    return '';
}

/** Depth-first search of RDAP entities for the abuse contact's address. */
function lg_bb_abuse_find($entities, $depth = 0)
{
    if (!is_array($entities) || $depth > 4) {
        return '';
    }
    foreach ($entities as $e) {
        if (!is_array($e)) {
            continue;
        }
        if (!empty($e['roles']) && in_array('abuse', (array) $e['roles'], true)) {
            $m = lg_bb_abuse_vcard_email($e);
            if ($m !== '') {
                return $m;
            }
        }
        if (!empty($e['entities'])) {
            $m = lg_bb_abuse_find($e['entities'], $depth + 1);
            if ($m !== '') {
                return $m;
            }
        }
    }
    return '';
}

/**
 * Who runs this IP, from the public RDAP registry (rdap.org redirects to the right regional registry).
 * Cached 7 days. Returns ['abuse' => address or '', 'name', 'range', 'country', 'error'].
 */
function lg_bb_abuse_rdap($ip)
{
    $key = 'lg_bb_rdap_' . substr(sha1($ip), 0, 20);
    $hit = get_transient($key);
    if (is_array($hit)) {
        return $hit;
    }
    $out = ['abuse' => '', 'name' => '', 'range' => '', 'country' => '', 'error' => ''];
    $res = wp_remote_get('https://rdap.org/ip/' . rawurlencode($ip), ['timeout' => 10, 'redirection' => 4, 'headers' => ['Accept' => 'application/rdap+json, application/json']]);
    if (is_wp_error($res)) {
        $out['error'] = 'Registry lookup failed: ' . $res->get_error_message();
        return $out; // not cached: try again next time
    }
    $j = json_decode((string) wp_remote_retrieve_body($res), true);
    if (wp_remote_retrieve_response_code($res) !== 200 || !is_array($j)) {
        $out['error'] = 'Registry lookup returned HTTP ' . (int) wp_remote_retrieve_response_code($res) . '.';
        return $out;
    }
    $out['name'] = isset($j['name']) ? substr(preg_replace('/[^\w.\- ]/', '', (string) $j['name']), 0, 80) : '';
    $out['country'] = isset($j['country']) ? substr(preg_replace('/[^A-Za-z]/', '', (string) $j['country']), 0, 2) : '';
    if (!empty($j['startAddress']) && !empty($j['endAddress'])) {
        $out['range'] = substr((string) $j['startAddress'] . ' - ' . (string) $j['endAddress'], 0, 90);
    }
    $out['abuse'] = lg_bb_abuse_find(isset($j['entities']) ? $j['entities'] : []);
    set_transient($key, $out, 7 * DAY_IN_SECONDS);
    return $out;
}

/** What this install recorded for the IP in the last $hours: total, first/last time and up to 30 sample lines (UTC, method, path; no query strings). */
function lg_bb_abuse_evidence($ip, $hours = 48)
{
    $since = time() - $hours * 3600;
    $n = 0;
    $first = 0;
    $last = 0;
    $probe = [];
    $other = [];
    $methods = ['G' => 'GET', 'P' => 'POST', 'H' => 'HEAD', 'O' => 'OPTIONS'];
    foreach ([lg_bb_rec_file(true), lg_bb_rec_file()] as $file) {
        $h = @fopen($file, 'r');
        if (!$h) {
            continue;
        }
        while (($line = fgets($h)) !== false) {
            if ($line[0] !== '{') {
                continue;
            }
            $r = json_decode($line, true);
            if (!is_array($r) || !isset($r['t'], $r['ip']) || $r['ip'] !== $ip || $r['t'] < $since) {
                continue;
            }
            $n++;
            $first = $first ? min($first, (int) $r['t']) : (int) $r['t'];
            $last = max($last, (int) $r['t']);
            $p = isset($r['p']) ? (string) $r['p'] : '';
            $mk = isset($r['m']) ? (string) $r['m'] : '?';
            $row = gmdate('Y-m-d H:i:s', (int) $r['t']) . 'Z ' . (isset($methods[$mk]) ? $methods[$mk] : $mk) . ' ' . $p;
            if (lg_bb_looks_like_probe($p)) {
                if (count($probe) < 30) {
                    $probe[] = $row;
                }
            } elseif (count($other) < 10) {
                $other[] = $row;
            }
        }
        fclose($h);
    }
    // Scanner-only paths first (that is the complaint), then a few others for context.
    $lines = array_slice(array_merge($probe, $other), 0, 30);
    // The probe shield and the gate keep their own per-IP counters for requests they refused before WordPress loaded.
    $extra = 0;
    foreach ([lg_bb_rl_dir() . '/probe-' . substr(sha1($ip), 0, 20) . '.php', lg_bb_blk_file($ip)] as $f) {
        $rec = lg_bb_rl_read($f);
        if (is_array($rec)) {
            $extra += (int) (isset($rec['n']) ? $rec['n'] : 0) + (int) (isset($rec['denied']) ? $rec['denied'] : 0);
            if (!empty($rec['first'])) {
                $first = $first ? min($first, (int) $rec['first']) : (int) $rec['first'];
            }
            if (!empty($rec['last'])) {
                $last = max($last, (int) $rec['last']);
            }
        }
    }
    return ['n' => $n, 'extra' => $extra, 'first' => $first, 'last' => $last, 'lines' => $lines];
}

/** Subject and body of the report. Built on the server at send time; nothing the browser posts goes into it. */
function lg_bb_abuse_message($ip, $net, $ev)
{
    $host = (string) wp_parse_url(home_url(), PHP_URL_HOST);
    $subject = 'Abuse report: scanning from ' . $ip . ' (' . gmdate('Y-m-d') . ' UTC)';
    $b = [];
    $b[] = 'Hello,';
    $b[] = '';
    $b[] = 'The address ' . $ip . ($net['name'] !== '' ? ' (network ' . $net['name'] . ($net['range'] !== '' ? ', ' . $net['range'] : '') . ')' : '')
        . ' is sending automated requests to our web server (' . $host . ') that probe for hidden files, credentials and admin interfaces'
        . ' (for example .env, /actuator, credentials files). It is not a normal visitor or a search engine.';
    $b[] = '';
    $b[] = 'Our logs show ' . ((int) $ev['n'] + (int) $ev['extra']) . ' requests'
        . ($ev['first'] ? ' between ' . gmdate('Y-m-d H:i:s', (int) $ev['first']) . 'Z and ' . gmdate('Y-m-d H:i:s', (int) $ev['last']) . 'Z' : '') . '. Times are UTC. Sample:';
    $b[] = '';
    foreach ($ev['lines'] as $l) {
        $b[] = '  ' . $l;
    }
    if (!$ev['lines']) {
        $b[] = '  (the sample lines have rotated out of our recorder; the counts above come from our block records)';
    }
    $b[] = '';
    $b[] = 'Please investigate the host using this address and stop the activity. Reply to this message if you need more detail. No personal data of our visitors is included in this report.';
    $b[] = '';
    $b[] = 'Sent by the site administrator of ' . $host . '.';
    return [$subject, implode("\n", $b)];
}

add_action('admin_post_lg_bb_abuse', function () {
    lg_bb_admin_guard('lg_bb_abuse');
    $op = isset($_REQUEST['op']) ? (string) $_REQUEST['op'] : '';
    $ip = isset($_REQUEST['ip']) ? trim((string) wp_unslash($_REQUEST['ip'])) : '';
    $back = admin_url('tools.php?page=lg-blackbox');
    $done = function ($msg) use ($back) {
        wp_safe_redirect(add_query_arg('lgmsg', rawurlencode($msg), $back) . '#lg-sources');
        exit;
    };
    if (!lg_bb_rl_public_ip($ip)) {
        $done('Not reported: ' . $ip . ' is not a public address.');
    }
    $lists = lg_bb_rl_lists();
    if ($ip === lg_bb_ip() || in_array($ip, $lists['allow'], true)) {
        $done('Not reported: that address is yours or on the "never block" list.');
    }
    $log = lg_bb_abuse_log();
    if (isset($log[$ip]) && (int) $log[$ip]['t'] > time() - LG_BB_ABUSE_REPEAT_DAYS * 86400) {
        $done($ip . ' was already reported on ' . lg_bb_date('M j', (int) $log[$ip]['t']) . ' to ' . $log[$ip]['to'] . '.');
    }
    $net = lg_bb_abuse_rdap($ip);
    $ev = lg_bb_abuse_evidence($ip);
    list($subject, $body) = lg_bb_abuse_message($ip, $net, $ev);
    $me = wp_get_current_user();

    if ($op === 'send') {
        $to = isset($_POST['to']) ? trim((string) wp_unslash($_POST['to'])) : '';
        if (!is_email($to)) {
            $done('Not sent: "' . $to . '" is not a valid e-mail address.');
        }
        $today = 0;
        foreach ($log as $v) {
            $today += ((int) $v['t'] > time() - 86400) ? 1 : 0;
        }
        if ($today >= LG_BB_ABUSE_PER_DAY) {
            $done('Not sent: ' . LG_BB_ABUSE_PER_DAY . ' abuse reports already went out in the last 24 hours.');
        }
        $headers = ['Content-Type: text/plain; charset=UTF-8', 'From: LG Black Box <' . lg_bb_abuse_from() . '>'];
        if (is_email($me->user_email)) {
            $headers[] = 'Reply-To: ' . $me->user_email;
            $headers[] = 'Cc: ' . $me->user_email;
        }
        $ok = wp_mail($to, $subject, $body, $headers);
        if (!$ok) {
            $done('The report could not be sent (the mail service refused it). Check that ' . lg_bb_abuse_from() . ' is on a domain verified in the mail add-on, or set LG_BB_ABUSE_FROM in wp-config.php.');
        }
        $log[$ip] = ['t' => time(), 'to' => $to];
        if (count($log) > 200) {
            $log = array_slice($log, -200, null, true);
        }
        update_option('lg_bb_abuse_log', $log, false);
        $done('Abuse report for ' . $ip . ' sent to ' . $to . ' (a copy went to ' . (is_email($me->user_email) ? $me->user_email : 'nobody: your profile has no e-mail') . ').');
    }

    // Preview page: nothing is sent until the button below is pressed.
    nocache_headers();
    header('Content-Type: text/html; charset=utf-8');
    $nonce = wp_create_nonce('lg_bb_abuse');
    echo '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Report abuse</title>'
        . '<style>body{font:14px/1.5 -apple-system,Segoe UI,sans-serif;max-width:780px;margin:2em auto;padding:0 1em;color:#1d2327}pre{background:#f6f7f7;border:1px solid #dcdcde;padding:1em;white-space:pre-wrap}'
        . 'input[type=email]{width:100%;max-width:420px;padding:6px}button{display:inline-block;padding:8px 16px;border:1px solid #2271b1;background:#2271b1;color:#fff;border-radius:3px;cursor:pointer}a.c{margin-left:1em}.w{background:#fcf9e8;border-left:4px solid #dba617;padding:8px 12px}</style></head><body>';
    echo '<h1>Report abuse: ' . esc_html($ip) . '</h1>';
    echo '<p><strong>Network:</strong> ' . esc_html($net['name'] !== '' ? $net['name'] : 'unknown') . ($net['range'] !== '' ? ' (' . esc_html($net['range']) . ')' : '') . ($net['country'] !== '' ? ', ' . esc_html($net['country']) : '')
        . '<br><small>Looked up in the public RDAP registry (the address was sent to rdap.org for this lookup).</small></p>';
    if ($net['error'] !== '') {
        echo '<p class="w">' . esc_html($net['error']) . '</p>';
    }
    if ($net['abuse'] === '') {
        echo '<p class="w">The registry lists no abuse contact for this address. Look one up yourself (for example on the registry page for this range) and type it below, or do not report.</p>';
    }
    echo '<p>This is exactly what will be sent. Nothing is sent until you press the button.</p>';
    echo '<p><strong>Subject:</strong> ' . esc_html($subject) . '</p><pre>' . esc_html($body) . '</pre>';
    echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">'
        . '<input type="hidden" name="action" value="lg_bb_abuse"><input type="hidden" name="op" value="send"><input type="hidden" name="ip" value="' . esc_attr($ip) . '">'
        . '<input type="hidden" name="_wpnonce" value="' . esc_attr($nonce) . '">'
        . '<p><label><strong>Send to</strong><br><input type="email" name="to" required value="' . esc_attr($net['abuse']) . '"></label></p>'
        . '<p>From <code>' . esc_html(lg_bb_abuse_from()) . '</code>' . (is_email($me->user_email) ? ', reply-to and copy to <code>' . esc_html($me->user_email) . '</code>' : '') . '.</p>'
        . '<button type="submit">Send the report</button><a class="c" href="' . esc_url($back) . '">Cancel</a></form>';
    echo '</body></html>';
    exit;
});

/** Admin panel: who is sending the most requests (scanner-like IPs flagged) with a Block button, and the site-wide block list. */
function lg_bb_blocked_panel()
{
    $lists = lg_bb_rl_lists();
    $sources = lg_bb_rec_sources(24, 25);
    ?>
    <h3 id="lg-sources">Request sources, last 24 h (from the burst recorder)</h3>
    <p>The IPs sending the most requests that reached WordPress. <strong>Scanner-like</strong> = at least 3 requests for paths only a
        vulnerability scanner asks for (<code>.env</code>, <code>/actuator</code>, <code>credentials.json</code>…) from a client that is not a
        search or link-preview crawler. Nothing is blocked automatically from this table: use the button.</p>
    <?php if (!$sources): ?>
        <p>Nothing recorded yet (is the burst recorder on?).</p>
    <?php else: ?>
        <table class="widefat striped" style="margin-bottom:1em">
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Country</th>
                    <th>Requests</th>
                    <th>Distinct paths</th>
                    <th>Scanner paths</th>
                    <th>Last seen</th>
                    <th>Client</th>
                    <th>Paths (sample)</th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($sources as $s): ?>
                    <tr<?php echo $s['scanner'] ? ' style="background:#fcf0f1"' : ''; ?>>
                        <td><?php echo esc_html($s['ip']); ?><?php echo $s['scanner'] ? ' <strong style="color:#b32d2e">scanner-like</strong>' : ''; ?></td>
                        <td><?php echo esc_html(lg_bb_cc_label($s['cc'])); ?></td>
                        <td><?php echo (int) $s['n']; ?></td>
                        <td><?php echo (int) $s['paths']; ?></td>
                        <td><?php echo (int) $s['probes']; ?></td>
                        <td><?php echo $s['last'] ? lg_bb_t($s['last']) : ''; ?></td>
                        <td style="font-size:11px"><?php echo esc_html($s['ua']); ?></td>
                        <td><code style="font-size:11px"><?php echo esc_html($s['sample']); ?></code><?php
                            if (!empty($s['auth'])) {
                                echo '<br><strong style="color:#996800">' . (int) $s['auth'] . ' logged-in CRM API calls from this IP (an office or a phone?). Check before blocking: it may be a customer.</strong>';
                            }
                            if (!empty($s['tenants'])) {
                                echo '<br>tenant: ' . esc_html(implode(', ', array_map('lg_bb_tenant_label', $s['tenants'])));
                            }
                        ?></td>
                        <td><?php $bl = lg_bb_block_link($s['ip']); echo $bl !== '' ? $bl : (in_array($s['ip'], $lists['allow'], true) ? 'never block' : 'you'); if ($s['scanner'] && empty($s['auth'])) { $al = lg_bb_abuse_link($s['ip']); echo $al !== '' ? '<br>' . $al : ''; } ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>

    <?php $acfg = lg_bb_rl_cfg(); $autos = lg_bb_auto_list(); ?>
    <h3 id="lg-auto">Automatic blocks (repeat offenders)</h3>
    <p>Status: <strong><?php echo !empty($acfg['auto']) ? 'ON' : 'OFF'; ?></strong>.
        When on, an IP that keeps scanning (blocked twice by the probe shield) or keeps failing logins (locked out 3 times) is refused on every request for
        <?php echo (int) $acfg['auto_days']; ?> days, before WordPress loads. It never applies to an IP on the "never block" list or to an IP that has made logged-in CRM
        calls, and every entry expires by itself; Unblock removes it at once.
        <a href="<?php echo esc_url(lg_bb_ip_action_url(!empty($acfg['auto']) ? 'auto_off' : 'auto_on', '0.0.0.0')); ?>"><?php echo !empty($acfg['auto']) ? 'Turn off' : 'Turn on'; ?></a></p>
    <?php if ($autos): ?>
        <table class="widefat striped" style="max-width:900px;margin-bottom:1em">
            <thead><tr><th>IP</th><th>Why</th><th>Since</th><th>Requests refused</th><th>Expires</th><th></th></tr></thead>
            <tbody>
                <?php foreach ($autos as $ar): ?>
                    <tr>
                        <td><?php echo esc_html($ar['ip']); ?></td>
                        <td><?php echo esc_html(isset($ar['why']) ? $ar['why'] : ''); ?></td>
                        <td><?php echo lg_bb_t((int) $ar['first']); ?></td>
                        <td><?php echo (int) (isset($ar['n']) ? $ar['n'] : 0); ?></td>
                        <td><?php echo esc_html(lg_bb_date('M j', (int) $ar['until'])); ?></td>
                        <td><a href="<?php echo esc_url(lg_bb_ip_action_url('unauto', $ar['ip'])); ?>">Unblock</a><?php $al = lg_bb_abuse_link($ar['ip']); echo $al !== '' ? ' · ' . $al : ''; ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>

    <?php $overs = lg_bb_over_list(); ?>
    <h3 id="lg-rate">Request-rate limit and wp-cron guard</h3>
    <p>Request-rate limit: <strong><?php echo !empty($acfg['rate']) ? 'ON' : 'OFF'; ?></strong>
        (<a href="<?php echo esc_url(lg_bb_ip_action_url(!empty($acfg['rate']) ? 'rate_off' : 'rate_on', '0.0.0.0')); ?>"><?php echo !empty($acfg['rate']) ? 'turn off' : 'turn on'; ?></a>).
        An IP (IPv6: a whole /64) that sends more than <?php echo (int) $acfg['rate_limit']; ?> PHP requests a minute, or <?php echo (int) $acfg['rate_limit_auth']; ?> when it presents a
        login (CRM token or WordPress cookie), or <?php echo (int) $acfg['rate_limit_bot']; ?> when it is an aggressive crawler, gets a 429 before WordPress loads. Five over-limit
        minutes within an hour put it on the automatic list for <?php echo (int) $acfg['rate_auto_days']; ?> day(s). Never for an allow-listed IP; search crawlers only get the 429.<br>
        wp-cron guard: <strong><?php echo !empty($acfg['cron_guard']) ? 'ON' : 'OFF'; ?></strong>
        (<a href="<?php echo esc_url(lg_bb_ip_action_url(!empty($acfg['cron_guard']) ? 'cron_off' : 'cron_on', '0.0.0.0')); ?>"><?php echo !empty($acfg['cron_guard']) ? 'turn off' : 'turn on'; ?></a>).
        wp-cron.php answers only the server itself, so nobody else can make WordPress load by calling it.<br>
        <?php
        $selfj = lg_bb_rl_read(lg_bb_rl_dir() . '/self.php');
        $deny = lg_bb_rl_read(lg_bb_rl_dir() . '/cron-denied.php');
        ?>
        Server addresses the guard lets through: <strong><?php echo esc_html(is_array($selfj) && !empty($selfj['ips']) ? implode(', ', (array) $selfj['ips']) : 'none known (guard inactive)'); ?></strong>
        (<a href="<?php echo esc_url(lg_bb_ip_action_url('self_refresh', '0.0.0.0')); ?>">re-detect</a>).
        <?php if (is_file(lg_bb_rl_dir() . '/cron-guard-off')): ?>
            <br><strong>The guard is switched off by the file rl/cron-guard-off</strong> (delete it, or press &laquo;turn on&raquo;, to bring it back).
        <?php endif; ?>
        <?php if (is_array($deny) && !empty($deny['ip'])): ?>
            <br>Last cron call refused: <code><?php echo esc_html($deny['ip']); ?></code> at <?php echo esc_html(gmdate('Y-m-d H:i', (int) $deny['t'])); ?> UTC.
            If that is this server, press &laquo;re-detect&raquo; or &laquo;turn off&raquo;.
        <?php endif; ?>
        <br><small>Emergency, without WordPress: <code>wp lg-bb cron-guard off</code>, or create an empty file <code>wp-content/lg-blackbox/rl/cron-guard-off</code>, or define <code>LG_BB_CRON_GUARD_OFF</code> as true in wp-config.php.</small></p>
    <?php if ($overs): ?>
        <table class="widefat striped" style="max-width:900px;margin-bottom:1em">
            <thead><tr><th>IP</th><th>Minutes over the limit (last hour)</th><th>Last</th><th>Path</th><th></th></tr></thead>
            <tbody>
                <?php foreach (array_slice($overs, 0, 15) as $ov): ?>
                    <tr>
                        <td><?php echo esc_html($ov['ip']); ?></td>
                        <td><?php echo (int) $ov['n']; ?></td>
                        <td><?php echo lg_bb_t((int) $ov['last']); ?></td>
                        <td><code style="font-size:11px"><?php echo esc_html(isset($ov['p']) ? $ov['p'] : ''); ?></code></td>
                        <td><?php $bl = lg_bb_block_link($ov['ip']); echo $bl; $al = lg_bb_abuse_link($ov['ip']); echo $al !== '' ? ' · ' . $al : ''; ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>

    <h3 id="lg-blocked">Blocked IPs (site-wide)</h3>
    <p>Every request from these IPs is refused with a 403 by the gate, before WordPress loads (cheap, but PHP still starts, so for a heavy
        attacker also block the IP in Cloudflare: paste the list below into a WAF custom rule or an IP list). Never applies to an IP on the
        "never block" list, so you cannot lock yourself out.</p>
    <?php if (!$lists['block_all']): ?>
        <p>No IP is blocked site-wide.</p>
    <?php else: ?>
        <table class="widefat striped" style="max-width:760px;margin-bottom:1em">
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Requests refused</th>
                    <th>Last refused</th>
                    <th>Last path</th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($lists['block_all'] as $ip): ?>
                    <?php $rec = lg_bb_rl_read(lg_bb_blk_file($ip)); ?>
                    <tr>
                        <td><?php echo esc_html($ip); ?></td>
                        <td><?php echo is_array($rec) ? (int) $rec['n'] : 0; ?></td>
                        <td><?php echo is_array($rec) && !empty($rec['last']) ? lg_bb_t((int) $rec['last']) : '-'; ?></td>
                        <td><code style="font-size:11px"><?php echo is_array($rec) && isset($rec['p']) ? esc_html($rec['p']) : ''; ?></code></td>
                        <td><a href="<?php echo esc_url(lg_bb_ip_action_url('unblock', $ip)); ?>">Unblock</a><?php $al = lg_bb_abuse_link($ip); echo $al !== '' ? ' · ' . $al : ''; ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <p><label for="lg-bb-cf"><strong>For Cloudflare</strong> (one IP per line):</label><br>
            <textarea id="lg-bb-cf" readonly rows="<?php echo (int) min(8, max(2, count($lists['block_all']))); ?>" style="width:100%;max-width:360px;font-family:monospace"><?php echo esc_textarea(implode("\n", $lists['block_all'])); ?></textarea></p>
        <?php if (!lg_bb_gate_installed()): ?>
            <p><strong style="color:#b32d2e">The gate file is missing, so these blocks are NOT being enforced.</strong> Adding or removing a block reinstalls it.</p>
        <?php endif; ?>
    <?php endif; ?>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-bottom:1em">
        <input type="hidden" name="action" value="lg_bb_login">
        <input type="hidden" name="op" value="blockall">
        <?php wp_nonce_field('lg_bb_login'); ?>
        Block an IP by hand: <input type="text" name="ip" placeholder="e.g. 203.0.113.7" style="width:220px" required>
        <button class="button" onclick="return confirm('Refuse every request from this IP?')">Block site-wide</button>
    </form>
    <?php
}

// ---------------------------------------------------------------- admin page

add_action('admin_menu', function () {
    add_management_page('LG Black Box', 'LG Black Box', 'manage_options', 'lg-blackbox', 'lg_bb_page');
});

function lg_bb_admin_guard($action)
{
    if (!current_user_can('manage_options')) {
        wp_die('Forbidden', 403);
    }
    check_admin_referer($action);
}

add_action('admin_post_lg_bb_download', function () {
    lg_bb_admin_guard('lg_bb_download');
    nocache_headers();
    header('Content-Type: text/plain; charset=utf-8');
    header('Content-Disposition: attachment; filename="lg-blackbox-raw-' . gmdate('Ymd-His') . '.txt"');
    foreach ([lg_bb_logfile(true), lg_bb_logfile()] as $f) {
        $h = @fopen($f, 'r');
        if ($h) {
            while (($line = fgets($h)) !== false) {
                if ($line[0] === '{') {
                    echo $line;
                }
            }
            fclose($h);
        }
    }
    exit;
});

add_action('admin_post_lg_bb_report', function () {
    lg_bb_admin_guard('lg_bb_report');
    $hours = isset($_GET['hours']) ? max(1, min(168, (int) $_GET['hours'])) : 6;
    nocache_headers();
    header('Content-Type: text/plain; charset=utf-8');
    header('Content-Disposition: attachment; filename="lg-blackbox-report-' . gmdate('Ymd-His') . '.txt"');
    echo lg_bb_report($hours);
    exit;
});

/**
 * Plain-text report meant to be pasted into a chat: compact pipe-separated lines,
 * incident windows kept in full, quiet periods thinned to fit (~140 sample lines).
 */
function lg_bb_report($hours = 6)
{
    $a = lg_bb_analyze(lg_bb_load_rows());
    $since = time() - $hours * 3600;
    $f = function ($t) {
        return lg_bb_date('m-d H:i:s', (int) $t);
    };
    $L = [];
    $L[] = 'LG BLACK BOX REPORT - generated ' . lg_bb_date('Y-m-d H:i:s') . ' (' . lg_bb_tz_label() . '; all times below are in this zone), window: last ' . $hours . 'h';
    $L[] = 'site: ' . wp_parse_url(home_url(), PHP_URL_HOST) . ' | WP ' . get_bloginfo('version') . ' | plugin v' . (defined('LG_BB_VERSION') ? LG_BB_VERSION : '?');

    $cfg = [];
    foreach (lg_bb_cfg() as $k => $v) {
        $cfg[] = $k . '=' . $v;
    }
    $L[] = 'CONFIG: ' . implode('; ', $cfg);

    $cs = lg_bb_cron_stats();
    $ov = [];
    foreach (array_slice($cs['overdue'], 0, 5) as $o) {
        $ov[] = $o[1] . ' (' . $o[0] . 's late)';
    }
    $many = [];
    foreach (array_slice($cs['by_hook'], 0, 5, true) as $hk => $n) {
        $many[] = $hk . ' x' . $n;
    }
    $L[] = 'CRON: ' . $cs['total'] . ' events, ' . $cs['size_kb'] . ' KB stored, ' . count($cs['overdue']) . ' overdue >60s [' . implode(', ', $ov) . ']; most pending: ' . implode(', ', $many);

    $pr = lg_bb_procs(10);
    if ($pr) {
        $x = [];
        foreach ($pr['top'] as $t) {
            $x[] = $t[0] . ' x' . $t[1] . '=' . $t[2] . 'MB(max ' . $t[3] . ')';
        }
        $L[] = 'PROCESSES NOW (RSS by name, whole server): ' . implode(', ', $x);
        if (!empty($pr['pools'])) {
            $px = [];
            foreach ($pr['pools'] as $pl) {
                $px[] = $pl[0] . ($pl[0] === $pr['own_pool'] ? '(THIS SITE)' : '') . ' x' . $pl[1] . '=' . $pl[2] . 'MB';
            }
            $L[] = 'PHP POOLS NOW (' . (isset($pr['pools_total']) ? $pr['pools_total'] : count($pr['pools'])) . ' applications with workers; ' . (isset($pr['pool_other']) ? $pr['pool_other'][0] . ' master/unnamed php processes=' . $pr['pool_other'][1] . 'MB' : '') . '): ' . implode(', ', $px);
        }
    } else {
        $L[] = 'PROCESSES NOW: /proc not readable';
    }

    // Incidents
    $inc = array_values(array_filter($a['inc'], function ($i) use ($since) {
        return $i['t'] >= $since;
    }));
    $L[] = '';
    $L[] = '== INCIDENTS in window (' . count($inc) . ') ==';
    foreach ($inc as $i) {
        $L[] = $f($i['t']) . ' | ' . $i['what'] . ' | ' . $i['detail'];
    }

    // Login activity
    $rl = lg_bb_rl_cfg();
    $L[] = '';
    $L[] = '== LOGIN ATTEMPTS, window (protection ' . (!empty($rl['enabled']) && lg_bb_gate_installed() ? 'ON: ' . $rl['limit'] . ' failures/' . $rl['window'] . ' min -> block ' . $rl['block'] . ' min' : 'OFF') . ') ==';
    $L[] = 'country filter: ' . (lg_bb_geo_on() && lg_bb_gate_installed() ? 'ON, allowed ' . implode(',', $rl['geo_countries']) : 'OFF') . ' | your country as seen by server: ' . (lg_bb_cc() !== '' ? lg_bb_cc() : 'not received');
    $auth_rows = lg_bb_auth_table($hours);
    $gs = [];
    foreach (array_slice(lg_bb_geo_summary($auth_rows), 0, 10) as $g) {
        $gs[] = $g['cc'] . ' ' . $g['ips'] . ' IP/' . $g['n'] . ' attempts/' . $g['f'] . ' failed' . ($g['geo'] ? '/' . $g['geo'] . ' refused' : '');
    }
    $L[] = 'by country: ' . ($gs ? implode('; ', $gs) : 'none');
    $L[] = 'ip | country | attempts | failed | endpoints | last seen | status';
    foreach (array_slice($auth_rows, 0, 12) as $r) {
        $L[] = $r['ip'] . ' | ' . ($r['cc'] !== '' ? $r['cc'] : '-') . ' | ' . ($r['n'] + $r['geo']) . ' | ' . $r['f'] . ' | ' . $r['kinds'] . ' | ' . ($r['last'] ? $f($r['last']) : '-') . ' | ' . $r['status'];
    }

    // Scanner probes answered by the gate (these never reach WordPress, so they are not in the request lists).
    $pr = lg_bb_probe_table($hours);
    $L[] = '';
    $L[] = '== PROBE SHIELD (' . (lg_bb_probe_on() && lg_bb_gate_installed() ? 'ON: block after ' . $rl['probe_limit'] . ' probes/' . $rl['probe_window'] . ' min for ' . $rl['probe_block'] . ' min' : 'OFF') . '), ' . count($pr) . ' IPs ==';
    if ($pr) {
        $L[] = 'ip | country | probes | last seen | status | paths tried';
        foreach (array_slice($pr, 0, 10) as $r) {
            $L[] = $r['ip'] . ' | ' . ($r['cc'] !== '' ? $r['cc'] : '-') . ' | ' . $r['n'] . ' | ' . ($r['last'] ? $f($r['last']) : '-') . ' | ' . $r['status'] . ' | ' . $r['paths'];
        }
    }

    // IPs blocked site-wide by hand, and IPs that look like scanners but are NOT blocked yet (candidates for the Block button).
    $bl_all = lg_bb_rl_lists();
    $L[] = '';
    $L[] = '== BLOCKED SITE-WIDE (' . count($bl_all['block_all']) . ') ==' . ($bl_all['block_all'] && !lg_bb_gate_installed() ? ' WARNING: gate file missing, NOT enforced' : '');
    foreach (array_slice($bl_all['block_all'], 0, 15) as $bip) {
        $brec = lg_bb_rl_read(lg_bb_blk_file($bip));
        $L[] = $bip . ' | refused ' . (is_array($brec) ? (int) $brec['n'] : 0) . ' requests' . (is_array($brec) && !empty($brec['last']) ? ', last ' . $f((int) $brec['last']) : '');
    }
    $auto_rows = lg_bb_auto_list();
    $L[] = '';
    $L[] = '== AUTO-BLOCKED REPEAT OFFENDERS (' . count($auto_rows) . ', automatic blocks ' . (!empty(lg_bb_rl_cfg()['auto']) ? 'ON' : 'OFF') . ') ==';
    foreach (array_slice($auto_rows, 0, 15) as $ar) {
        $L[] = $ar['ip'] . ' | ' . (isset($ar['why']) ? $ar['why'] : '') . ' | since ' . $f((int) $ar['first']) . ' | refused ' . (int) (isset($ar['n']) ? $ar['n'] : 0) . ' requests | expires ' . gmdate('Y-m-d', (int) $ar['until']);
    }
    $ovr = lg_bb_over_list();
    $L[] = '';
    $L[] = '== REQUEST-RATE LIMIT (' . (!empty(lg_bb_rl_cfg()['rate']) ? 'ON' : 'OFF') . ', wp-cron guard ' . (!empty(lg_bb_rl_cfg()['cron_guard']) ? 'ON' : 'OFF') . '): ' . count($ovr) . ' IPs refused in the last day ==';
    foreach (array_slice($ovr, 0, 10) as $ov) {
        $L[] = $ov['ip'] . ' | ' . (int) $ov['n'] . ' minutes over ' . (isset($ov['limit']) ? (int) $ov['limit'] : 0) . '/min | last ' . $f((int) $ov['last']) . ' | ' . (isset($ov['p']) ? $ov['p'] : '');
    }
    $L[] = '';
    foreach (lg_bb_sec_report_lines() as $sl) {
        $L[] = $sl;
    }
    $cand = array_filter(lg_bb_rec_sources($hours, 25), function ($s) use ($bl_all) {
        return $s['scanner'] && !in_array($s['ip'], $bl_all['block_all'], true) && !in_array($s['ip'], $bl_all['allow'], true);
    });
    if ($cand) {
        $L[] = '';
        $L[] = '== SCANNER-LIKE IPs NOT BLOCKED (use Block site-wide on the Tools > LG Black Box page) ==';
        $L[] = 'ip | country | requests | distinct paths | scanner paths | last seen | sample';
        foreach (array_slice($cand, 0, 10) as $s) {
            $L[] = $s['ip'] . ' | ' . ($s['cc'] !== '' ? $s['cc'] : '-') . ' | ' . $s['n'] . ' | ' . $s['paths'] . ' | ' . $s['probes'] . ' | ' . ($s['last'] ? $f($s['last']) : '-') . ' | ' . $s['sample'];
        }
    }

    // Every request that reached WordPress (burst recorder): who made the busy minutes, and the minutes before each incident.
    foreach (lg_bb_rec_report($hours, $inc) as $line) {
        $L[] = $line;
    }

    // Samples: keep everything near an incident or looking busy, thin the rest.
    $hbw = array_values(array_filter($a['hb'], function ($h) use ($since) {
        return $h['t'] >= $since;
    }));
    $prot = [];
    $rest = [];
    foreach ($hbw as $idx => $h) {
        $keep = false;
        foreach ($inc as $i) {
            if ($h['t'] >= $i['t'] - 1200 && $h['t'] <= $i['t'] + 600) {
                $keep = true;
                break;
            }
        }
        $busy = (isset($h['load'][0]) && $h['load'][0] > 4)
            || (isset($h['mem_avail']) && $h['mem_avail'] < 500)
            || (isset($h['psi_some']) && $h['psi_some'] > 5)
            || !empty($h['inf']['long']) || !empty($h['pl']) || (isset($h['auth']['n1']) && $h['auth']['n1'] >= 10) || !empty($h['p']['disk']) && $h['p']['disk'] >= 3;
        if ($keep || $busy) {
            $prot[$idx] = true;
        } else {
            $rest[] = $idx;
        }
    }
    $budget = max(20, 140 - count($prot));
    $step = count($rest) > $budget ? (int) ceil(count($rest) / $budget) : 1;
    foreach ($rest as $n => $idx) {
        if ($n % $step === 0) {
            $prot[$idx] = true;
        }
    }
    ksort($prot);
    $L[] = '';
    $L[] = '== SAMPLES (' . count($prot) . ' of ' . count($hbw) . '; incident windows and busy moments kept in full) ==';
    $L[] = 'time | load 1/5/15 | avail MB | swap MB | mem PSI some/full | mariadb MB | php procs/MB | running/disk-wait | db uptime s | db conn/running | in-flight (this site only) | top CPU % (100=1 core; fpm:NAME* = this site, other fpm:NAME = another app on the server) | notes';
    foreach (array_keys($prot) as $idx) {
        $h = $hbw[$idx];
        $notes = [];
        if (!empty($h['inf']['long'])) {
            foreach ($h['inf']['long'] as $x) {
                $notes[] = 'LONG ' . $x[0] . 's ' . $x[1];
            }
        }
        if (!empty($h['pl'])) {
            foreach (array_slice($h['pl'], 0, 3) as $x) {
                $notes[] = 'SQL ' . $x[0] . 's ' . $x[2];
            }
        }
        if (!empty($h['auth'])) {
            $notes[] = lg_bb_auth_str($h['auth']);
        }
        // When PHP is busy, say WHOSE workers they are: "name n/running", * = this site's pool, others are other applications.
        if (!empty($h['p']['pools']) && ((isset($h['p']['run']) && $h['p']['run'] >= 6) || $h['p']['php_n'] >= 30)) {
            $pp = [];
            foreach (array_slice($h['p']['pools'], 0, 4) as $pl) {
                $pp[] = $pl[0] . (isset($h['p']['own_pool']) && $pl[0] === $h['p']['own_pool'] ? '*' : '') . ' ' . $pl[1] . '/' . $pl[3];
            }
            $notes[] = 'fpm pools(workers/running): ' . implode(', ', $pp);
        }
        $L[] = $f($h['t']) . ' | '
            . (isset($h['load']) ? implode('/', $h['load']) : '-') . ' | '
            . (isset($h['mem_avail']) ? $h['mem_avail'] : '-') . ' | '
            . (isset($h['swap_used']) ? $h['swap_used'] : '-') . ' | '
            . (isset($h['psi_some']) ? $h['psi_some'] . '/' . (isset($h['psi_full']) ? $h['psi_full'] : '-') : '-') . ' | '
            . (isset($h['p']) ? $h['p']['db_mb'] : '-') . ' | '
            . (isset($h['p']) ? $h['p']['php_n'] . '/' . $h['p']['php_mb'] : '-') . ' | '
            . (isset($h['p']['run']) ? $h['p']['run'] . '/' . $h['p']['disk'] : '-') . ' | '
            . (isset($h['db']['up']) ? $h['db']['up'] : (isset($h['db']['err']) ? 'ERR ' . $h['db']['err'] : '-')) . ' | '
            . (isset($h['db']['conn']) ? $h['db']['conn'] . '/' . $h['db']['run'] : '-') . ' | '
            . (isset($h['inf']['n']) ? $h['inf']['n'] : '-') . ' | '
            . (!empty($h['p']['cpu']) ? lg_bb_cpu_str($h['p']['cpu']) : '-') . ' | '
            . implode(' ; ', $notes);
    }

    // Requests
    $rq = array_values(array_filter($a['req'], function ($r) use ($since) {
        return $r['t'] >= $since;
    }));
    $total_rq = count($rq);

    // Who sent them: ALL logged slow/heavy requests in the window rolled up per client (IPv6 grouped by /48),
    // and per 10-minute bucket, so a burst is attributable even when the 60-row list below cuts it off.
    $cl = [];
    $bk = [];
    $tt = [];
    foreach ($rq as $r) {
        $tk = !empty($r['tn']) ? (string) $r['tn'] : '-';
        if (!isset($tt[$tk])) {
            $tt[$tk] = ['n' => 0, 'ms' => 0, 'cpu' => 0, 'max' => 0, 'peak' => 0, 'paths' => []];
        }
        $tt[$tk]['n']++;
        $tt[$tk]['ms'] += $r['ms'];
        $tt[$tk]['cpu'] += $r['cpu'];
        $tt[$tk]['max'] = max($tt[$tk]['max'], $r['ms']);
        $tt[$tk]['peak'] = max($tt[$tk]['peak'], $r['peak']);
        $tpath = preg_replace('/\?.*$/', '', (string) $r['uri']);
        $tt[$tk]['paths'][$tpath] = isset($tt[$tk]['paths'][$tpath]) ? $tt[$tk]['paths'][$tpath] + 1 : 1;
        $g = lg_bb_ip_group($r['ip']);
        $ua = lg_bb_ua_short($r['ua']);
        $key = $g . ' | ' . $ua;
        if (!isset($cl[$key])) {
            $cl[$key] = ['g' => $g, 'ua' => $ua, 'n' => 0, 'ms' => 0, 'cpu' => 0, 'max' => 0, 't0' => $r['t'], 't1' => $r['t'], 'paths' => [], 'st' => []];
        }
        $c = &$cl[$key];
        $c['n']++;
        $c['ms'] += $r['ms'];
        $c['cpu'] += $r['cpu'];
        $c['max'] = max($c['max'], $r['ms']);
        $c['t0'] = min($c['t0'], $r['t']);
        $c['t1'] = max($c['t1'], $r['t']);
        $p = $r['m'] . ' ' . preg_replace('/\?.*$/', '', (string) $r['uri']);
        $c['paths'][$p] = isset($c['paths'][$p]) ? $c['paths'][$p] + 1 : 1;
        $c['st'][$r['st']] = isset($c['st'][$r['st']]) ? $c['st'][$r['st']] + 1 : 1;
        unset($c);
        $b = (int) floor($r['t'] / 600) * 600;
        if (!isset($bk[$b])) {
            $bk[$b] = ['n' => 0, 'ms' => 0, 'by' => []];
        }
        $bk[$b]['n']++;
        $bk[$b]['ms'] += $r['ms'];
        $bk[$b]['by'][$g . ' ' . $ua] = isset($bk[$b]['by'][$g . ' ' . $ua]) ? $bk[$b]['by'][$g . ' ' . $ua] + 1 : 1;
    }
    uasort($cl, function ($x, $y) {
        return $y['ms'] - $x['ms'];
    });
    $L[] = '';
    $L[] = '== SLOW/HEAVY REQUESTS BY CLIENT (all ' . $total_rq . ' in window, ranked by total wall time) ==';
    $L[] = 'client | user agent | requests | total wall s | total cpu s | slowest ms | first-last | http codes | distinct paths | top paths';
    foreach (array_slice($cl, 0, 15) as $c) {
        arsort($c['paths']);
        $tp = [];
        foreach (array_slice($c['paths'], 0, 3, true) as $p => $n) {
            $tp[] = substr($p, 0, 45) . ' x' . $n;
        }
        $codes = [];
        foreach ($c['st'] as $s => $n) {
            $codes[] = $s . 'x' . $n;
        }
        $L[] = $c['g'] . ' | ' . $c['ua'] . ' | ' . $c['n'] . ' | ' . round($c['ms'] / 1000) . ' | ' . round($c['cpu'] / 1000, 1) . ' | ' . $c['max'] . ' | ' . lg_bb_date('H:i:s', $c['t0']) . '-' . lg_bb_date('H:i:s', $c['t1']) . ' | ' . implode(',', $codes) . ' | ' . count($c['paths']) . ' | ' . implode('; ', $tp);
    }
    uasort($tt, function ($x, $y) {
        return $y['ms'] - $x['ms'];
    });
    $L[] = '';
    $L[] = '== SLOW/HEAVY REQUESTS BY TENANT (the tenant the CRM resolved for the request; - = none, e.g. anonymous, login, WordPress itself) ==';
    $L[] = 'tenant | requests | total wall s | total cpu s | slowest ms | highest peak MB | top path';
    foreach (array_slice($tt, 0, 12, true) as $tk => $v) {
        arsort($v['paths']);
        $L[] = ($tk === '-' ? '-' : lg_bb_tenant_label($tk)) . ' | ' . $v['n'] . ' | ' . round($v['ms'] / 1000) . ' | ' . round($v['cpu'] / 1000, 1) . ' | ' . $v['max'] . ' | ' . $v['peak'] . ' | ' . substr((string) key($v['paths']), 0, 50);
    }
    ksort($bk);
    $L[] = '';
    $L[] = '== SLOW/HEAVY REQUESTS PER 10 MIN (buckets with 3+; shows the clients behind each burst) ==';
    $L[] = 'bucket start | requests | total wall s | top clients';
    foreach ($bk as $b => $v) {
        if ($v['n'] < 3) {
            continue;
        }
        arsort($v['by']);
        $tc = [];
        foreach (array_slice($v['by'], 0, 3, true) as $who => $n) {
            $tc[] = $who . ' x' . $n;
        }
        $L[] = lg_bb_date('m-d H:i', $b) . ' | ' . $v['n'] . ' | ' . round($v['ms'] / 1000) . ' | ' . implode('; ', $tc);
    }

    if ($total_rq > 60) {
        usort($rq, function ($x, $y) {
            return ($y['ms'] + $y['peak'] * 50) - ($x['ms'] + $x['peak'] * 50);
        });
        $rq = array_slice($rq, 0, 60);
        usort($rq, function ($x, $y) {
            return $x['t'] - $y['t'];
        });
    }
    $L[] = '';
    $L[] = '== SLOW/HEAVY REQUESTS (' . count($rq) . ' of ' . $total_rq . ') ==';
    $L[] = 'start | why | request | ms | cpu ms | peak MB | queries | http | ip | user agent | detail';
    foreach ($rq as $r) {
        $d = [];
        if (!empty($r['tn'])) {
            $d[] = 'tenant ' . lg_bb_tenant_label($r['tn']);
        }
        if (!empty($r['fatal'])) {
            $d[] = 'FATAL ' . $r['fatal'];
        }
        if (!empty($r['cron'])) {
            foreach ($r['cron'] as $c) {
                $d[] = 'cron ' . $c[0] . ' ' . $c[1] . 'ms ' . $c[2] . 'MB';
            }
        }
        if (!empty($r['sq'])) {
            foreach ($r['sq'] as $s) {
                $d[] = 'SQL ' . $s[0] . 'ms [' . $s[1] . '] ' . $s[2];
            }
        }
        $L[] = $f($r['t']) . ' | ' . $r['why'] . ' | ' . $r['m'] . ' ' . $r['uri'] . ' | ' . $r['ms'] . ' | ' . $r['cpu'] . ' | ' . $r['peak'] . ' | ' . $r['q'] . ' | ' . $r['st'] . ' | ' . $r['ip'] . ' | ' . substr($r['ua'], 0, 40) . ' | ' . implode(' ; ', $d);
    }
    $L[] = '';
    $L[] = '== END ==';
    return lg_bb_label_pools(implode("\n", $L));
}

add_action('admin_post_lg_bb_clear', function () {
    lg_bb_admin_guard('lg_bb_clear');
    @unlink(lg_bb_logfile());
    @unlink(lg_bb_logfile(true));
    @unlink(lg_bb_rec_file());
    @unlink(lg_bb_rec_file(true));
    wp_safe_redirect(admin_url('tools.php?page=lg-blackbox'));
    exit;
});

add_action('admin_post_lg_bb_recorder', function () {
    lg_bb_admin_guard('lg_bb_recorder');
    update_option('lg_bb_recorder', empty($_POST['on']) ? '0' : '1', true);
    wp_safe_redirect(admin_url('tools.php?page=lg-blackbox') . '#lg-rec');
    exit;
});

function lg_bb_rec_panel()
{
    $on = lg_bb_rec_on();
    $S = lg_bb_rec_summary(24);
    $mins = $S['min'];
    uasort($mins, function ($a, $b) {
        return $b['n'] - $a['n'];
    });
    $top = array_slice($mins, 0, 8, true);
    ?>
    <h2 id="lg-rec">Burst recorder (every PHP request, compact)</h2>
    <p>
        Status: <strong><?php echo $on ? 'ON' : 'OFF'; ?></strong>.
        One short line per request that reaches WordPress: time, IP, country, client type, path (long ids masked), the
        <em>names</em> of query parameters (never their values) and the referring site. It is written when the request starts, so a
        request that is later killed is still there. Rolling file of about 8 MB. Pages answered by the cache never reach it, and
        requests refused by the gate (login, country, probes) are listed in their own sections.
        <?php if ($S['n']): ?>
            <br>Holds <?php echo (int) $S['n']; ?> requests from <?php echo lg_bb_t($S['t0']); ?> to <?php echo lg_bb_t($S['t1']); ?>
            (<?php echo (int) $S['ad']; ?> with ad-click parameters, <?php echo (int) $S['fb']; ?> from Facebook/Instagram/Meta).
        <?php endif; ?>
    </p>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-bottom:1em">
        <input type="hidden" name="action" value="lg_bb_recorder">
        <?php wp_nonce_field('lg_bb_recorder'); ?>
        <label><input type="checkbox" name="on" value="1" <?php checked($on); ?>> record every request</label>
        <button class="button">Save</button>
    </form>
    <?php if ($top): ?>
        <table class="widefat striped" style="margin-bottom:1em">
            <thead>
                <tr>
                    <th>Busiest minutes (24 h)</th>
                    <th>Requests</th>
                    <th>Distinct IPs</th>
                    <th>Ad-click</th>
                    <th>From Facebook</th>
                    <th>Top clients</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($top as $mk => $M): ?>
                    <?php
                    $by = [];
                    foreach (lg_bb_rec_top($M['by'], 2) as $g => $c) {
                        $by[] = $g . ' ×' . $c;
                    }
                    ?>
                    <tr>
                        <td><?php echo lg_bb_t($mk); ?></td>
                        <td><?php echo (int) $M['n']; ?></td>
                        <td><?php echo count($M['ip']); ?></td>
                        <td><?php echo (int) $M['ad']; ?></td>
                        <td><?php echo (int) $M['fb']; ?></td>
                        <td><?php echo esc_html(implode('; ', $by)); ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
    <?php
}

add_action('admin_post_lg_bb_savequeries', function () {
    lg_bb_admin_guard('lg_bb_savequeries');
    update_option('lg_bb_savequeries', empty($_POST['on']) ? 0 : 1, true);
    wp_safe_redirect(admin_url('tools.php?page=lg-blackbox'));
    exit;
});

/** Last ~$bytes of the log (previous file too if the current one is short), as decoded rows. */
function lg_bb_load_rows($bytes = 1500000)
{
    static $cache = [];
    if (isset($cache[$bytes])) {
        return $cache[$bytes]; // the page and the report both ask; parse the log once per request
    }
    $rows = [];
    foreach ([lg_bb_logfile(true), lg_bb_logfile()] as $f) {
        $size = @filesize($f);
        if (!$size) {
            continue;
        }
        $h = @fopen($f, 'r');
        if (!$h) {
            continue;
        }
        if ($size > $bytes) {
            fseek($h, $size - $bytes);
            fgets($h); // drop the partial line
        }
        while (($line = fgets($h)) !== false) {
            if ($line[0] === '{') {
                $r = json_decode($line, true);
                if (is_array($r)) {
                    $rows[] = $r;
                }
            }
        }
        fclose($h);
    }
    $cache[$bytes] = $rows;
    return $rows;
}

function lg_bb_t($t)
{
    return esc_html(lg_bb_date('M j H:i:s', (int) $t));
}

function lg_bb_cpu_str($cpu)
{
    $o = [];
    foreach ((array) $cpu as $c) {
        $o[] = $c[0] . ' ' . $c[1] . '%';
    }
    return implode(', ', $o);
}

function lg_bb_state($h)
{
    $bits = [];
    if (isset($h['load'])) {
        $bits[] = 'load ' . implode('/', $h['load']);
    }
    if (isset($h['mem_avail'])) {
        $bits[] = 'avail ' . $h['mem_avail'] . ' MB';
    }
    if (isset($h['swap_used'])) {
        $bits[] = 'swap ' . $h['swap_used'] . ' MB';
    }
    if (isset($h['p'])) {
        $bits[] = 'mariadb ' . $h['p']['db_mb'] . ' MB';
        $bits[] = 'php ' . $h['p']['php_n'] . ' procs / ' . $h['p']['php_mb'] . ' MB';
        if (isset($h['p']['run'])) {
            $bits[] = 'running ' . $h['p']['run'] . ' / disk-wait ' . $h['p']['disk'];
        }
        if (!empty($h['p']['cpu'])) {
            $bits[] = 'cpu ' . lg_bb_cpu_str($h['p']['cpu']);
        }
    }
    if (isset($h['inf']['n'])) {
        $bits[] = 'in-flight ' . $h['inf']['n'];
    }
    if (!empty($h['inf']['long'])) {
        $l = [];
        foreach ($h['inf']['long'] as $x) {
            $l[] = $x[0] . 's ' . $x[1];
        }
        $bits[] = 'long: ' . implode(' | ', $l);
    }
    if (!empty($h['pl'])) {
        $bits[] = 'SQL: ' . $h['pl'][0][0] . 's ' . $h['pl'][0][2];
    }
    if (!empty($h['auth'])) {
        $bits[] = lg_bb_auth_str($h['auth']);
    }
    return implode(' · ', $bits);
}

/** Splits log rows by kind (oldest first) and derives the incident list (newest first). */
function lg_bb_analyze($rows)
{
    $hb = $req = $dberr = $orph = [];
    foreach ($rows as $r) {
        switch (isset($r['k']) ? $r['k'] : '') {
            case 'hb':
                $hb[] = $r;
                break;
            case 'req':
                $req[] = $r;
                break;
            case 'dberr':
                $dberr[] = $r;
                break;
            case 'orphan':
                $orph[] = $r;
                break;
        }
    }
    $by_t = function ($a, $b) {
        return $a['t'] - $b['t'];
    };
    usort($hb, $by_t);
    usort($req, $by_t);
    usort($dberr, $by_t);
    usort($orph, $by_t);

    // Incidents -------------------------------------------------------------
    $inc = [];
    $prev = null;
    foreach ($hb as $h) {
        if (!isset($h['db']['up'])) {
            continue;
        }
        // Uptime grew by less than the wall clock did => MariaDB restarted in between.
        if ($prev && $h['db']['up'] < $prev['db']['up'] + ($h['t'] - $prev['t']) - 15) {
            $inc[] = [
                't' => $h['t'] - $h['db']['up'],
                'what' => 'MariaDB restarted (uptime was ' . $prev['db']['up'] . ' s, now ' . $h['db']['up'] . ' s)',
                'detail' => 'Last sample before it (' . lg_bb_date('H:i:s', $prev['t']) . '): ' . lg_bb_state($prev),
            ];
        }
        $prev = $h;
    }
    $win = null;
    foreach ($dberr as $d) {
        if ($win && $d['t'] - $win['to'] <= 120) {
            $win['to'] = $d['t'];
            $win['n']++;
            $win['codes'][(string) (isset($d['conn']['errno']) ? $d['conn']['errno'] : '?')] = true;
            continue;
        }
        if ($win) {
            $inc[] = lg_bb_dberr_incident($win);
        }
        $win = ['from' => $d['t'], 'to' => $d['t'], 'n' => 1, 'first' => $d, 'codes' => [(string) (isset($d['conn']['errno']) ? $d['conn']['errno'] : '?') => true]];
    }
    if ($win) {
        $inc[] = lg_bb_dberr_incident($win);
    }
    foreach ($orph as $o) {
        $inc[] = ['t' => $o['started'], 'what' => 'Request never finished (worker killed) - ' . $o['uri'], 'detail' => 'ran ≥ ' . $o['age'] . ' s, IP ' . $o['ip']];
    }
    usort($inc, function ($a, $b) {
        return $b['t'] - $a['t'];
    });
    return compact('hb', 'req', 'dberr', 'orph', 'inc');
}

/** Loads the stylesheet and script of the redesigned admin page (only on our own page). */
add_action('admin_enqueue_scripts', function ($hook) {
    if ($hook !== 'tools_page_lg-blackbox') {
        return;
    }
    $dir = plugin_dir_path(__FILE__) . 'assets/';
    $ver = LG_BB_VERSION . '.' . (int) @filemtime($dir . 'lgbb-ui.js') . (int) @filemtime($dir . 'lgbb-ui.css');
    wp_enqueue_style('lgbb-ui', plugins_url('assets/lgbb-ui.css', __FILE__), ['dashicons'], $ver);
    wp_enqueue_script('lgbb-ui', plugins_url('assets/lgbb-ui.js', __FILE__), [], $ver, true);
});

/** One switch of the hero: a link to the existing admin op, turned into a background request by lgbb-ui.js. */
function lg_bb_ui_switch($label, $desc, $icon, $is_on, $op_on, $op_off, $confirm_off = '')
{
    $url = wp_nonce_url(admin_url('admin-post.php?action=lg_bb_login&op=' . ($is_on ? $op_off : $op_on) . '&ip=0.0.0.0'), 'lg_bb_login');
    return '<a class="lgbb-switch' . ($is_on ? ' is-on' : '') . '" role="switch" aria-checked="' . ($is_on ? 'true' : 'false') . '" href="' . esc_url($url) . '"'
        . ($is_on && $confirm_off !== '' ? ' data-confirm="' . esc_attr($confirm_off) . '"' : '') . '>'
        . '<span class="dashicons ' . esc_attr($icon) . '"></span><span class="lgbb-switch__txt"><b>' . esc_html($label) . '</b><small>' . esc_html($desc) . '</small></span>'
        . '<span class="lgbb-switch__knob" aria-hidden="true"></span></a>';
}

function lg_bb_ui_kpi($icon, $label, $value, $unit = '', $sub = '', $tone = '')
{
    return '<div class="lgbb-kpi' . ($tone !== '' ? ' is-' . esc_attr($tone) : '') . '"><div class="lgbb-kpi__label"><span class="dashicons ' . esc_attr($icon) . '"></span>' . esc_html($label) . '</div>'
        . '<div class="lgbb-kpi__value">' . esc_html($value) . ($unit !== '' ? '<small>' . esc_html($unit) . '</small>' : '') . '</div>'
        . ($sub !== '' ? '<div class="lgbb-kpi__sub">' . esc_html($sub) . '</div>' : '') . '</div>';
}

/** The dashboard tiles and the "Recent alerts" list count what happened in this many hours (the raw log reaches back as far as its size allows). */
define('LG_BB_DASH_HOURS', 24);

/** How many recent alerts show at once; the rest of the 24 hours opens under "older". */
define('LG_BB_RECENT_SHOWN', 6);

/**
 * Everything worth a look in the last $hours hours, newest first: alerts sent, incidents, automatic blocks, rate-limited IPs,
 * scanner probes, failed or refused logins, refused cron calls, failing security checks and very slow requests.
 * Each item: t, tone (bad|warn|info), kind, what, detail.
 */
function lg_bb_recent_events($inc, $req, $hours = LG_BB_DASH_HOURS)
{
    $since = time() - (int) $hours * 3600;
    $ev = [];
    $add = function ($t, $tone, $kind, $what, $detail = '') use (&$ev, $since) {
        if ((int) $t > 0 && (int) $t >= $since) {
            $ev[] = ['t' => (int) $t, 'tone' => $tone, 'kind' => $kind, 'what' => (string) $what, 'detail' => (string) $detail];
        }
    };
    $who = function ($ip, $cc) {
        return $ip . ($cc !== '' && $cc !== null ? ' (' . $cc . ')' : '');
    };

    // Alerts the plugin raised (the e-mail log).
    $al = lg_bb_sec_read('alerts');
    foreach ((array) (isset($al['log']) ? $al['log'] : []) as $a) {
        if (!is_array($a) || !isset($a['t']) || strpos((string) (isset($a['key']) ? $a['key'] : ''), 'digest-') === 0) {
            continue;
        }
        $sent = isset($a['sent']) ? (string) $a['sent'] : '';
        $add($a['t'], isset($a['level']) && $a['level'] === 'crit' ? 'bad' : (isset($a['level']) && $a['level'] === 'info' ? 'info' : 'warn'), 'Alert',
            isset($a['subject']) ? $a['subject'] : '', $sent === 'sent' ? 'e-mailed' : ($sent === 'FAILED' ? 'e-mail FAILED to send' : 'not e-mailed (' . $sent . ')'));
    }
    // Server incidents.
    foreach ((array) $inc as $i) {
        $add($i['t'], 'bad', 'Server', $i['what'], isset($i['detail']) ? $i['detail'] : '');
    }
    // Very slow requests.
    foreach ((array) $req as $r) {
        if (isset($r['ms']) && (int) $r['ms'] >= 8000) {
            $add($r['t'], 'warn', 'Slow request', (isset($r['m']) ? $r['m'] . ' ' : '') . (isset($r['uri']) ? $r['uri'] : ''),
                round((int) $r['ms'] / 1000, 1) . ' s, status ' . (isset($r['st']) ? (int) $r['st'] : '?') . ', IP ' . (isset($r['ip']) ? $r['ip'] : '?') . (!empty($r['why']) ? ', ' . $r['why'] : ''));
        }
    }
    // Blocks the plugin or the gate put in force.
    foreach (lg_bb_auto_list() as $r) {
        $add($r['first'], 'warn', 'Blocked', 'IP ' . $who($r['ip'], isset($r['cc']) ? (string) $r['cc'] : '') . ' put on the automatic block list',
            (isset($r['why']) ? $r['why'] : '') . ', until ' . lg_bb_date('M j H:i', (int) $r['until']) . (!empty($r['n']) ? ', ' . (int) $r['n'] . ' requests refused so far' : ''));
    }
    foreach (lg_bb_over_list() as $r) {
        $add($r['last'], 'warn', 'Rate limit', 'IP ' . $r['ip'] . ' went over the request limit in ' . (int) $r['n'] . ' separate minute(s)',
            'last on ' . (isset($r['p']) ? $r['p'] : '') . (!empty($r['limit']) ? ', limit ' . (int) $r['limit'] . ' requests/min' : ''));
    }
    foreach (lg_bb_probe_table($hours) as $r) {
        $add($r['last'], $r['blocked'] ? 'warn' : 'info', $r['blocked'] ? 'Scanner blocked' : 'Scanner probe',
            'IP ' . $who($r['ip'], $r['cc']) . ' asked for ' . (int) $r['n'] . ' junk path(s)', trim($r['paths'] . ($r['status'] !== '' ? ' - ' . $r['status'] : '')));
    }
    foreach (lg_bb_auth_table($hours) as $r) {
        if (!empty($r['f'])) {
            $add($r['last'], 'warn', 'Login', (int) $r['f'] . ' failed login(s) from ' . $who($r['ip'], $r['cc']),
                ($r['kinds'] !== '' ? $r['kinds'] . ', ' : '') . (int) $r['n'] . ' attempt(s)' . ($r['status'] !== '' ? ' - ' . $r['status'] : ''));
        } elseif (!empty($r['geo'])) {
            $add($r['last'], 'info', 'Country filter', 'IP ' . $who($r['ip'], $r['cc']) . ' refused', $r['status']);
        }
    }
    // The gate refused a wp-cron.php call.
    $dn = lg_bb_rl_read(lg_bb_rl_dir() . '/cron-denied.php');
    if (is_array($dn) && !empty($dn['t'])) {
        $add($dn['t'], 'warn', 'Cron guard', 'wp-cron.php refused for ' . (isset($dn['ip']) ? $dn['ip'] : '?'),
            'If that is this server, press "re-detect" under the wp-cron guard (the plugin switches the guard off by itself when the cron stalls).');
    }
    // Security checks that found something.
    foreach ((array) lg_bb_sec_read('jobs') as $name => $j) {
        if ($name !== 'digest' && is_array($j) && isset($j['ok']) && !$j['ok'] && !empty($j['t'])) {
            $add($j['t'], 'warn', 'Check', ucfirst((string) $name) . ' check found something', isset($j['summary']) ? $j['summary'] : '');
        }
    }
    usort($ev, function ($a, $b) {
        return $b['t'] - $a['t'];
    });
    return array_slice($ev, 0, 150);
}

/** "Recent alerts": a few at once, the rest of the last 24 hours behind a fold. */
function lg_bb_recent_panel($inc, $req)
{
    $ev = lg_bb_recent_events($inc, $req, LG_BB_DASH_HOURS);
    $tones = ['bad' => 'Serious', 'warn' => 'Flagged', 'info' => 'Notice'];
    $rows = function ($list) use ($tones) {
        foreach ($list as $e) {
            echo '<tr><td style="white-space:nowrap">' . lg_bb_t($e['t']) . '<br><small>' . esc_html(lg_bb_sec_ago($e['t'])) . '</small></td>'
                . '<td><span class="lgbb-ev is-' . esc_attr($e['tone']) . '">' . esc_html($tones[$e['tone']]) . '</span></td>'
                . '<td>' . esc_html($e['kind']) . '</td><td>' . esc_html($e['what']) . '</td><td>' . esc_html($e['detail']) . '</td></tr>';
        }
    };
    $head = '<thead><tr><th style="width:120px">When</th><th style="width:80px">Level</th><th style="width:120px">Type</th><th>What</th><th>Detail</th></tr></thead>';
    $first = array_slice($ev, 0, LG_BB_RECENT_SHOWN);
    $older = array_slice($ev, LG_BB_RECENT_SHOWN);
    ?>
    <h2 id="lg-recent">Recent alerts</h2>
    <p>Everything blocked, refused or flagged in the <strong>last <?php echo (int) LG_BB_DASH_HOURS; ?> hours</strong>, newest first
        (<?php echo (int) count($ev); ?> in all; times in <?php echo esc_html(lg_bb_tz_label()); ?>). Older events are not kept here.</p>
    <?php if (!$ev): ?>
        <p>Nothing blocked or flagged in the last <?php echo (int) LG_BB_DASH_HOURS; ?> hours.</p>
    <?php else: ?>
        <table class="widefat striped"><?php echo $head; ?><tbody><?php $rows($first); ?></tbody></table>
        <?php if ($older): ?>
            <details class="lgbb-older" style="margin-top:10px">
                <summary style="cursor:pointer;font-weight:600">Show the other <?php echo (int) count($older); ?> from the last <?php echo (int) LG_BB_DASH_HOURS; ?> hours</summary>
                <table class="widefat striped" style="margin-top:8px"><?php echo $head; ?><tbody><?php $rows($older); ?></tbody></table>
            </details>
        <?php endif; ?>
    <?php endif; ?>
    <?php
}

/** Header of the admin page: live server tiles and a switch for every protection. */
function lg_bb_ui_hero($sys, $hb, $req, $inc)
{
    $cfg = lg_bb_rl_cfg();
    $gate = lg_bb_gate_installed();
    $lists = lg_bb_rl_lists();
    $autos = count(lg_bb_auto_list());
    $overs = count(lg_bb_over_list());
    $switches = [
        ['Login protection', 'Locks out repeated failed logins', 'dashicons-shield', !empty($cfg['enabled']) && $gate, 'enable', 'disable', 'Turn login protection off?'],
        ['Probe shield', 'Scanners get a 404, then a block', 'dashicons-search', $cfg['probe'] === 'on' && $gate, 'probe_enable', 'probe_disable', 'Turn the probe shield off?'],
        ['Automatic blocks', 'Repeat offenders for ' . (int) $cfg['auto_days'] . ' days', 'dashicons-update', !empty($cfg['auto']), 'auto_on', 'auto_off', ''],
        ['Request-rate limit', 'Floods get a 429 before WordPress', 'dashicons-dashboard', !empty($cfg['rate']), 'rate_on', 'rate_off', 'Turn the request-rate limit off?'],
        ['wp-cron guard', 'Only the server may call wp-cron.php', 'dashicons-clock', !empty($cfg['cron_guard']), 'cron_on', 'cron_off', ''],
        ['Under-attack mode', 'High load: anonymous visitors cut to a quarter', 'dashicons-warning', lg_bb_sec_ua_on() && $gate, 'ua_on', 'ua_off', 'Turn under-attack mode off?'],
        ['404 flood watch', 'Many page misses or refused links: blocked', 'dashicons-visibility', lg_bb_sec_flood_on(), 'flood_on', 'flood_off', ''],
        ['Country filter', 'Needs Cloudflare in front', 'dashicons-admin-site-alt3', $cfg['geo'] === 'block', 'geo_enable', 'geo_disable', 'Turn the country filter off?'],
    ];
    $n_on = 0;
    foreach ($switches as $sw) {
        $n_on += $sw[3] ? 1 : 0;
    }
    $load = isset($sys['load'][0]) ? (float) $sys['load'][0] : null;
    $cpus = !empty($sys['cpus']) ? max(1, (int) $sys['cpus']) : 1;
    $lt = $load === null ? '' : ($load / $cpus >= 2 ? 'bad' : ($load / $cpus >= 1 ? 'warn' : 'good'));
    $avail = isset($sys['mem_avail']) ? (int) $sys['mem_avail'] : null;
    $total = isset($sys['mem_total']) ? (int) $sys['mem_total'] : 0;
    $mt = $avail === null || !$total ? '' : ($avail / $total < 0.1 ? 'bad' : ($avail / $total < 0.2 ? 'warn' : 'good'));
    $swap = isset($sys['swap_used']) ? (int) $sys['swap_used'] : null;
    $st = $swap === null ? '' : ($swap > 1500 ? 'bad' : ($swap > 500 ? 'warn' : 'good'));
    $last = $hb ? end($hb) : null;
    $db_text = '-';
    $db_tone = '';
    if (is_array($last) && isset($last['db']['up'])) {
        $up = max(1, (int) $last['db']['up']);
        $db_text = $up >= 172800 ? intdiv($up, 86400) . ' days' : ($up >= 7200 ? intdiv($up, 3600) . ' hours' : max(1, intdiv($up, 60)) . ' min');
        $db_tone = 'good';
    } elseif (is_array($last) && isset($last['db']['err'])) {
        $db_text = 'down';
        $db_tone = 'bad';
    }
    $blocked = count($lists['block_all']) + $autos;
    // Incidents and slow requests are counted over a fixed clock window, not over "whatever the log file still holds".
    $win_from = time() - LG_BB_DASH_HOURS * 3600;
    $inc_w = array_filter((array) $inc, function ($i) use ($win_from) {
        return (int) $i['t'] >= $win_from;
    });
    $req_w = array_filter((array) $req, function ($r) use ($win_from) {
        return (int) $r['t'] >= $win_from;
    });
    ?>
    <hr class="wp-header-end">
    <header class="lgbb-hero">
        <div class="lgbb-hero__top">
            <div class="lgbb-logo"><span class="dashicons dashicons-shield-alt"></span></div>
            <div>
                <h1>LG Black Box</h1>
                <p class="lgbb-hero__sub">Flight recorder and shield for this server. Changes apply instantly, no reload.</p>
            </div>
            <div class="lgbb-hero__right">
                <span class="lgbb-chip <?php echo $n_on >= 4 ? 'is-good' : 'is-warn'; ?>"><span class="dashicons dashicons-yes-alt"></span><?php echo (int) $n_on; ?> of <?php echo (int) count($switches); ?> protections on</span>
                <span class="lgbb-chip"><span class="dashicons dashicons-clock"></span><?php echo esc_html(lg_bb_tz_label()); ?></span>
                <span class="lgbb-chip" title="Load, memory and swap are live. Incidents, slow requests and rate-limited IPs are counted over the last <?php echo (int) LG_BB_DASH_HOURS; ?> hours. Blocked IPs are the blocks in force now."><span class="dashicons dashicons-backup"></span>Counts: last <?php echo (int) LG_BB_DASH_HOURS; ?> h</span>
                <span class="lgbb-chip">v<?php echo esc_html(LG_BB_VERSION); ?></span>
            </div>
        </div>
        <div class="lgbb-kpis">
            <?php
            echo lg_bb_ui_kpi('dashicons-dashboard', 'Server load', $load === null ? '-' : (string) $load, $cpus > 1 ? '/ ' . $cpus . ' cores' : '/ 1 core', 'right now', $lt);
            echo lg_bb_ui_kpi('dashicons-database', 'Free memory', $avail === null ? '-' : (string) $avail, 'MB', ($total ? 'of ' . $total . ' MB, ' : '') . 'right now', $mt);
            echo lg_bb_ui_kpi('dashicons-backup', 'Swap used', $swap === null ? '-' : (string) $swap, 'MB', 'right now', $st);
            echo lg_bb_ui_kpi('dashicons-yes', 'MariaDB uptime', $db_text, '', 'last sample', $db_tone);
            echo lg_bb_ui_kpi('dashicons-dismiss', 'Blocked IPs', (string) $blocked, '', count($lists['block_all']) . ' site-wide, ' . $autos . ' automatic, in force now', $blocked ? 'warn' : '');
            echo lg_bb_ui_kpi('dashicons-controls-pause', 'Rate-limited', (string) $overs, '', 'IPs over the limit, last ' . LG_BB_DASH_HOURS . ' h', $overs ? 'warn' : '');
            echo lg_bb_ui_kpi('dashicons-warning', 'Incidents', (string) count($inc_w), '', 'last ' . LG_BB_DASH_HOURS . ' h', count($inc_w) ? 'bad' : 'good');
            echo lg_bb_ui_kpi('dashicons-clock', 'Slow / heavy', (string) count($req_w), '', 'requests, last ' . LG_BB_DASH_HOURS . ' h', '');
            ?>
        </div>
        <div class="lgbb-switches">
            <?php
            foreach ($switches as $sw) {
                echo lg_bb_ui_switch($sw[0], $sw[1], $sw[2], $sw[3], $sw[4], $sw[5], $sw[6]);
            }
            ?>
        </div>
    </header>
    <?php
}

function lg_bb_page()
{
    if (!current_user_can('manage_options')) {
        return;
    }
    extract(lg_bb_analyze(lg_bb_load_rows()));
    $url = function ($action, $args = '') {
        return wp_nonce_url(admin_url('admin-post.php?action=' . $action . $args), $action);
    };
    $sys = lg_bb_sys();
    $pr = lg_bb_procs(10);
    ?>
    <div class="wrap lgbb" id="lgbb">
        <?php lg_bb_ui_hero($sys, $hb, $req, $inc); ?>
        <?php
        $first_t = [];
        foreach ([$hb, $req] as $set) {
            if ($set) {
                $first_t[] = (int) reset($set)['t'];
            }
        }
        ?>
        <p class="lgbb-meta">Times are shown in <?php echo esc_html(lg_bb_tz_label()); ?>. Samples every ~30 s (10 s when the server is
            busy). Log: <?php echo esc_html(count($hb)); ?> samples, <?php echo esc_html(count($req)); ?> heavy/slow
            requests loaded<?php echo $first_t ? ', going back to ' . esc_html(lg_bb_date('M j H:i', min($first_t))) : ''; ?>. The tiles above count the last
            <?php echo (int) LG_BB_DASH_HOURS; ?> hours.
            <a class="button" href="<?php echo esc_url($url('lg_bb_download')); ?>">Raw log (.txt)</a>
            <a class="button" href="<?php echo esc_url($url('lg_bb_clear')); ?>"
                onclick="return confirm('Delete the log?')">Clear</a>
        </p>

        <?php lg_bb_recent_panel($inc, $req); ?>

        <?php lg_bb_reco_panel(); ?>

        <h2>Report to paste into Claude</h2>
        <?php
        $hours = isset($_GET['hours']) ? max(1, min(168, (int) $_GET['hours'])) : 6;
        ?>
        <p>Plain text, sized to paste into a chat. Window:
            <?php foreach ([1, 3, 6, 24, 72] as $hh): ?>
                <a class="button<?php echo $hh === $hours ? ' button-primary' : ''; ?>"
                    href="<?php echo esc_url(admin_url('tools.php?page=lg-blackbox&hours=' . $hh)); ?>"><?php echo (int) $hh; ?>h</a>
            <?php endforeach; ?>
            <button type="button" class="button button-primary"
                onclick="var t=document.getElementById('lg-bb-report');t.select();var b=this;(navigator.clipboard&&navigator.clipboard.writeText?navigator.clipboard.writeText(t.value):Promise.reject()).catch(function(){document.execCommand('copy');});b.textContent='Copied!';">Copy
                report</button>
            <a class="button" href="<?php echo esc_url($url('lg_bb_report', '&hours=' . $hours)); ?>">Download report
                (.txt)</a>
        </p>
        <textarea id="lg-bb-report" readonly rows="12"
            style="width:100%;font-family:monospace;font-size:11px"><?php echo esc_textarea(lg_bb_report($hours)); ?></textarea>

        <h2>Incidents</h2>
        <?php if (!$inc): ?>
            <p>None recorded yet. After the next crash, a "MariaDB restarted" line appears here with the server state just
                before it.</p>
        <?php else: ?>
            <p>Every incident still in the log (<?php echo (int) count($inc); ?>), not only the last <?php echo (int) LG_BB_DASH_HOURS; ?> hours counted in the tile above. The log is
                trimmed by size, so old incidents drop off as new records arrive.</p>
            <table class="widefat striped">
                <thead>
                    <tr>
                        <th style="width:110px">When</th>
                        <th>What</th>
                        <th>Server state</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($inc as $i): ?>
                        <tr>
                            <td><?php echo lg_bb_t($i['t']); ?></td>
                            <td><?php echo esc_html($i['what']); ?></td>
                            <td><?php echo esc_html($i['detail']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>

        <?php lg_bb_rec_panel(); ?>

        <?php lg_bb_login_panel(); ?>

        <?php lg_bb_sec_panel(); ?>

        <h2>Server right now (what PHP is allowed to see)</h2>
        <p>
            <?php echo esc_html(lg_bb_state($sys + ['p' => $pr]) ?: 'nothing readable'); ?>
            <?php if (!$pr): ?><br><strong>/proc is not readable here: per-process memory won't be recorded.</strong><?php endif; ?>
        </p>
        <?php if ($pr): ?>
            <table class="widefat striped" style="max-width:520px">
                <thead>
                    <tr>
                        <th>Process</th>
                        <th>Count</th>
                        <th>RSS total MB</th>
                        <th>Largest MB</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($pr['top'] as $t): ?>
                        <tr>
                            <td><?php echo esc_html($t[0]); ?></td>
                            <td><?php echo (int) $t[1]; ?></td>
                            <td><?php echo (int) $t[2]; ?></td>
                            <td><?php echo (int) $t[3]; ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php if (!empty($pr['pools'])): ?>
                <h3>PHP pools right now (one pool = one application on this server)</h3>
                <table class="widefat striped" style="max-width:520px">
                    <thead>
                        <tr>
                            <th>Pool</th>
                            <th>Workers</th>
                            <th>RSS total MB</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($pr['pools'] as $pl): ?>
                            <tr>
                                <td><?php echo esc_html(lg_bb_label_pools($pl[0]) . ($pl[0] === $pr['own_pool'] ? '  ← this site' : '')); ?></td>
                                <td><?php echo (int) $pl[1]; ?></td>
                                <td><?php echo (int) $pl[2]; ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        <?php endif; ?>

        <?php lg_bb_config_panel(); ?>

        <h2>Slow / heavy requests</h2>
        <p>Logged when a request takes ≥ <?php echo esc_html(LG_BB_SLOW_S); ?> s, peaks ≥ <?php echo esc_html(LG_BB_HEAVY_MB); ?> MB, runs ≥ <?php echo esc_html(LG_BB_MANY_QUERIES); ?> queries, uses ≥ 2 s of CPU, or dies with a fatal error.
            SQL-level detail (slowest queries per request):
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display:inline">
                <input type="hidden" name="action" value="lg_bb_savequeries">
                <?php wp_nonce_field('lg_bb_savequeries'); ?>
                <label><input type="checkbox" name="on" value="1" <?php checked((bool) get_option('lg_bb_savequeries')); ?>>
                    record query timings</label>
                <button class="button">Save</button>
            </form>
        </p>
        <?php
        $top = $req;
        usort($top, function ($a, $b) {
            return $b['peak'] - $a['peak'];
        });
        lg_bb_req_table('Top 15 by peak PHP memory', array_slice($top, 0, 15));
        lg_bb_req_table('Latest 60', array_slice(array_reverse($req), 0, 60));
        ?>

        <h2>Samples (latest 60)</h2>
        <table class="widefat striped">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Load 1/5/15</th>
                    <th>Avail MB</th>
                    <th>Swap MB</th>
                    <th>Mem PSI</th>
                    <th>MariaDB MB</th>
                    <th>PHP procs / MB</th>
                    <th>DB uptime</th>
                    <th>DB conn / running</th>
                    <th>In-flight</th>
                    <th>Running / disk-wait</th>
                    <th>Top CPU</th>
                    <th>Notes</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach (array_slice(array_reverse($hb), 0, 60) as $h): ?>
                    <tr>
                        <td><?php echo lg_bb_t($h['t']); ?></td>
                        <td><?php echo esc_html(isset($h['load']) ? implode(' / ', $h['load']) : '–'); ?></td>
                        <td><?php echo esc_html(isset($h['mem_avail']) ? $h['mem_avail'] : '–'); ?></td>
                        <td><?php echo esc_html(isset($h['swap_used']) ? $h['swap_used'] : '–'); ?></td>
                        <td><?php echo esc_html(isset($h['psi_some']) ? $h['psi_some'] . ' / ' . (isset($h['psi_full']) ? $h['psi_full'] : '–') : '–'); ?></td>
                        <td><?php echo esc_html(isset($h['p']) ? $h['p']['db_mb'] : '–'); ?></td>
                        <td><?php echo esc_html(isset($h['p']) ? $h['p']['php_n'] . ' / ' . $h['p']['php_mb'] : '–'); ?></td>
                        <td><?php echo esc_html(isset($h['db']['up']) ? $h['db']['up'] . ' s' : (isset($h['db']['err']) ? 'ERR ' . $h['db']['err'] : '–')); ?></td>
                        <td><?php echo esc_html(isset($h['db']['conn']) ? $h['db']['conn'] . ' / ' . $h['db']['run'] : '–'); ?></td>
                        <td><?php echo esc_html(isset($h['inf']['n']) ? $h['inf']['n'] : '–'); ?></td>
                        <td><?php echo esc_html(isset($h['p']['run']) ? $h['p']['run'] . ' / ' . $h['p']['disk'] : '–'); ?></td>
                        <td style="font-size:11px"><?php echo esc_html(!empty($h['p']['cpu']) ? lg_bb_cpu_str($h['p']['cpu']) : '–'); ?></td>
                        <td style="font-size:11px">
                            <?php
                            $n = [];
                            if (!empty($h['inf']['long'])) {
                                foreach ($h['inf']['long'] as $x) {
                                    $n[] = $x[0] . 's ' . $x[1];
                                }
                            }
                            if (!empty($h['pl'])) {
                                foreach ($h['pl'] as $x) {
                                    $n[] = 'SQL ' . $x[0] . 's ' . $x[2];
                                }
                            }
                            if (!empty($h['auth'])) {
                                $n[] = lg_bb_auth_str($h['auth']);
                            }
                            echo esc_html(implode(' | ', $n));
                            ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php
}

/**
 * wp-config values that matter for load (no secrets - a fixed whitelist) and the
 * state of WP-Cron: how many events, how overdue, and which hooks pile up.
 */
function lg_bb_cfg()
{
    $cfg = [];
    foreach (['DISABLE_WP_CRON', 'ALTERNATE_WP_CRON', 'WP_CRON_LOCK_TIMEOUT', 'WP_MEMORY_LIMIT', 'WP_MAX_MEMORY_LIMIT', 'WP_DEBUG', 'WP_DEBUG_LOG', 'WP_CACHE', 'WP_POST_REVISIONS', 'EMPTY_TRASH_DAYS', 'WP_HTTP_BLOCK_EXTERNAL'] as $c) {
        $cfg[$c] = defined($c) ? var_export(constant($c), true) : 'not set';
    }
    foreach (['memory_limit', 'max_execution_time', 'max_input_vars', 'post_max_size', 'upload_max_filesize', 'default_socket_timeout', 'opcache.enable'] as $i) {
        $cfg['php ' . $i] = (string) ini_get($i);
    }
    $cfg['PHP version / SAPI'] = PHP_VERSION . ' / ' . PHP_SAPI;
    $cfg['external object cache'] = function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache() ? 'yes' : 'no';
    $cfg['active plugins'] = (string) count((array) get_option('active_plugins', []));
    return $cfg;
}

/** WP-Cron queue summary: total events, stored size, overdue events, pending count per hook. */
function lg_bb_cron_stats()
{
    $crons = _get_cron_array();
    $crons = is_array($crons) ? $crons : [];
    $now = time();
    $total = 0;
    $overdue = [];
    $by_hook = [];
    foreach ($crons as $ts => $hooks) {
        foreach ((array) $hooks as $hook => $events) {
            foreach ((array) $events as $ev) {
                $total++;
                $by_hook[$hook] = isset($by_hook[$hook]) ? $by_hook[$hook] + 1 : 1;
                if ($ts < $now - 60) {
                    $overdue[] = [$now - $ts, $hook, isset($ev['schedule']) && $ev['schedule'] ? $ev['schedule'] : 'once'];
                }
            }
        }
    }
    usort($overdue, function ($a, $b) {
        return $b[0] - $a[0];
    });
    arsort($by_hook);
    return ['total' => $total, 'size_kb' => round(strlen(serialize($crons)) / 1024), 'overdue' => $overdue, 'by_hook' => $by_hook, 'now' => $now];
}

function lg_bb_config_panel()
{
    $cfg = lg_bb_cfg();
    $cs = lg_bb_cron_stats();
    $total = $cs['total'];
    $size_kb = $cs['size_kb'];
    $overdue = $cs['overdue'];
    $by_hook = $cs['by_hook'];
    $now = $cs['now'];
    ?>
    <h2>Config &amp; cron</h2>
    <p>Safe values only (no passwords or keys). <strong>DISABLE_WP_CRON = true</strong> means a real server cron is
        used; <em>not set</em> means WordPress spawns <code>wp-cron.php</code> from visitor requests.</p>
    <table class="widefat striped" style="max-width:520px">
        <tbody>
            <?php foreach ($cfg as $k => $v): ?>
                <tr>
                    <td><?php echo esc_html($k); ?></td>
                    <td><?php echo esc_html($v); ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <p>WP-Cron queue: <strong><?php echo (int) $total; ?></strong> scheduled events (<?php echo (int) $size_kb; ?> KB
        stored - loaded on every request), <strong><?php echo count($overdue); ?></strong> overdue by more than 60 s.
        A hook with dozens of pending events is a pile-up.</p>
    <table class="widefat striped" style="max-width:720px">
        <thead>
            <tr>
                <th>Most overdue</th>
                <th>Schedule</th>
                <th>Late by</th>
                <th style="width:40px"></th>
                <th>Hooks with the most pending events</th>
                <th>Pending</th>
            </tr>
        </thead>
        <tbody>
            <?php
            $late = array_slice($overdue, 0, 10);
            $many = array_slice($by_hook, 0, 10, true);
            $many_keys = array_keys($many);
            for ($n = 0; $n < 10; $n++):
                if (!isset($late[$n]) && !isset($many_keys[$n])) {
                    break;
                }
                ?>
                <tr>
                    <td><?php echo isset($late[$n]) ? esc_html($late[$n][1]) : ''; ?></td>
                    <td><?php echo isset($late[$n]) ? esc_html($late[$n][2]) : ''; ?></td>
                    <td><?php echo isset($late[$n]) ? esc_html(human_time_diff($now - $late[$n][0], $now)) : ''; ?></td>
                    <td></td>
                    <td><?php echo isset($many_keys[$n]) ? esc_html($many_keys[$n]) : ''; ?></td>
                    <td><?php echo isset($many_keys[$n]) ? (int) $many[$many_keys[$n]] : ''; ?></td>
                </tr>
            <?php endfor; ?>
        </tbody>
    </table>
    <?php
}

function lg_bb_dberr_incident($w)
{
    $f = $w['first'];
    $codes = implode(',', array_keys($w['codes']));
    return [
        't' => $w['from'],
        'what' => 'Database unreachable for ≥ ' . max(1, $w['to'] - $w['from']) . ' s (' . $w['n'] . ' failed page loads; connect error code ' . $codes . ': 2002/2006 = MariaDB down, 1040 = too many connections)',
        'detail' => lg_bb_state($f),
    ];
}

function lg_bb_req_table($title, $list)
{
    echo '<h3>' . esc_html($title) . '</h3>';
    if (!$list) {
        echo '<p>Nothing yet.</p>';
        return;
    }
    echo '<table class="widefat striped"><thead><tr><th>Time</th><th>Why</th><th>Request</th><th>ms</th><th>CPU ms</th><th>Peak MB</th><th>Queries</th><th>Status</th><th>IP</th><th>User agent</th><th>Detail</th></tr></thead><tbody>';
    foreach ($list as $r) {
        $detail = [];
        if (!empty($r['tn'])) {
            $detail[] = 'tenant ' . lg_bb_tenant_label($r['tn']);
        }
        if (!empty($r['fatal'])) {
            $detail[] = 'FATAL ' . $r['fatal'];
        }
        if (!empty($r['cron'])) {
            foreach ($r['cron'] as $c) {
                $detail[] = 'cron ' . $c[0] . ' ' . $c[1] . 'ms ' . $c[2] . 'MB';
            }
        }
        if (!empty($r['sq'])) {
            foreach ($r['sq'] as $s) {
                $detail[] = 'SQL ' . $s[0] . 'ms [' . $s[1] . '] ' . $s[2];
            }
        }
        $bl = lg_bb_block_link($r['ip'], 'Block');
        echo '<tr><td>' . lg_bb_t($r['t']) . '</td><td>' . esc_html($r['why']) . '</td><td>' . esc_html($r['m'] . ' ' . $r['uri']) . '</td><td>' . (int) $r['ms'] . '</td><td>' . (int) $r['cpu'] . '</td><td>' . (int) $r['peak'] . '</td><td>' . (int) $r['q'] . '</td><td>' . (int) $r['st'] . '</td><td>' . esc_html($r['ip']) . ($bl !== '' ? '<br>' . $bl : '') . '</td><td style="font-size:11px">' . esc_html($r['ua']) . '</td><td style="font-size:11px">' . esc_html(implode(' | ', $detail)) . '</td></tr>';
    }
    echo '</tbody></table>';
}
