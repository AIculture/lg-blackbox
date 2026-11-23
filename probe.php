<?php
/**
 * LG Black Box — server probes. Plain PHP, NO WordPress dependency, so the
 * db-error.php drop-in can use it while WordPress cannot even reach its database.
 */
if (!function_exists('lg_bb_read')) {

    function lg_bb_read($path, $max = 65536)
    {
        $s = @file_get_contents($path, false, null, 0, $max);
        return is_string($s) ? $s : null;
    }

    /** Load average, memory, swap, memory pressure (PSI) — whatever the host lets PHP see. */
    function lg_bb_sys()
    {
        $o = [];
        $la = function_exists('sys_getloadavg') ? @sys_getloadavg() : false;
        if (is_array($la)) {
            $o['load'] = [round($la[0], 2), round($la[1], 2), round($la[2], 2)];
        }
        $mi = lg_bb_read('/proc/meminfo');
        if ($mi !== null) {
            $kv = [];
            foreach (explode("\n", $mi) as $line) {
                if (preg_match('/^(\w+):\s+(\d+)/', $line, $m)) {
                    $kv[$m[1]] = (int) $m[2];
                }
            }
            if (isset($kv['MemTotal'])) {
                $o['mem_total'] = (int) round($kv['MemTotal'] / 1024);
            }
            if (isset($kv['MemAvailable'])) {
                $o['mem_avail'] = (int) round($kv['MemAvailable'] / 1024);
            }
            if (isset($kv['SwapTotal'], $kv['SwapFree'])) {
                $o['swap_used'] = (int) round(($kv['SwapTotal'] - $kv['SwapFree']) / 1024);
            }
        }
        $psi = lg_bb_read('/proc/pressure/memory', 1024);
        if ($psi !== null) {
            if (preg_match('/^some avg10=([\d.]+)/m', $psi, $m)) {
                $o['psi_some'] = (float) $m[1];
            }
            if (preg_match('/^full avg10=([\d.]+)/m', $psi, $m)) {
                $o['psi_full'] = (float) $m[1];
            }
        }
        $ci = lg_bb_read('/proc/cpuinfo', 262144);
        if ($ci !== null) {
            $o['cpus'] = preg_match_all('/^processor\s*:/m', $ci);
        }
        return $o;
    }

    /**
     * Resident memory by process name, server-wide (all sites on the box, MariaDB, Redis…).
     * RSS counts shared pages once per process, so php-fpm totals are an upper bound —
     * good for trends and for spotting a runaway, not for exact accounting.
     */
    /**
     * Heuristic: is this path something only a vulnerability scanner asks for (dotfiles, /actuator,
     * credentials.json, terraform.tfvars, phpinfo...)? Used to flag scanner-like IPs in the admin page.
     * Never used to block anything by itself.
     */
    function lg_bb_looks_like_probe($path)
    {
        $p = strtolower((string) $path);
        if ($p === '' || $p[0] !== '/') {
            return false;
        }
        if (preg_match('#(^|/)\.(env|git|svn|hg|aws|ssh|docker|vscode|idea|npmrc|htpasswd|bash_history)(/|\.|$)#', $p)) {
            return true;
        }
        if (preg_match('#^/(actuator|phpmyadmin|pma/|adminer|cgi-bin/|boaform|manager/html|server-status|server-info|_profiler|_ignition|telescope|symfony/|vendor/phpunit|v2/_catalog)#', $p)) {
            return true;
        }
        foreach (['/wp-content/', '/wp-includes/', '/wp-admin/', '/wp-json/'] as $safe) {
            if (strpos($p, $safe) === 0) {
                return false;
            }
        }
        if (in_array(basename($p), ['phpinfo', 'phpinfo.php', 'info.php', 'metrics', 'env', 'jenkinsfile', 'dockerfile', 'makefile', 'litellm.yaml', 'litellm.yml'], true)) {
            return true;
        }
        // JavaScript: a request only reaches PHP when the file does not exist, so a hunt for bundles / config / source maps.
        // Service workers are exempt (a browser with a stale registration asks for them by itself).
        if (preg_match('#\.(m?js|map)$#', $p)) {
            return !preg_match('#^(sw|service-?worker|ngsw-worker|firebase-messaging-sw|pwabuilder-sw|workbox-[a-z0-9]+|onesignal[a-z]*worker|sw-[a-z0-9]+)\.js$#i', basename($p));
        }
        return (bool) preg_match('#\.(env|ya?ml|json|ini|conf|cfg|toml|properties|tfvars|tfstate|hcl|key|pem|ovpn|bak|sql|old|swp)$#', $p);
    }

    /**
     * Optional wp-config.php constant: LG_BB_POOL_NAMES = ['fkvzeayjws-83' => 'client-a.com', ...] so the
     * report names the other applications instead of showing random pool ids. Leave it unset on any app
     * whose wp-admin users should not learn the names of their neighbours.
     */
    function lg_bb_label_pools($text)
    {
        if (!defined('LG_BB_POOL_NAMES') || !is_array(LG_BB_POOL_NAMES)) {
            return $text;
        }
        foreach (LG_BB_POOL_NAMES as $id => $name) {
            if (is_string($id) && $id !== '' && is_string($name) && $name !== '') {
                $text = str_replace($id, $id . '[' . preg_replace('/[^\w.\- ]/', '', $name) . ']', $text);
            }
        }
        return $text;
    }

    /** PHP-FPM sets each worker's process title to "php-fpm: pool NAME"; on Cloudways one pool = one application. */
    function lg_bb_pool_from_cmdline($raw)
    {
        $raw = str_replace("\0", ' ', (string) $raw);
        return preg_match('/php-fpm: pool (\S+)/', $raw, $m) ? substr($m[1], 0, 24) : '';
    }

    function lg_bb_procs($top = 6, $snap = null, $root = '/proc')
    {
        $dirs = @glob($root . '/[0-9]*', GLOB_ONLYDIR);
        if (!$dirs) {
            return null;
        }
        $own = lg_bb_pool_from_cmdline(lg_bb_read($root . '/self/cmdline', 512)); // the pool THIS request runs in = this site
        $pools = [];  // pool => [workers, rss kb, running]
        $g = [];
        $count = 0;
        $ticks = [];  // pid => [name, cumulative cpu ticks]
        $run = 0;     // processes in state R (on CPU / runnable)
        $disk = 0;    // processes in state D (blocked on disk / swap) — both feed the load average
        foreach ($dirs as $d) {
            $s = lg_bb_read($d . '/status', 4096);
            if ($s === null || !preg_match('/^Name:\s*(.+)$/m', $s, $n) || !preg_match('/^VmRSS:\s*(\d+)/m', $s, $r)) {
                continue; // kernel threads carry no VmRSS
            }
            $count++;
            $name = substr(trim($n[1]), 0, 15);
            $kb = (int) $r[1];
            $pool = strpos($name, 'php') === 0 ? lg_bb_pool_from_cmdline(lg_bb_read($d . '/cmdline', 512)) : '';
            if ($pool === '' && strpos($name, 'php') === 0) {
                $nopool_kb = (isset($nopool_kb) ? $nopool_kb : 0) + $kb;
                $nopool_n = (isset($nopool_n) ? $nopool_n : 0) + 1; // php-fpm master processes (one per application) and anything unnamed
            }
            if ($pool !== '') {
                if (!isset($pools[$pool])) {
                    $pools[$pool] = ['n' => 0, 'kb' => 0, 'run' => 0];
                }
                $pools[$pool]['n']++;
                $pools[$pool]['kb'] += $kb;
            }
            if ($snap !== null) {
                $st = lg_bb_read($d . '/stat', 1024);
                $cp = $st === null ? false : strrpos($st, ')');
                if ($cp !== false) {
                    $f = explode(' ', substr($st, $cp + 2));
                    if (isset($f[12])) {
                        // CPU is tracked per PHP pool (not just "php-fpm8.3") so a busy neighbour is visible; * marks this site's pool.
                        $cname = $pool !== '' ? 'fpm:' . $pool . ($pool === $own ? '*' : '') : $name;
                        $ticks[(int) basename($d)] = [$cname, (int) $f[11] + (int) $f[12]];
                        if ($f[0] === 'R') {
                            $run++;
                            if ($pool !== '') {
                                $pools[$pool]['run']++;
                            }
                        } elseif ($f[0] === 'D') {
                            $disk++;
                        }
                    }
                }
            }
            if (!isset($g[$name])) {
                $g[$name] = ['n' => 0, 'kb' => 0, 'max' => 0];
            }
            $g[$name]['n']++;
            $g[$name]['kb'] += $kb;
            $g[$name]['max'] = max($g[$name]['max'], $kb);
        }
        if (!$g) {
            return null;
        }
        $out = ['procs' => $count, 'db_mb' => 0, 'php_mb' => 0, 'php_n' => 0, 'top' => []];
        if ($pools) {
            uasort($pools, function ($a, $b) {
                return $b['n'] - $a['n'];
            });
            $out['pools'] = [];
            foreach (array_slice($pools, 0, 15, true) as $pn => $v) {
                $out['pools'][] = [$pn, $v['n'], (int) round($v['kb'] / 1024), $v['run']];
            }
            $out['own_pool'] = $own;
            $out['pools_total'] = count($pools);
            $out['pool_other'] = [isset($nopool_n) ? $nopool_n : 0, isset($nopool_kb) ? (int) round($nopool_kb / 1024) : 0];
        }
        foreach ($g as $name => $v) {
            if (preg_match('/^(mysqld|mariadbd)/', $name)) {
                $out['db_mb'] += (int) round($v['kb'] / 1024);
            } elseif (strpos($name, 'php') === 0) {
                $out['php_mb'] += (int) round($v['kb'] / 1024);
                $out['php_n'] += $v['n'];
            }
        }
        uasort($g, function ($a, $b) {
            return $b['kb'] - $a['kb'];
        });
        foreach (array_slice($g, 0, $top, true) as $name => $v) {
            $out['top'][] = [$name, $v['n'], (int) round($v['kb'] / 1024), (int) round($v['max'] / 1024)];
        }

        // CPU use per process name since the previous sample (100 = one full core).
        // Processes that started AND ended between two samples are not seen.
        if ($snap !== null) {
            $out['run'] = $run;
            $out['disk'] = $disk;
            $now = time();
            $prev = json_decode((string) lg_bb_read($snap, 1048576), true);
            if (is_array($prev) && isset($prev['t'], $prev['p']) && $now - $prev['t'] >= 5 && $now - $prev['t'] <= 300) {
                $dt = $now - $prev['t'];
                $cpu = [];
                foreach ($ticks as $pid => $v) {
                    if (isset($prev['p'][$pid]) && $prev['p'][$pid][0] === $v[0] && $v[1] >= $prev['p'][$pid][1]) {
                        $cpu[$v[0]] = (isset($cpu[$v[0]]) ? $cpu[$v[0]] : 0) + ($v[1] - $prev['p'][$pid][1]);
                    }
                }
                arsort($cpu);
                $out['cpu'] = [];
                foreach (array_slice($cpu, 0, 5, true) as $name => $t) {
                    $pct = (int) round($t / 100 / $dt * 100); // CLK_TCK is 100 on Linux
                    if ($pct >= 5) {
                        $out['cpu'][] = [$name, $pct];
                    }
                }
            }
            @file_put_contents($snap, json_encode(['t' => $now, 'p' => $ticks]));
        }
        return $out;
    }

    /** Append one JSON line. The file is a .php with an exit header so it can never be served as text. */
    function lg_bb_append($path, array $row, $max_bytes = 10485760)
    {
        $json = @json_encode($row, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        if (!is_string($json)) {
            return;
        }
        clearstatcache(true, $path);
        $size = @filesize($path);
        if ($size === false) {
            $json = "<?php http_response_code(404); exit; ?>\n" . $json;
        } elseif ($size > $max_bytes) {
            @rename($path, preg_replace('/\.php$/', '.1.php', $path));
            $json = "<?php http_response_code(404); exit; ?>\n" . $json;
        }
        @file_put_contents($path, $json . "\n", FILE_APPEND | LOCK_EX);
    }

    /**
     * Called by db-error.php while WordPress cannot reach its database: records the
     * server state at that moment, and asks MariaDB directly why it refused us
     * (2002 = not running / socket gone, 1040 = too many connections, 2006 = went away…).
     */
    function lg_bb_dropin_log($logfile)
    {
        $dir = dirname($logfile);
        $stamp = $dir . '/dberr.stamp';
        clearstatcache(true, $stamp);
        if (is_file($stamp) && time() - (int) @filemtime($stamp) < 15) {
            return; // one record per 15 s is plenty
        }
        @touch($stamp);

        $row = ['k' => 'dberr', 't' => time(), 'uri' => isset($_SERVER['REQUEST_URI']) ? substr((string) strtok($_SERVER['REQUEST_URI'], '?'), 0, 120) : ''];
        $row += lg_bb_sys();
        $p = lg_bb_procs();
        if ($p) {
            $row['p'] = $p;
        }
        $inf = @glob($dir . '/inflight/*.php');
        $row['inf'] = ['n' => $inf ? count($inf) : 0];

        if (defined('DB_HOST') && function_exists('mysqli_init')) {
            try {
                if (function_exists('mysqli_report')) {
                    mysqli_report(MYSQLI_REPORT_OFF);
                }
                $host = (string) DB_HOST;
                $port = null;
                $sock = null;
                if (strpos($host, ':') !== false) {
                    $parts = explode(':', $host, 2);
                    $host = $parts[0];
                    if (ctype_digit($parts[1])) {
                        $port = (int) $parts[1];
                    } else {
                        $sock = $parts[1];
                    }
                }
                $m = mysqli_init();
                $m->options(MYSQLI_OPT_CONNECT_TIMEOUT, 2);
                $t = microtime(true);
                $ok = @$m->real_connect($host, DB_USER, DB_PASSWORD, null, $port, $sock);
                $row['conn'] = ['ok' => $ok ? 1 : 0, 'errno' => (int) $m->connect_errno, 'err' => substr((string) $m->connect_error, 0, 100), 'ms' => (int) round((microtime(true) - $t) * 1000)];
                if ($ok) {
                    $m->close();
                }
            } catch (\Throwable $e) {
                $row['conn'] = ['ok' => 0, 'err' => substr($e->getMessage(), 0, 100)];
            }
        }
        lg_bb_append($logfile, $row);
    }
}
