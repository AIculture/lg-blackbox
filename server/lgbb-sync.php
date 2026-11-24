<?php
/**
 * Shares the Black Box automatic block list between the apps of this server.
 *
 * Scanners and brute-forcers hit every site on the box within minutes of each other, but each app's Black Box only
 * learns from its own traffic. This script copies each app's automatic blocks (rl/auto-*.php) into the others, so an
 * address caught by one app is refused by all of them.
 *
 * Run by a server user that is in the same group as the web users, from cron, every 5 minutes (PHP CLI only):
 *   *\/5 * * * * php /home/USER/scripts/lgbb-sync.php >> /home/USER/lgbb-sync.log 2>&1
 *
 * Rules:
 *   - Only apps whose Black Box has automatic blocks switched on take part (as source and as target). An app that
 *     cannot see the real visitor address (behind a proxy without trusted ranges) must not take part.
 *   - A shared entry is marked 'shared' and is never shared again (no ping-pong); it keeps the original expiry.
 *   - Never an address on the target's allow list, the target's own server address, a private/reserved address, or an
 *     address that made signed-in CRM API calls on the target (a customer's office), and never past 500 entries.
 *   - Unblocking an address on one app does not unblock it on the others: remove it where you want it gone.
 *
 * Usage: php lgbb-sync.php [--dry] [--base=/home/USER/applications] [--apps=site1:folder1,site2:folder2]
 */
if (PHP_SAPI !== 'cli') {
    exit;
}
umask(0002); // new files are group-writable: the app users share the www-data group with this user

$opt = ['dry' => false, 'base' => '/home/USER/applications', 'apps' => ''];   // pass --apps=name:appfolder,name2:appfolder2
foreach (array_slice($argv, 1) as $a) {
    if ($a === '--dry') {
        $opt['dry'] = true;
    } elseif (strpos($a, '--base=') === 0) {
        $opt['base'] = substr($a, 7);
    } elseif (strpos($a, '--apps=') === 0) {
        $opt['apps'] = substr($a, 7);
    }
}

function lgbb_read($f)
{
    $s = @file_get_contents($f);
    if (!is_string($s) || strlen($s) < 14) {
        return null;
    }
    $j = json_decode(substr($s, 13), true);
    return is_array($j) ? $j : null;
}

function lgbb_known_good($dir, $ip)
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

$now = time();
$apps = [];
foreach (explode(',', $opt['apps']) as $pair) {
    $parts = explode(':', trim($pair));
    if (count($parts) !== 2) {
        continue;
    }
    $dir = $opt['base'] . '/' . $parts[1] . '/public_html/wp-content/lg-blackbox/rl';
    if (!is_dir($dir)) {
        continue;
    }
    $cfg = lgbb_read($dir . '/config.php');
    if (!$cfg || empty($cfg['auto'])) {
        continue;
    }
    $lists = lgbb_read($dir . '/lists.php');
    $self = lgbb_read($dir . '/self.php');
    $auto = [];
    foreach ((array) glob($dir . '/auto-*.php') as $f) {
        $r = lgbb_read($f);
        if (is_array($r) && !empty($r['ip']) && !empty($r['until']) && (int) $r['until'] > $now) {
            $auto[$r['ip']] = $r;
        }
    }
    $apps[$parts[0]] = ['dir' => $dir, 'allow' => (array) ($lists['allow'] ?? []), 'self' => (array) ($self['ips'] ?? []), 'auto' => $auto];
}

$added = 0;
$skipped = 0;
foreach ($apps as $tname => &$t) {
    foreach ($apps as $sname => $s) {
        if ($sname === $tname) {
            continue;
        }
        foreach ($s['auto'] as $ip => $rec) {
            if (!empty($rec['shared']) || isset($t['auto'][$ip])) {
                continue;
            }
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)
                || in_array($ip, $t['allow'], true) || in_array($ip, $t['self'], true) || count($t['auto']) >= 500
                || lgbb_known_good($t['dir'], $ip)) {
                $skipped++;
                continue;
            }
            $entry = ['ip' => $ip, 'cc' => (string) ($rec['cc'] ?? ''), 'why' => 'shared from ' . $sname . ': ' . substr((string) ($rec['why'] ?? ''), 0, 120),
                'first' => $now, 'last' => 0, 'n' => 0, 'until' => (int) $rec['until'], 'shared' => 1];
            $file = $t['dir'] . '/auto-' . substr(sha1($ip), 0, 20) . '.php';
            if (!$opt['dry']) {
                if (@file_put_contents($file, '<?php exit;?>' . json_encode($entry), LOCK_EX) === false) {
                    fwrite(STDERR, gmdate('c') . " cannot write $file\n");
                    continue;
                }
                @chmod($file, 0664);
            }
            $t['auto'][$ip] = $entry;
            $added++;
            echo gmdate('c') . " $ip -> $tname (from $sname)" . ($opt['dry'] ? ' [dry run]' : '') . "\n";
        }
    }
}
unset($t);
if ($added || $skipped) {
    echo gmdate('c') . " shared $added, skipped $skipped, apps taking part: " . implode(',', array_keys($apps)) . "\n";
}
