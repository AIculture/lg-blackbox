<?php
/**
 * LG Black Box "Enable recommended protection" (added in 2.4.0).
 *
 * A new user should not have to learn ten switches before the server is reasonably protected. One button turns
 * on a safe baseline, tells exactly what it changed, and can be pressed again at any time (it never turns anything
 * off and never overwrites numbers you tuned).
 *
 * Safety rules, because a wrong setting here can lock real visitors out:
 *   - Address-based protections count visitors by IP. Behind a proxy or CDN the plugin does not trust yet, every
 *     visitor looks like the proxy's address, so one bot could get the whole site refused. In that case ONLY the
 *     protections that do not depend on the visitor's address are enabled, and the page says how to fix it.
 *   - The address pressing the button is put on the allow list first, so the person enabling it cannot be locked out.
 *   - If the gate file (the mu-plugin that does the early work) cannot be installed, nothing address-based is enabled
 *     and the reason is given in plain words.
 *   - The country filter stays off: it only works behind Cloudflare and can lock out travellers.
 *
 * Written for PHP 7.4 and later.
 */
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Can the visitor's real address be trusted on this request? Evaluated on the request of the person pressing the
 * button, which arrives through the same path as every visitor.
 *
 * @return array ['state' => 'ok'|'untrusted', 'peer' => string, 'why' => string]
 */
function lg_bb_reco_proxy_state()
{
    $d = lg_bb_ip_diag();
    $cf = !empty($_SERVER['HTTP_CF_RAY']) || !empty($_SERVER['HTTP_CF_CONNECTING_IP']);
    if (!$d['trusted'] && ($d['ignored'] || $cf)) {
        return [
            'state' => 'untrusted',
            'peer' => $d['peer'],
            'why' => 'this site is behind a proxy or CDN that is not trusted yet (requests arrive from ' . $d['peer'] . '), so every visitor would look like one address',
        ];
    }
    return ['state' => 'ok', 'peer' => $d['peer'], 'why' => ''];
}

/**
 * The recommended baseline, with the current state of each item.
 *
 * @return array[] [key, label, what it does, is on, depends on the visitor's address]
 */
function lg_bb_reco_items()
{
    $c = lg_bb_rl_cfg();
    $gate = lg_bb_gate_installed();
    $to = lg_bb_alert_recipients();
    return [
        ['login', 'Login protection', 'Refuses an address for ' . (int) $c['block'] . ' minutes after ' . (int) $c['limit'] . ' failed logins in ' . (int) $c['window'] . ' minutes (WordPress login, XML-RPC and the app login).', !empty($c['enabled']) && $gate, true],
        ['probe', 'Scanner shield', 'Answers requests for .env files, backups, phpMyAdmin and similar with a plain 404, then blocks repeat scanners.', $c['probe'] === 'on' && $gate, true],
        ['auto', 'Automatic blocks', 'Repeat offenders are refused for ' . (int) $c['auto_days'] . ' days. Signed-in users and allow-listed addresses are never blocked.', !empty($c['auto']) && $gate, true],
        ['rate', 'Request-rate limit', 'A flood from one address gets a 429 before WordPress even loads (' . (int) $c['rate_limit'] . ' requests a minute for anonymous visitors).', !empty($c['rate']) && $gate, true],
        ['ua', 'Under-attack mode', 'While the server is overloaded, anonymous visitors get a quarter of that rate. Signed-in users and webhooks are not slowed.', lg_bb_sec_ua_on() && $gate, true],
        ['flood', '404 and refused-link watch', 'An address causing many page misses or refused links is added to the automatic block list.', lg_bb_sec_flood_on() && !empty($c['auto']) && $gate, true],
        ['cron_guard', 'wp-cron guard', 'Only this server itself may call wp-cron.php, so nobody can make WordPress load by calling it.', !empty($c['cron_guard']) && $gate, true],
        ['harden', 'Basic hardening', 'Hides user names (author pages, the REST user list, the users sitemap, login error wording), empties the public REST route list and removes readme.html and license.txt.', lg_bb_harden_on(true), false],
        ['recorder', 'Request recorder', 'Keeps a compact record of requests. It also tells automatic blocks which addresses are real signed-in users.', lg_bb_rec_on(), false],
        ['alerts', 'Email alerts', $to ? 'Security alerts go to ' . implode(', ', $to) . '.' : 'No valid address yet: set one under Security checks and alerts.', (bool) $to, false],
    ];
}

/** "7 of 10 recommended protections are on". */
function lg_bb_reco_summary()
{
    $on = 0;
    $items = lg_bb_reco_items();
    foreach ($items as $it) {
        $on += $it[3] ? 1 : 0;
    }
    return [$on, count($items)];
}

/**
 * Turn the baseline on. Idempotent, never turns anything off, keeps tuned numbers.
 *
 * @return array ['enabled' => string[], 'already' => string[], 'skipped' => array[label, reason][], 'ip' => string, 'msg' => string]
 */
function lg_bb_reco_apply()
{
    $before = [];
    foreach (lg_bb_reco_items() as $it) {
        $before[$it[0]] = $it[3];
    }
    $cfg = lg_bb_rl_cfg();
    $lists = lg_bb_rl_lists();
    $out = ['enabled' => [], 'already' => [], 'skipped' => [], 'ip' => '', 'msg' => ''];

    $why_not = '';
    $proxy = lg_bb_reco_proxy_state();
    if ($proxy['state'] === 'untrusted') {
        $why_not = $proxy['why'] . '. Add the proxy\'s address ranges to LG_CRM_TRUSTED_PROXIES in wp-config.php, then press the button again';
    } elseif (!lg_bb_gate_install()) {
        $why_not = 'the gate file could not be installed: ' . lg_bb_gate_why();
    }

    if ($why_not === '') {
        $me = lg_bb_ip();
        if ($me !== '' && lg_bb_rl_public_ip($me) && !in_array($me, $lists['allow'], true)) {
            $lists['allow'][] = $me; // never lock out the person enabling it
            lg_bb_rl_write(lg_bb_rl_dir() . '/lists.php', $lists);
            $out['ip'] = $me;
        }
        $cfg['enabled'] = 1;
        $cfg['probe'] = 'on';
        $cfg['auto'] = 1;
        $cfg['rate'] = 1;
        $cfg['cron_guard'] = 1;
        $cfg['ua'] = 1;
        foreach (['limit' => 8, 'window' => 10, 'block' => 30, 'probe_limit' => 5, 'probe_window' => 10, 'probe_block' => 60, 'auto_days' => 30,
                  'rate_limit' => 120, 'rate_limit_auth' => 600, 'rate_limit_bot' => 20, 'rate_auto_days' => 1] as $k => $v) {
            if (empty($cfg[$k])) {
                $cfg[$k] = $v; // only fills what is missing: numbers you tuned stay
            }
        }
        if (empty($cfg['ua_load'])) {
            $cfg['ua_load'] = 3.0;
        }
        $sc = lg_bb_sec_read('config');
        $sc['flood'] = 1;
        lg_bb_sec_write('config', $sc);
    }

    // These do not depend on the visitor's address, so they are always safe.
    $cfg['harden'] = 1;
    $cfg['recommended_on'] = time();
    lg_bb_rl_write(lg_bb_rl_dir() . '/config.php', $cfg);
    update_option('lg_bb_recorder', '1', true);

    foreach (lg_bb_reco_items() as $it) {
        if ($before[$it[0]]) {
            $out['already'][] = $it[1];
        } elseif ($it[3]) {
            $out['enabled'][] = $it[1];
        } else {
            $out['skipped'][] = [$it[1], $it[4] && $why_not !== '' ? $why_not : ($it[0] === 'alerts' ? 'no valid email address is set' : 'could not be switched on')];
        }
    }

    $m = [];
    if ($out['enabled']) {
        $m[] = 'Enabled: ' . implode(', ', $out['enabled']) . '.';
    }
    if ($out['already']) {
        $m[] = 'Already on: ' . count($out['already']) . '.';
    }
    if ($out['ip'] !== '') {
        $m[] = 'Your address ' . $out['ip'] . ' was added to the allow list so you cannot lock yourself out.';
    }
    if ($why_not !== '') {
        $m[] = 'NOT enabled (address-based protections): ' . $why_not . '.';
    } elseif ($out['skipped']) {
        $m[] = 'Not enabled: ' . implode('; ', array_map(function ($s) {
            return $s[0] . ' (' . $s[1] . ')';
        }, $out['skipped'])) . '.';
    }
    if (!$m) {
        $m[] = 'Nothing to change.';
    }
    $out['msg'] = implode(' ', $m);
    return $out;
}

/** The card at the top of the Black Box page. */
function lg_bb_reco_panel()
{
    $items = lg_bb_reco_items();
    list($on, $total) = lg_bb_reco_summary();
    $proxy = lg_bb_reco_proxy_state();
    $url = wp_nonce_url(admin_url('admin-post.php?action=lg_bb_login&op=recommended&ip=0.0.0.0'), 'lg_bb_login');
    ?>
    <h2 id="lg-recommended">Recommended protection</h2>
    <p>
        <?php if ($on >= $total): ?>
            <strong style="color:#1a7f37">All <?php echo (int) $total; ?> recommended protections are on.</strong>
        <?php else: ?>
            <strong><?php echo (int) $on; ?> of <?php echo (int) $total; ?> recommended protections are on.</strong>
            One click turns on a safe baseline for any site. It tells you exactly what it changed, adds your own address to the
            allow list first, never turns anything off, and keeps numbers you tuned.
        <?php endif; ?>
    </p>
    <?php if ($proxy['state'] === 'untrusted' && $on < $total): ?>
        <div class="notice notice-warning inline" style="margin:8px 0;max-width:900px"><p>
            <strong>Address-based protections are held back on this site.</strong>
            It is behind a proxy or CDN the plugin does not trust yet (requests arrive from <code><?php echo esc_html($proxy['peer']); ?></code>),
            so every visitor would look like one address and a single bot could get everyone refused. Add that provider's address ranges to
            <code>LG_CRM_TRUSTED_PROXIES</code> in <code>wp-config.php</code> (Cloudflare publishes its ranges at cloudflare.com/ips), then press the button again.
            The button still turns on everything that does not depend on the visitor's address.
        </p></div>
    <?php endif; ?>
    <table class="widefat striped" style="max-width:980px">
        <thead><tr><th style="width:210px">Protection</th><th>What it does</th><th style="width:90px">Status</th></tr></thead>
        <tbody>
            <?php foreach ($items as $it): ?>
                <tr>
                    <td><strong><?php echo esc_html($it[1]); ?></strong></td>
                    <td><?php echo esc_html($it[2]); ?></td>
                    <td><?php echo $it[3]
                        ? '<span class="lgbb-chip is-good"><span class="dashicons dashicons-yes-alt"></span>On</span>'
                        : '<span class="lgbb-chip is-warn"><span class="dashicons dashicons-warning"></span>Off</span>'; ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <p>
        <?php if ($on < $total): ?>
            <a class="button button-primary button-hero" href="<?php echo esc_url($url); ?>">Enable recommended protection</a>
        <?php endif; ?>
        <small>The country filter is not part of this: it only works behind Cloudflare and can lock out travellers. Each protection can still be switched off one by one above.</small>
    </p>
    <?php
}

/**
 * First-run nudge: a site that has installed Black Box but switched nothing on is told once, with a link to the card
 * (it does not press the button for you). Hidden for good once anything is on or it is dismissed.
 */
add_action('admin_notices', function () {
    if (!current_user_can('manage_options')) {
        return;
    }
    $screen = function_exists('get_current_screen') ? get_current_screen() : null;
    if (!$screen || !in_array($screen->id, ['dashboard', 'plugins'], true)) {
        return;
    }
    $c = lg_bb_rl_cfg();
    if (!empty($c['recommended_on']) || !empty($c['enabled']) || $c['probe'] === 'on' || !empty($c['auto']) || !empty($c['rate'])) {
        return;
    }
    if (get_user_meta(get_current_user_id(), 'lg_bb_reco_dismissed', true)) {
        return;
    }
    $go = admin_url('tools.php?page=lg-blackbox#lg-recommended');
    $no = wp_nonce_url(admin_url('admin-post.php?action=lg_bb_login&op=reco_dismiss&ip=0.0.0.0'), 'lg_bb_login');
    echo '<div class="notice notice-warning"><p><strong>LG Black Box is installed, but no protection is switched on yet.</strong> '
        . '<a href="' . esc_url($go) . '">Review and enable the recommended protection</a> (one click, nothing is changed until you press it). '
        . '<a href="' . esc_url($no) . '" style="margin-left:12px">Dismiss</a></p></div>';
});
