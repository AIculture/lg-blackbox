<?php
/**
 * LG Black Box basic hardening (added in 2.4.0), switched on by "Enable recommended protection".
 *
 * What an anonymous visitor can learn about a WordPress site without logging in, closed in ways that are safe for an
 * ordinary public website as well as for an app:
 *
 *   - ?author=N and /author/<name>/   turn a number into a login name        -> 404 for anonymous visitors
 *   - /wp-json/wp/v2/users            lists user names                       -> removed for anonymous visitors
 *   - /wp-sitemap-users-1.xml         lists author URLs                      -> that one sitemap is removed
 *   - /wp-json/ and namespace indexes print every route                      -> empty for anonymous visitors
 *   - wp-login.php wording            "unknown user" vs "wrong password"     -> one message
 *   - readme.html, license.txt        print the exact WordPress version      -> removed daily (core updates put them back)
 *
 * Deliberately NOT done here, because they break ordinary sites: turning off the normal sitemap, blocking XML-RPC
 * (Jetpack and the mobile apps use it; there is a separate switch), hiding the oEmbed route.
 *
 * Nothing here touches a signed-in visitor, a webhook, or the WordPress admin. Written for PHP 7.4 and later.
 */
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Is basic hardening on? Read once per request from the plugin's config file (the filters below call this on every
 * request). Pass true to read it again, for the page that has just changed it.
 */
function lg_bb_harden_on($fresh = false)
{
    static $on = null;
    if ($on === null || $fresh) {
        $c = lg_bb_rl_read(lg_bb_rl_dir() . '/config.php');
        $on = is_array($c) && !empty($c['harden']);
    }
    return $on;
}

add_action('init', function () {
    if (!lg_bb_harden_on() || is_admin() || (defined('WP_CLI') && WP_CLI) || is_user_logged_in()) {
        return;
    }
    $path = (string) parse_url(isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '', PHP_URL_PATH);
    if (isset($_GET['author']) || preg_match('#/author/#i', $path)) {
        status_header(404);
        nocache_headers();
        exit;
    }
}, 1);

/** The users list and the users sitemap name accounts; the rest of the REST API and the normal sitemap are left alone. */
add_filter('rest_endpoints', function ($endpoints) {
    if (!lg_bb_harden_on() || is_user_logged_in() || !is_array($endpoints)) {
        return $endpoints;
    }
    foreach (array_keys($endpoints) as $route) {
        if (strpos($route, '/wp/v2/users') === 0) {
            unset($endpoints[$route]);
        }
    }
    return $endpoints;
});

add_filter('wp_sitemaps_add_provider', function ($provider, $name) {
    return ($name === 'users' && lg_bb_harden_on()) ? false : $provider;
}, 10, 2);

/** The route index is a map of every endpoint. Signed-in WordPress users keep it (the block editor reads it). */
function lg_bb_harden_strip_index($response)
{
    if (!lg_bb_harden_on() || is_user_logged_in() || !($response instanceof WP_REST_Response)) {
        return $response;
    }
    $data = $response->get_data();
    if (!is_array($data)) {
        return $response;
    }
    foreach (['name', 'description', 'url', 'home', 'gmt_offset', 'timezone_string', 'authentication'] as $k) {
        if (array_key_exists($k, $data)) {
            $data[$k] = is_array($data[$k]) ? [] : '';
        }
    }
    if (array_key_exists('namespaces', $data)) {
        $data['namespaces'] = [];
    }
    if (array_key_exists('routes', $data)) {
        $data['routes'] = new stdClass();
    }
    $response->set_data($data);
    return $response;
}
add_filter('rest_index', 'lg_bb_harden_strip_index');
add_filter('rest_namespace_index', 'lg_bb_harden_strip_index');

/** One wording for every login failure, so the page cannot be used to test which accounts exist. Runs early: a site's own message can still replace it. */
add_filter('login_errors', function ($error) {
    return lg_bb_harden_on() ? apply_filters('lg_bb_harden_login_error', 'Invalid username or password.') : $error;
}, 5);

/** Once a day, from the plugin's tick. */
add_action('lg_bb_tick', function () {
    if (!lg_bb_harden_on() || (defined('LG_BB_KEEP_CORE_INFO_FILES') && LG_BB_KEEP_CORE_INFO_FILES)) {
        return;
    }
    $stamp = lg_bb_dir() . '/harden.stamp';
    clearstatcache(true, $stamp);
    if (is_file($stamp) && time() - (int) @filemtime($stamp) < 86400) {
        return;
    }
    @touch($stamp);
    foreach (['readme.html', 'license.txt'] as $f) {
        if (is_file(ABSPATH . $f)) {
            @unlink(ABSPATH . $f);
        }
    }
}, 30);
