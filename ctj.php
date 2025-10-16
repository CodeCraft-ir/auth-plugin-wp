<?php
/*
Plugin Name: Custom JWT Auth (No Composer) - CodeCraft
Description: JWT auth for WP REST API without composer. Stores refresh tokens in DB with rotation (professional).
Version: 1.1 // Updated version for improvements
Author: CodeCraft
*/

if (!defined('ABSPATH')) exit;

// Allow CORS for local development
add_action('init', function() {
    header('Access-Control-Allow-Origin: http://localhost:3000'); // آدرس فرانت‌اند شما
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
    header('Access-Control-Allow-Credentials: true'); // اگر از کوکی‌ها یا اطلاعات احراز هویت استفاده می‌کنید

    // اگر یک درخواست OPTIONS (preflight request) باشد، فوراً پاسخ دهید
    if ('OPTIONS' === $_SERVER['REQUEST_METHOD']) {
        status_header(200);
        exit();
    }
}, 999);

global $cja_db_version;
$cja_db_version = '1.1'; // Updated for potential schema changes

// --- config ---
if (!defined('CJA_ACCESS_TTL')) define('CJA_ACCESS_TTL', apply_filters('cja_access_ttl', 60*60)); // 1 hour, filterable
if (!defined('CJA_REFRESH_TTL')) define('CJA_REFRESH_TTL', apply_filters('cja_refresh_ttl', 7*24*3600)); // 7 days, filterable
if (!defined('CJA_REFRESH_TABLE')) define('CJA_REFRESH_TABLE', 'cja_refresh_tokens');
if (!defined('CJA_SECRET_OPTION')) define('CJA_SECRET_OPTION', 'cja_jwt_secret');
if (!defined('CJA_TEXT_DOMAIN')) define('CJA_TEXT_DOMAIN', 'custom-jwt-auth'); // For i18n

// --- activation: create DB table & secret ---
register_activation_hook(__FILE__, 'cja_activate_plugin');
function cja_activate_plugin() {
    global $wpdb, $cja_db_version;
    $table_name = $wpdb->prefix . CJA_REFRESH_TABLE;

    $installed_ver = get_option('cja_db_version');
    if ($installed_ver != $cja_db_version) {
        $charset_collate = $wpdb->get_charset_collate();
        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
          id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
          jti VARCHAR(64) NOT NULL,
          user_id BIGINT UNSIGNED NOT NULL,
          token_hash VARCHAR(128) NOT NULL,
          issued_at BIGINT UNSIGNED NOT NULL,
          expires_at BIGINT UNSIGNED NOT NULL,
          ip VARCHAR(45) DEFAULT NULL,
          user_agent TEXT DEFAULT NULL,
          revoked TINYINT(1) DEFAULT 0,
          PRIMARY KEY (id),
          UNIQUE KEY jti_unique (jti),
          INDEX user_idx (user_id),
          INDEX expires_idx (expires_at),
          INDEX revoked_idx (revoked)
        ) {$charset_collate};";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);

        update_option('cja_db_version', $cja_db_version);
    }

    // create secret if not set
    if (!get_option(CJA_SECRET_OPTION)) {
        try {
            $secret = bin2hex(random_bytes(32));
        } catch (Exception $e) {
            error_log('CJA: Failed to generate random secret: ' . $e->getMessage());
            $secret = hash_hmac('sha256', uniqid('', true) . wp_salt(), wp_salt());
        }
        update_option(CJA_SECRET_OPTION, $secret, false);
    }

    // Schedule cron for pruning
    if (!wp_next_scheduled('cja_prune_cron')) {
        wp_schedule_event(time(), 'daily', 'cja_prune_cron');
    }
}

register_deactivation_hook(__FILE__, 'cja_deactivate_plugin');
function cja_deactivate_plugin() {
    wp_clear_scheduled_hook('cja_prune_cron');
}

// --- cron for pruning expired tokens ---
add_action('cja_prune_cron', 'cja_prune_expired_tokens');

// --- helper: get secret ---
function cja_get_secret() {
    if (defined('CJA_JWT_SECRET')) return CJA_JWT_SECRET;
    $s = get_option(CJA_SECRET_OPTION);
    if (empty($s)) {
        // fallback (shouldn't happen because activation sets it)
        try { $s = bin2hex(random_bytes(32)); }
        catch (Exception $e) {
            error_log('CJA: Failed to generate fallback secret: ' . $e->getMessage());
            $s = hash_hmac('sha256', uniqid('', true) . wp_salt(), wp_salt());
        }
        update_option(CJA_SECRET_OPTION, $s, false);
    }
    return $s;
}

// --- base64url helpers ---
function cja_base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
function cja_base64url_decode($data) {
    $remainder = strlen($data) % 4;
    if ($remainder) $data .= str_repeat('=', 4 - $remainder);
    return base64_decode(strtr($data, '-_', '+/'));
}

// --- jwt encode / decode (HS256) ---
function cja_jwt_encode($payload, $secret) {
    $header = ['typ' => 'JWT', 'alg' => 'HS256'];
    $h = cja_base64url_encode(json_encode($header));
    $p = cja_base64url_encode(json_encode($payload));
    $sig = hash_hmac('sha256', "$h.$p", $secret, true);
    $s = cja_base64url_encode($sig);
    return "$h.$p.$s";
}

function cja_jwt_decode($token, $secret) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return new WP_Error('invalid_token_format', __('فرمت توکن نامعتبر است.', CJA_TEXT_DOMAIN), ['status'=>403]);

    list($h64, $p64, $s64) = $parts;
    $sig = cja_base64url_decode($s64);
    $expected = hash_hmac('sha256', "$h64.$p64", $secret, true);
    if (!hash_equals($expected, $sig)) return new WP_Error('invalid_signature', __('امضای توکن نامعتبر است.', CJA_TEXT_DOMAIN), ['status'=>403]);

    $payload_json = cja_base64url_decode($p64);
    $payload = json_decode($payload_json, true);
    if (!is_array($payload)) return new WP_Error('invalid_payload', __('پِی‌لود توکن نامعتبر است.', CJA_TEXT_DOMAIN), ['status'=>403]);

    // check iss
    if (($payload['iss'] ?? '') !== get_site_url()) return new WP_Error('invalid_iss', __('Issuer نامعتبر است.', CJA_TEXT_DOMAIN), ['status'=>403]);

    // check nbf if present
    if (isset($payload['nbf']) && time() < (int)$payload['nbf']) return new WP_Error('not_yet_valid', __('توکن هنوز معتبر نیست.', CJA_TEXT_DOMAIN), ['status'=>403]);

    // check exp if present
    if (isset($payload['exp']) && time() > (int)$payload['exp']) return new WP_Error('token_expired', __('توکن منقضی شده است.', CJA_TEXT_DOMAIN), ['status'=>403]);

    return $payload;
}

// --- DB helpers for refresh tokens ---
function cja_store_refresh_token_record($jti, $user_id, $refresh_token, $issued_at, $expires_at, $ip=null, $ua=null) {
    global $wpdb;
    $table = $wpdb->prefix . CJA_REFRESH_TABLE;
    $hash = hash_hmac('sha256', $refresh_token, cja_get_secret());
    $data = [
        'jti' => $jti,
        'user_id' => $user_id,
        'token_hash' => $hash,
        'issued_at' => $issued_at,
        'expires_at' => $expires_at,
        'ip' => $ip,
        'user_agent' => $ua,
        'revoked' => 0
    ];
    $format = ['%s','%d','%s','%d','%d','%s','%s','%d'];
    $wpdb->insert($table, $data, $format);
    return $wpdb->insert_id;
}

function cja_get_refresh_record_by_jti($jti) {
    global $wpdb;
    $table = $wpdb->prefix . CJA_REFRESH_TABLE;
    $sql = $wpdb->prepare("SELECT * FROM {$table} WHERE jti = %s LIMIT 1", $jti);
    return $wpdb->get_row($sql, ARRAY_A);
}

function cja_revoke_refresh_by_jti($jti) {
    global $wpdb;
    $table = $wpdb->prefix . CJA_REFRESH_TABLE;
    return $wpdb->update($table, ['revoked'=>1], ['jti'=>$jti], ['%d'], ['%s']);
}

function cja_revoke_all_for_user($user_id) {
    global $wpdb;
    $table = $wpdb->prefix . CJA_REFRESH_TABLE;
    return $wpdb->update($table, ['revoked'=>1], ['user_id'=>$user_id], ['%d'], ['%d']);
}

function cja_prune_expired_tokens() {
    global $wpdb;
    $table = $wpdb->prefix . CJA_REFRESH_TABLE;
    $now = time();
    return $wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE expires_at < %d OR revoked = 1", $now)); // Also prune revoked for cleanup
}

// --- REST routes ---
add_action('rest_api_init', function() {
    register_rest_route('cja/v1', '/login', [
        'methods' => 'POST',
        'callback' => 'cja_handle_login',
        'permission_callback' => '__return_true'
    ]);
    register_rest_route('cja/v1', '/refresh', [
        'methods' => 'POST',
        'callback' => 'cja_handle_refresh',
        'permission_callback' => '__return_true'
    ]);
    register_rest_route('cja/v1', '/logout', [
        'methods' => 'POST',
        'callback' => 'cja_handle_logout',
        'permission_callback' => '__return_true'
    ]);
    register_rest_route('cja/v1', '/revoke-all', [
        'methods' => 'POST',
        'callback' => 'cja_handle_revoke_all',
        'permission_callback' => function() {
            return current_user_can('activate_plugins') || current_user_can('manage_options'); // محدود به مدیران
        }
    ]);
});

// --- verify WP REST nonce helper (X-WP-Nonce) ---
function cja_require_wp_rest_nonce(WP_REST_Request $request) {
    $nonce = $request->get_header('X-WP-Nonce');
    if (empty($nonce) || !wp_verify_nonce($nonce, 'wp_rest')) {
        return new WP_Error('bad_nonce', __('شماره nonce معتبر نیست. هدر X-WP-Nonce را بررسی کنید.', CJA_TEXT_DOMAIN), ['status'=>403]);
    }
    return true;
}

// --- create tokens ---
function cja_create_access_token($user_id) {
    $user = get_user_by('id', $user_id);
    $issued = time();
    $exp = $issued + CJA_ACCESS_TTL;
    $payload = [
        'iss' => get_site_url(),
        'iat' => $issued,
        'nbf' => $issued, // Added nbf
        'exp' => $exp,
        'sub' => (int)$user_id,
        'scope' => 'access',
        'roles' => $user->roles // Added roles for extensibility
    ];
    $payload = apply_filters('cja_access_payload', $payload, $user_id); // Filter for customization
    return cja_jwt_encode($payload, cja_get_secret());
}

function cja_create_refresh_token($user_id) {
    $issued = time();
    $exp = $issued + CJA_REFRESH_TTL;
    try {
        $jti = bin2hex(random_bytes(16));
    } catch (Exception $e) {
        error_log('CJA: Failed to generate JTI: ' . $e->getMessage());
        $jti = wp_hash($user_id . '|' . microtime(true) . '|' . uniqid('', true));
    }
    $payload = [
        'iss' => get_site_url(),
        'iat' => $issued,
        'nbf' => $issued, // Added nbf
        'exp' => $exp,
        'sub' => (int)$user_id,
        'scope' => 'refresh',
        'jti' => $jti
    ];
    $payload = apply_filters('cja_refresh_payload', $payload, $user_id); // Filter for customization
    $token = cja_jwt_encode($payload, cja_get_secret());
    return ['token'=>$token, 'jti'=>$jti, 'issued'=>$issued, 'expires'=>$exp];
}

// --- endpoint: login ---
function cja_handle_login(WP_REST_Request $request) {
    

    $username = sanitize_text_field($request->get_param('username'));
    $password = $request->get_param('password');

    if (empty($username) || empty($password)) {
        return new WP_Error('missing_credentials', __('نام کاربری و رمز عبور لازم است.', CJA_TEXT_DOMAIN), ['status'=>400]);
    }

    $user = wp_authenticate($username, $password);
    if (is_wp_error($user)) {
        return new WP_Error('invalid_credentials', __('نام کاربری یا رمز عبور اشتباه است.', CJA_TEXT_DOMAIN), ['status'=>403]);
    }

    $user_id = $user->ID;

    // create tokens
    $access = cja_create_access_token($user_id);
    $refresh = cja_create_refresh_token($user_id);

    // store hashed refresh token record
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : null;
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'],0,255) : null;
    cja_store_refresh_token_record($refresh['jti'], $user_id, $refresh['token'], $refresh['issued'], $refresh['expires'], $ip, $ua);

    return rest_ensure_response([
        'user_id' => $user_id,
        'access_token' => $access,
        'access_expires_in' => CJA_ACCESS_TTL,
        'refresh_token' => $refresh['token'],
        'refresh_expires_in' => CJA_REFRESH_TTL
    ]);
}

// --- endpoint: refresh (rotate) ---
function cja_handle_refresh(WP_REST_Request $request) {
 

    $refresh_token = $request->get_param('refresh_token');
    if (empty($refresh_token)) return new WP_Error('missing_token', __('توکن رفرش لازم است.', CJA_TEXT_DOMAIN), ['status'=>400]);

    $decoded = cja_jwt_decode($refresh_token, cja_get_secret());
    if (is_wp_error($decoded)) return $decoded;

    if (empty($decoded['sub']) || ($decoded['scope'] ?? '') !== 'refresh' || empty($decoded['jti'])) {
        return new WP_Error('invalid_refresh', __('توکن رفرش نامعتبر است.', CJA_TEXT_DOMAIN), ['status'=>403]);
    }

    $jti = $decoded['jti'];
    $record = cja_get_refresh_record_by_jti($jti);
    if (empty($record)) return new WP_Error('refresh_not_found', __('توکن رفرش پیدا نشد یا قبلاً باطل شده.', CJA_TEXT_DOMAIN), ['status'=>403]);

    // check match user and not revoked and not expired and hash matches
    if ((int)$record['revoked'] === 1) return new WP_Error('revoked', __('این توکن قبلاً باطل شده است.', CJA_TEXT_DOMAIN), ['status'=>403]);
    if (time() > (int)$record['expires_at']) return new WP_Error('expired', __('توکن رفرش منقضی شده است.', CJA_TEXT_DOMAIN), ['status'=>403]);

    $sent_hash = hash_hmac('sha256', $refresh_token, cja_get_secret());
    if (!hash_equals($record['token_hash'], $sent_hash)) {
        // possible token theft / reuse
        // revoke this record for safety
        cja_revoke_refresh_by_jti($jti);
        return new WP_Error('hash_mismatch', __('توکن رفرش منطبق نیست (ممکن است مورد استفاده قرار گرفته باشد).', CJA_TEXT_DOMAIN), ['status'=>403]);
    }

    // Optional: Check IP/UA mismatch for extra security (comment out if not needed)
    $current_ip = $_SERVER['REMOTE_ADDR'] ?? null;
    $current_ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);
    if ($record['ip'] && $current_ip !== $record['ip']) {
        cja_revoke_refresh_by_jti($jti);
        return new WP_Error('ip_mismatch', __('IP تغییر کرده است. برای امنیت، توکن باطل شد.', CJA_TEXT_DOMAIN), ['status'=>403]);
    }
    // Similarly for UA if desired
    // if ($record['user_agent'] && $current_ua !== $record['user_agent']) { ... }

    $user_id = (int)$record['user_id'];

    // rotate: revoke old and create new refresh token
    cja_revoke_refresh_by_jti($jti);

    $new_refresh = cja_create_refresh_token($user_id);
    cja_store_refresh_token_record($new_refresh['jti'], $user_id, $new_refresh['token'], $new_refresh['issued'], $new_refresh['expires'], $current_ip, $current_ua);

    // new access token
    $new_access = cja_create_access_token($user_id);

    return rest_ensure_response([
        'access_token' => $new_access,
        'access_expires_in' => CJA_ACCESS_TTL,
        'refresh_token' => $new_refresh['token'],
        'refresh_expires_in' => CJA_REFRESH_TTL
    ]);
}

// --- endpoint: logout (revoke single refresh token) ---
function cja_handle_logout(WP_REST_Request $request) {

    $refresh_token = $request->get_param('refresh_token');
    if (empty($refresh_token)) {
        return new WP_Error('missing_token', __('توکن رفرش لازم است.', CJA_TEXT_DOMAIN), ['status'=>400]);
    }

    $decoded = cja_jwt_decode($refresh_token, cja_get_secret());
    if (is_wp_error($decoded)) {
        return $decoded;
    }

    if (empty($decoded['jti'])) {
        return new WP_Error('invalid_token', __('ساختار توکن نامعتبر است (JTI وجود ندارد).', CJA_TEXT_DOMAIN), ['status'=>403]);
    }

    $jti = $decoded['jti'];
    
    $record = cja_get_refresh_record_by_jti($jti);

    if (empty($record)) {
         return new WP_Error('refresh_not_found', __('توکن رفرش پیدا نشد یا قبلاً منقضی/حذف شده است.', CJA_TEXT_DOMAIN), ['status'=>404]);
    }

    if ((int)$record['revoked'] === 1) {
        return new WP_Error('already_revoked', __('این توکن قبلاً باطل شده است.', CJA_TEXT_DOMAIN), ['status'=>403]);
    }
    
    $updated = cja_revoke_refresh_by_jti($jti);
    
    if ($updated === false) {
        return new WP_Error('revoke_failed', __('عملیات باطل‌سازی توکن ناموفق بود.', CJA_TEXT_DOMAIN), ['status'=>500]);
    }

    return rest_ensure_response(['success' => true]);
}

// --- endpoint: revoke-all (admin only) ---
function cja_handle_revoke_all(WP_REST_Request $request) {
    $user_id = (int)$request->get_param('user_id');
    if (empty($user_id)) return new WP_Error('missing_user', __('user_id لازم است', CJA_TEXT_DOMAIN), ['status'=>400]);

    cja_revoke_all_for_user($user_id);
    return rest_ensure_response(['success' => true, 'user_id' => $user_id]);
}

// For internationalization (load text domain)
add_action('plugins_loaded', 'cja_load_textdomain');
function cja_load_textdomain() {
    load_plugin_textdomain(CJA_TEXT_DOMAIN, false, dirname(plugin_basename(__FILE__)) . '/languages/');
}


// JWT for all standard endpoints
add_filter('determine_current_user', function ($user_id) {
    $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/Bearer\s(\S+)/', $auth, $matches)) {
        $token = $matches[1];
        $decoded = cja_jwt_decode($token, cja_get_secret());
        if (is_wp_error($decoded)) return $user_id;
        if (($decoded['scope'] ?? '') !== 'access') return $user_id;
        $user_id = (int)$decoded['sub'];
        if (get_user_by('id', $user_id)) {
            return $user_id;
        }
    }
    return $user_id;
}, 20);

add_filter('rest_authentication_errors', function ($result) {
    if (!empty($result)) return $result;
    return true; // اجازه ادامه در صورت احراز موفق
});