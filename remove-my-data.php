<?php
/**
 * Plugin Name: Remove My Data
 * Description: GDPR-compliant account deletion with email verification, token hashing, throttling, and extensible data wipe hooks.
 * Version:     4.0
 * Author:      cFunkz
 */

if ( ! defined( 'ABSPATH' ) ) exit;

// =========================================================================
// 1. Activation defaults
// =========================================================================

register_activation_hook( __FILE__, 'rmd_set_defaults' );
function rmd_set_defaults() {
    $defaults = [
        'rmd_primary_color' => '#dc2626',
        'rmd_title'         => 'Delete Account & Data',
        'rmd_description'   => 'For your security, we will send a confirmation link to your email. The link expires in 1 hour.',
        'rmd_button_text'   => 'Send Deletion Email',
        'rmd_success_msg'   => 'Your account and all associated data have been permanently deleted.',
        'rmd_allowed_roles' => [ 'subscriber' ],
        'rmd_notify_admin'  => '1',
    ];
    foreach ( $defaults as $key => $value ) {
        if ( get_option( $key ) === false ) {
            update_option( $key, $value );
        }
    }
}

// =========================================================================
// 2. Admin settings
// =========================================================================

add_action( 'admin_menu', 'rmd_add_admin_menu' );
function rmd_add_admin_menu() {
    add_menu_page(
        'Remove My Data',
        'Remove My Data',
        'manage_options',
        'remove-my-data',
        'rmd_settings_page',
        'dashicons-trash'
    );
}

add_action( 'admin_init', 'rmd_register_settings' );
function rmd_register_settings() {
    register_setting( 'rmd_settings_group', 'rmd_primary_color', 'sanitize_hex_color' );
    register_setting( 'rmd_settings_group', 'rmd_title',         'sanitize_text_field' );
    register_setting( 'rmd_settings_group', 'rmd_description',   'wp_kses_post' );
    register_setting( 'rmd_settings_group', 'rmd_button_text',   'sanitize_text_field' );
    register_setting( 'rmd_settings_group', 'rmd_success_msg',   'sanitize_text_field' );
    register_setting( 'rmd_settings_group', 'rmd_notify_admin',  'absint' );

    // Sanitize roles array — only accept known WP role slugs.
    register_setting( 'rmd_settings_group', 'rmd_allowed_roles', 'rmd_sanitize_roles' );
}

function rmd_sanitize_roles( $input ) {
    if ( ! is_array( $input ) ) return [];
    $valid = array_keys( wp_roles()->get_names() );
    $clean = [];
    foreach ( $input as $role ) {
        $role = sanitize_key( $role );
        if ( in_array( $role, $valid, true ) && $role !== 'administrator' ) {
            $clean[] = $role;
        }
    }
    return $clean;
}

function rmd_settings_page() {
    if ( ! current_user_can( 'manage_options' ) ) return;
    $allowed_roles = get_option( 'rmd_allowed_roles', [] );
    $wp_roles      = wp_roles()->get_names();
    ?>
    <div class="wrap">
        <h1>Remove My Data — Settings</h1>
        <form method="post" action="options.php">
            <?php settings_fields( 'rmd_settings_group' ); ?>
            <table class="form-table">
                <tr>
                    <th>Allowed Roles</th>
                    <td>
                        <?php foreach ( $wp_roles as $role_key => $role_name ) :
                            if ( $role_key === 'administrator' ) continue; ?>
                            <label style="display:block; margin-bottom:5px;">
                                <input type="checkbox"
                                       name="rmd_allowed_roles[]"
                                       value="<?php echo esc_attr( $role_key ); ?>"
                                       <?php checked( in_array( $role_key, $allowed_roles, true ) ); ?>>
                                <?php echo esc_html( $role_name ); ?>
                            </label>
                        <?php endforeach; ?>
                    </td>
                </tr>
                <tr>
                    <th>Notify Admin on Deletion</th>
                    <td>
                        <label>
                            <input type="checkbox" name="rmd_notify_admin" value="1"
                                   <?php checked( get_option( 'rmd_notify_admin' ), '1' ); ?>>
                            Send an email to the site admin when an account is deleted.
                        </label>
                    </td>
                </tr>
                <tr><th>Button Color</th><td><input type="color" name="rmd_primary_color" value="<?php echo esc_attr( get_option( 'rmd_primary_color' ) ); ?>"></td></tr>
                <tr><th>Card Title</th><td><input type="text" class="regular-text" name="rmd_title" value="<?php echo esc_attr( get_option( 'rmd_title' ) ); ?>"></td></tr>
                <tr><th>Description</th><td><textarea class="regular-text" name="rmd_description" rows="3"><?php echo esc_textarea( get_option( 'rmd_description' ) ); ?></textarea></td></tr>
                <tr><th>Button Text</th><td><input type="text" class="regular-text" name="rmd_button_text" value="<?php echo esc_attr( get_option( 'rmd_button_text' ) ); ?>"></td></tr>
                <tr><th>Success Message</th><td><input type="text" class="regular-text" name="rmd_success_msg" value="<?php echo esc_attr( get_option( 'rmd_success_msg' ) ); ?>"></td></tr>
            </table>
            <?php submit_button(); ?>
        </form>

        <hr>
        <h2>Extensibility — Developer Hook</h2>
        <p>To wipe custom data when a user is deleted, add this to your theme or plugin:</p>
        <pre style="background:#f1f1f1; padding:12px; border-radius:6px;">
add_action( 'rmd_before_delete_user', function( $user_id, $user ) {
    // e.g. delete WooCommerce orders, form entries, etc.
    // $user is the WP_User object — snapshot it now, it gets deleted after this hook.
}, 10, 2 );
        </pre>
    </div>
    <?php
}

// =========================================================================
// 3. Email handler (hooks on init, any page)
// =========================================================================

add_action( 'init', 'rmd_handle_email_confirmation' );
function rmd_handle_email_confirmation() {

    if ( ! isset( $_GET['rmd_action'] ) || $_GET['rmd_action'] !== 'confirm_wipe' ) return;
    if ( ! is_user_logged_in() ) {
        wp_die( 'You must be logged in to confirm account deletion.', 'Session Required', [ 'response' => 403 ] );
    }

    $user_id    = get_current_user_id();
    $raw_token  = isset( $_GET['token'] ) ? sanitize_text_field( wp_unslash( $_GET['token'] ) ) : '';

    $stored = get_user_meta( $user_id, '_rmd_del_data', true );

    if ( ! $stored || empty( $stored['token_hash'] ) || empty( $stored['expiry'] ) ) {
        wp_die( 'No pending deletion request found. Please request a new link.', 'Not Found', [ 'response' => 404 ] );
    }

    // Expiry check.
    if ( time() > (int) $stored['expiry'] ) {
        delete_user_meta( $user_id, '_rmd_del_data' );
        wp_die( 'This link has expired (1 hour limit). Please request a new one.', 'Link Expired', [ 'response' => 410 ] );
    }

    // Token check — compare hash of the submitted token against the stored hash.
    // hash_equals prevents timing attacks.
    if ( ! hash_equals( $stored['token_hash'], wp_hash( $raw_token ) ) ) {
        wp_die( 'Invalid or already-used security token.', 'Forbidden', [ 'response' => 403 ] );
    }

    // Hard block: administrators can never be deleted this way.
    if ( current_user_can( 'administrator' ) ) {
        wp_die( 'Administrator accounts cannot be deleted via this tool.', 'Forbidden', [ 'response' => 403 ] );
    }

    // ── Snapshot user details before deletion ────────────────────────────
    $user = get_userdata( $user_id );

    // Clean up meta before delete so nothing sensitive lingers.
    delete_user_meta( $user_id, '_rmd_del_data' );
    delete_user_meta( $user_id, '_rmd_last_email_time' );

    // ── Fire hook so other plugins can delete their own data first ────────
    // Passes the full WP_User object because it won't exist after wp_delete_user.
    do_action( 'rmd_before_delete_user', $user_id, $user );

    // ── Built-in data wipe ────────────────────────────────────────────────
    require_once ABSPATH . 'wp-admin/includes/user.php';

    // Delete comments made by the user.
    $comments = get_comments( [ 'user_id' => $user_id, 'status' => 'any' ] );
    foreach ( $comments as $comment ) {
        wp_delete_comment( (int) $comment->comment_ID, true );
    }

    // Delete the user account. Pass 0 so any authored posts are left
    // unattributed (null is undocumented — always be explicit).
    wp_delete_user( $user_id, 0 );

    // ── Notify admin ─────────────────────────────────────────────────────
    if ( get_option( 'rmd_notify_admin' ) ) {
        wp_mail(
            get_option( 'admin_email' ),
            sprintf( '[%s] Account deleted: %s', get_bloginfo( 'name' ), $user->user_email ),
            sprintf(
                "A user has deleted their account and data.\n\nDisplay name: %s\nEmail: %s\nUser ID: %d\nTime (UTC): %s",
                $user->display_name,
                $user->user_email,
                $user_id,
                gmdate( 'Y-m-d H:i:s' )
            )
        );
    }

    // ── Store one-time success flag, redirect ─────────────────────────────
    // Using a transient keyed by a random value stored in a cookie avoids
    // showing the success banner to anyone who guesses the URL.
    $flash_key = wp_generate_password( 16, false );
    set_transient( 'rmd_deleted_' . $flash_key, 1, 120 ); // 2 min window

    wp_logout();

    wp_safe_redirect( add_query_arg( 'rmd_done', $flash_key, home_url( '/' ) ) );
    exit;
}

// =========================================================================
// 4. Shortcode
// =========================================================================

add_shortcode( 'remove_data_profile', 'rmd_shortcode_output' );
function rmd_shortcode_output() {

    // ── One-time success flash ────────────────────────────────────────────
    if ( isset( $_GET['rmd_done'] ) ) {
        $flash_key = sanitize_text_field( wp_unslash( $_GET['rmd_done'] ) );
        $transient = 'rmd_deleted_' . $flash_key;
        if ( get_transient( $transient ) ) {
            delete_transient( $transient ); // one-time only
            $color = esc_attr( get_option( 'rmd_primary_color', '#dc2626' ) );
            $msg   = esc_html( get_option( 'rmd_success_msg' ) );
            return '<div style="max-width:600px;margin:2rem auto;padding:1.5rem;background:' . $color . ';color:#fff;border-radius:12px;text-align:center;">' . $msg . '</div>';
        }
    }

    if ( ! is_user_logged_in() ) {
        return '<p style="text-align:center;">Please log in to manage your data.</p>';
    }

    $user          = wp_get_current_user();
    $allowed_roles = get_option( 'rmd_allowed_roles', [] );

    if ( empty( array_intersect( $allowed_roles, (array) $user->roles ) ) ) {
        return '<p style="text-align:center;">Account deletion is not available for your account type.</p>';
    }

    $message  = '';
    $cooldown = 3600;
    $last_sent = (int) get_user_meta( $user->ID, '_rmd_last_email_time', true );

    // ── Handle form submission ────────────────────────────────────────────
    if ( isset( $_POST['request_deletion_email'] ) ) {

        if ( ! isset( $_POST['rmd_nonce'] ) || ! wp_verify_nonce( wp_unslash( $_POST['rmd_nonce'] ), 'rmd_request_action' ) ) {
            $message = '<p class="rmd-msg rmd-msg--error">Security check failed. Please refresh and try again.</p>';

        } elseif ( $last_sent && ( time() - $last_sent < $cooldown ) ) {
            $wait    = (int) ceil( ( $cooldown - ( time() - $last_sent ) ) / 60 );
            $message = '<p class="rmd-msg rmd-msg--error">Please wait ' . $wait . ' minute(s) before requesting another email.</p>';

        } else {
            // Generate a strong random token, store only its hash.
            $raw_token  = wp_generate_password( 40, false );
            $token_hash = wp_hash( $raw_token ); // SHA-256 keyed with WP secret keys

            update_user_meta( $user->ID, '_rmd_del_data', [
                'token_hash' => $token_hash,
                'expiry'     => time() + $cooldown,
            ] );
            update_user_meta( $user->ID, '_rmd_last_email_time', time() );

            $confirm_url = add_query_arg(
                [ 'rmd_action' => 'confirm_wipe', 'token' => rawurlencode( $raw_token ) ],
                home_url( '/' )
            );

            $subject = sprintf( '[%s] Confirm permanent account deletion', get_bloginfo( 'name' ) );
            $body    = sprintf(
                "Hello %s,\n\nYou requested to permanently delete your account and all associated data on %s.\n\nThis action CANNOT be undone. To confirm, click the link below within 1 hour:\n\n%s\n\nIf you did not request this, please change your password immediately.\n\nThis link expires: %s UTC",
                $user->display_name,
                get_bloginfo( 'name' ),
                $confirm_url,
                gmdate( 'Y-m-d H:i:s', time() + $cooldown )
            );

            wp_mail( $user->user_email, $subject, $body );

            $message = '<p class="rmd-msg rmd-msg--ok">Confirmation email sent to ' . esc_html( $user->user_email ) . '. The link expires in 1 hour.</p>';
        }
    }

    // ── Render ────────────────────────────────────────────────────────────
    $btn_color = get_option( 'rmd_primary_color', '#dc2626' );

    ob_start(); ?>
    <style>
        .rmd-card { border: 1px solid rgba(128,128,128,0.2); border-radius: 16px; padding: 1.5rem; max-width: 600px; margin: 1rem auto; font-family: system-ui, sans-serif; text-align: center; }
        .rmd-btn { background: <?php echo esc_attr( $btn_color ); ?>; color: #fff; border: none; width: 100%; padding: 1rem; border-radius: 10px; font-weight: 700; cursor: pointer; font-size: 1rem; transition: opacity .15s; }
        .rmd-btn:hover:not(:disabled) { opacity: .85; }
        .rmd-btn:disabled { background: #ccc; cursor: not-allowed; }
        .rmd-msg { font-weight: 600; margin: .75rem 0; }
        .rmd-msg--ok    { color: #16a34a; }
        .rmd-msg--error { color: #dc2626; }
        .rmd-warning { font-size: .8rem; opacity: .55; margin-top: 1rem; line-height: 1.5; }
    </style>

    <div class="rmd-card">
        <h2 style="margin-top:0;"><?php echo esc_html( get_option( 'rmd_title' ) ); ?></h2>
        <div style="margin-bottom:1.5rem; opacity:.8; line-height:1.5;">
            <?php echo wp_kses_post( get_option( 'rmd_description' ) ); ?>
        </div>

        <?php echo $message; ?>

        <form method="POST">
            <?php wp_nonce_field( 'rmd_request_action', 'rmd_nonce' ); ?>
            <button type="submit" name="request_deletion_email" class="rmd-btn">
                <?php echo esc_html( get_option( 'rmd_button_text' ) ); ?>
            </button>
        </form>

        <p class="rmd-warning">
            ⚠️ This will permanently delete your account and all your data. This action cannot be undone.
        </p>
    </div>
    <?php
    return ob_get_clean();
}