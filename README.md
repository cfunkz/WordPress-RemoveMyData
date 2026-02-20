# Remove My Data (WordPress Plugin)

Most "delete account" plugins for WordPress are either too bloated or surprisingly insecure. I built **Remove My Data** to provide a middle ground: a lightweight, GDPR-friendly way for users to delete their own accounts using a secure, email-verified workflow.

## Screenshots

<img width="1888" height="721" alt="image" src="https://github.com/user-attachments/assets/29e01614-3c9a-42c8-9b7e-d66ca35f74dd" />
<img width="1689" height="827" alt="image" src="https://github.com/user-attachments/assets/aee60b12-7f4e-4cea-9f0b-05bdc08c74d9" />

## Features

* **Email Verification:** Users can't accidentally click a button and vanish. They receive a secure, time-limited link (valid for 1 hour).
* **Security First:** Uses SHA-256 token hashing and `hash_equals` to prevent timing attacks.
* **Throttling:** Prevents "email bombing" by limiting deletion requests to one per hour per user.
* **Admin Control:** You choose exactly which roles (e.g., Subscribers only) have the right to delete themselves. Administrators are hard-blocked from deleting themselves through this tool for safety.
* **Customizable UI:** Change the button colors, titles, and success messages directly from the WP admin to match your theme.

## How it works

1. **The Shortcode:** Drop `[remove_data_profile]` onto any page (like a User Account or Settings page).
2. **The Request:** The user clicks the button, and the plugin sends an email with a unique, hashed token.
3. **The Wipe:** Upon clicking the email link, the plugin:
* Wipes the user's comments.
* Fires a developer hook for custom cleanup.
* Deletes the user account.
* Notifies the site admin (optional).

## For Developers: Extending the Wipe

If your site uses WooCommerce, BuddyPress, or custom tables, you’ll want to wipe that data too. You can hook into the deletion process easily:

```php
add_action( 'rmd_before_delete_user', function( $user_id, $user ) {
    // Delete custom meta, orders, or files here
    // $user is the full WP_User object snapshot
}, 10, 2 );

```

## Installation

1. Upload the `remove-my-data` folder to your `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Go to **Remove My Data** in your admin sidebar to configure your settings.
4. Add the shortcode `[remove_data_profile]` where you want the deletion card to appear.
