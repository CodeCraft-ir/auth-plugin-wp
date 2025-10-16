# Custom JWT Auth (No Composer) - CodeCraft

A professional WordPress plugin for JWT authentication with WP REST API, designed to work without Composer dependencies. It provides a secure and robust authentication system with refresh token management and rotation, storing tokens in the database.

## Features

*   **JWT Authentication:** Securely authenticate users via JSON Web Tokens for WP REST API.
*   **No Composer Required:** Self-contained and ready to use without external dependencies.
*   **Refresh Token Management:** Implements refresh tokens with rotation for enhanced security and user experience.
*   **Database Storage:** Stores refresh tokens in a dedicated database table for persistence and revocation.
*   **Token Revocation:** Allows for individual or mass revocation of refresh tokens.
*   **CORS Support:** Configurable CORS headers for seamless integration with frontend applications.
*   **Internationalization (i18n):** Ready for translation.

## Installation

1.  **Upload:** Upload the `ctj` folder to the `/wp-content/plugins/` directory of your WordPress installation.
2.  **Activate:** Activate the plugin through the 'Plugins' menu in WordPress.
3.  **Configure Secret Key:** **Crucially**, define a strong, unique secret key in your `wp-config.php` file. Add the following line *before* `/* That's all, stop editing! Happy publishing. */`:

    ```php
    define('CJA_JWT_SECRET', 'YOUR_VERY_STRONG_AND_UNIQUE_SECRET_KEY_HERE');
    ```
    **Important:** Replace `YOUR_VERY_STRONG_AND_UNIQUE_SECRET_KEY_HERE` with a truly random and secure string. You can use online tools to generate such keys.

## Usage (REST API Endpoints)

The plugin registers several REST API endpoints under the `cja/v1` namespace for authentication and token management.

### 1. `POST /cja/v1/login`

Authenticates a user and issues new access and refresh tokens.

*   **Method:** `POST`
*   **Parameters (JSON Body):**
    *   `username` (string, required): The user's username.
    *   `password` (string, required): The user's password.
*   **Success Response (200 OK):**
    ```json
    {
        "user_id": 1,
        "access_token": "eyJ...",
        "access_expires_in": 3600, // In seconds (e.g., 1 hour)
        "refresh_token": "eyJ...",
        "refresh_expires_in": 604800 // In seconds (e.g., 7 days)
    }
    ```
*   **Error Responses:**
    *   `400 Bad Request`: `missing_credentials`
    *   `403 Forbidden`: `invalid_credentials`

### 2. `POST /cja/v1/refresh`

Rotates an expired access token using a valid refresh token to obtain a new access token and a new refresh token.

*   **Method:** `POST`
*   **Parameters (JSON Body):**
    *   `refresh_token` (string, required): The current refresh token.
*   **Success Response (200 OK):**
    ```json
    {
        "access_token": "eyJ...",
        "access_expires_in": 3600,
        "refresh_token": "eyJ...",
        "refresh_expires_in": 604800
    }
    ```
*   **Error Responses:**
    *   `400 Bad Request`: `missing_token`
    *   `403 Forbidden`: `invalid_refresh`, `invalid_signature`, `token_expired`, `refresh_not_found`, `revoked`, `hash_mismatch`, `ip_mismatch` (if IP checking is enabled)

### 3. `POST /cja/v1/logout`

Revokes a specific refresh token, invalidating it and any associated access tokens.

*   **Method:** `POST`
*   **Parameters (JSON Body):**
    *   `refresh_token` (string, required): The refresh token to revoke.
*   **Success Response (200 OK):**
    ```json
    {
        "success": true
    }
    ```
*   **Error Responses:**
    *   `400 Bad Request`: `missing_token`
    *   `403 Forbidden`: `invalid_token`, `already_revoked`
    *   `404 Not Found`: `refresh_not_found`
    *   `500 Internal Server Error`: `revoke_failed`

### 4. `POST /cja/v1/revoke-all`

Revokes all refresh tokens for a specific user. This endpoint is restricted to users with `activate_plugins` or `manage_options` capabilities (typically administrators).

*   **Method:** `POST`
*   **Parameters (JSON Body):**
    *   `user_id` (integer, required): The ID of the user whose tokens should be revoked.
*   **Success Response (200 OK):**
    ```json
    {
        "success": true,
        "user_id": 1
    }
    ```
*   **Error Responses:**
    *   `400 Bad Request`: `missing_user`
    *   `403 Forbidden`: (If the current user does not have sufficient permissions)

## CORS Configuration

The plugin includes basic CORS headers for local development, allowing requests from `http://localhost:3000`. You should adjust `header('Access-Control-Allow-Origin: http://localhost:3000');` in `ctj.php` (around line 13) to match your frontend application's URL(s) in a production environment.

## Customization (Filters & Actions)

The plugin provides several filters for extending its functionality:

*   `cja_access_ttl`: Filter to modify the Time-To-Live (TTL) for access tokens.
*   `cja_refresh_ttl`: Filter to modify the Time-To-Live (TTL) for refresh tokens.
*   `cja_access_payload`: Filter to modify the payload of the access token before encoding.
*   `cja_refresh_payload`: Filter to modify the payload of the refresh token before encoding.

## Development

The plugin handles database table creation (`cja_refresh_tokens`) on activation and schedules a daily cron job (`cja_prune_cron`) to prune expired and revoked refresh tokens.
