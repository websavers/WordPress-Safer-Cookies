<?php
/*
Plugin Name: Safer Cookies
Plugin URI: http://w-shadow.com/blog/2008/07/12/safer-cookies-plugin-for-wordpress/
Description: Ties your login cookie to your IP address so that the cookie can't be used to access your blog from another computer.
Version: 2.0
Author: Janis Elsts / Websavers.ca
Author URI: http://w-shadow.com/blog/
*/

/*
Created by Janis Elsts (email : whiteshadow@w-shadow.com) 
It's GPL.
*/

/** ************************************************************
 Override existing cookie generation/validation functions: add
 $_SERVER['REMOTE_ADDR'] as part of the hash. 
 Original hash functions still shown, commented out.
****************************************************************/

// https://developer.wordpress.org/reference/functions/wp_generate_auth_cookie/
if ( !function_exists('wp_generate_auth_cookie') ){

	function wp_generate_auth_cookie($user_id, $expiration, $scheme = 'auth') {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return '';
		}
	
		if ( ! $token ) {
			$manager = WP_Session_Tokens::get_instance( $user_id );
			$token   = $manager->create( $expiration );
		}
	
		$pass_frag = substr( $user->user_pass, 8, 4 );
	
		//$key = wp_hash( $user->user_login . '|' . $pass_frag . '|' . $expiration . '|' . $token, $scheme );
		$key = wp_hash( $user->user_login . '|' . $pass_frag . '|' . $expiration . '|' .  $_SERVER['REMOTE_ADDR'] . '|' . $token, $scheme );
	
		// If ext/hash is not present, compat.php's hash_hmac() does not support sha256.
		$algo = function_exists( 'hash' ) ? 'sha256' : 'sha1';
		$hash = hash_hmac( $algo, $user->user_login . '|' . $expiration . '|' . $token, $key );
	
		$cookie = $user->user_login . '|' . $expiration . '|' . $token . '|' . $hash;
	
		/**
		 * Filters the authentication cookie.
		 *
		 * @since 2.5.0
		 * @since 4.0.0 The `$token` parameter was added.
		 *
		 * @param string $cookie     Authentication cookie.
		 * @param int    $user_id    User ID.
		 * @param int    $expiration The time the cookie expires as a UNIX timestamp.
		 * @param string $scheme     Cookie scheme used. Accepts 'auth', 'secure_auth', or 'logged_in'.
		 * @param string $token      User's session token used.
		 */
		return apply_filters( 'auth_cookie', $cookie, $user_id, $expiration, $scheme, $token );
	}

}

// https://developer.wordpress.org/reference/functions/wp_validate_auth_cookie/
if ( !function_exists('wp_validate_auth_cookie') ){

	function wp_validate_auth_cookie( $cookie = '', $scheme = '' ) {
		$cookie_elements = wp_parse_auth_cookie( $cookie, $scheme );
		if ( ! $cookie_elements ) {
			/**
			 * Fires if an authentication cookie is malformed.
			 *
			 * @since 2.7.0
			 *
			 * @param string $cookie Malformed auth cookie.
			 * @param string $scheme Authentication scheme. Values include 'auth', 'secure_auth',
			 *                       or 'logged_in'.
			 */
			do_action( 'auth_cookie_malformed', $cookie, $scheme );
			return false;
		}
	
		$scheme     = $cookie_elements['scheme'];
		$username   = $cookie_elements['username'];
		$hmac       = $cookie_elements['hmac'];
		$token      = $cookie_elements['token'];
		$expired    = $cookie_elements['expiration'];
		$expiration = $cookie_elements['expiration'];
	
		// Allow a grace period for POST and Ajax requests.
		if ( wp_doing_ajax() || 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			$expired += HOUR_IN_SECONDS;
		}
	
		// Quick check to see if an honest cookie has expired.
		if ( $expired < time() ) {
			/**
			 * Fires once an authentication cookie has expired.
			 *
			 * @since 2.7.0
			 *
			 * @param string[] $cookie_elements {
			 *     Authentication cookie components. None of the components should be assumed
			 *     to be valid as they come directly from a client-provided cookie value.
			 *
			 *     @type string $username   User's username.
			 *     @type string $expiration The time the cookie expires as a UNIX timestamp.
			 *     @type string $token      User's session token used.
			 *     @type string $hmac       The security hash for the cookie.
			 *     @type string $scheme     The cookie scheme to use.
			 * }
			 */
			do_action( 'auth_cookie_expired', $cookie_elements );
			return false;
		}
	
		$user = get_user_by( 'login', $username );
		if ( ! $user ) {
			/**
			 * Fires if a bad username is entered in the user authentication process.
			 *
			 * @since 2.7.0
			 *
			 * @param string[] $cookie_elements {
			 *     Authentication cookie components. None of the components should be assumed
			 *     to be valid as they come directly from a client-provided cookie value.
			 *
			 *     @type string $username   User's username.
			 *     @type string $expiration The time the cookie expires as a UNIX timestamp.
			 *     @type string $token      User's session token used.
			 *     @type string $hmac       The security hash for the cookie.
			 *     @type string $scheme     The cookie scheme to use.
			 * }
			 */
			do_action( 'auth_cookie_bad_username', $cookie_elements );
			return false;
		}
	
		$pass_frag = substr( $user->user_pass, 8, 4 );
	
		//$key = wp_hash( $username . '|' . $pass_frag . '|' . $expiration . '|' . $token, $scheme );
		$key = wp_hash( $username . '|' . $pass_frag . '|' . $expiration . '|' . $_SERVER['REMOTE_ADDR'] . '|' . $token, $scheme );
	
		// If ext/hash is not present, compat.php's hash_hmac() does not support sha256.
		$algo = function_exists( 'hash' ) ? 'sha256' : 'sha1';
		$hash = hash_hmac( $algo, $username . '|' . $expiration . '|' . $token, $key );
	
		if ( ! hash_equals( $hash, $hmac ) ) {
			/**
			 * Fires if a bad authentication cookie hash is encountered.
			 *
			 * @since 2.7.0
			 *
			 * @param string[] $cookie_elements {
			 *     Authentication cookie components. None of the components should be assumed
			 *     to be valid as they come directly from a client-provided cookie value.
			 *
			 *     @type string $username   User's username.
			 *     @type string $expiration The time the cookie expires as a UNIX timestamp.
			 *     @type string $token      User's session token used.
			 *     @type string $hmac       The security hash for the cookie.
			 *     @type string $scheme     The cookie scheme to use.
			 * }
			 */
			do_action( 'auth_cookie_bad_hash', $cookie_elements );
			return false;
		}
	
		$manager = WP_Session_Tokens::get_instance( $user->ID );
		if ( ! $manager->verify( $token ) ) {
			/**
			 * Fires if a bad session token is encountered.
			 *
			 * @since 4.0.0
			 *
			 * @param string[] $cookie_elements {
			 *     Authentication cookie components. None of the components should be assumed
			 *     to be valid as they come directly from a client-provided cookie value.
			 *
			 *     @type string $username   User's username.
			 *     @type string $expiration The time the cookie expires as a UNIX timestamp.
			 *     @type string $token      User's session token used.
			 *     @type string $hmac       The security hash for the cookie.
			 *     @type string $scheme     The cookie scheme to use.
			 * }
			 */
			do_action( 'auth_cookie_bad_session_token', $cookie_elements );
			return false;
		}
	
		// Ajax/POST grace period set above.
		if ( $expiration < time() ) {
			$GLOBALS['login_grace_period'] = 1;
		}
	
		/**
		 * Fires once an authentication cookie has been validated.
		 *
		 * @since 2.7.0
		 *
		 * @param string[] $cookie_elements {
		 *     Authentication cookie components.
		 *
		 *     @type string $username   User's username.
		 *     @type string $expiration The time the cookie expires as a UNIX timestamp.
		 *     @type string $token      User's session token used.
		 *     @type string $hmac       The security hash for the cookie.
		 *     @type string $scheme     The cookie scheme to use.
		 * }
		 * @param WP_User  $user            User object.
		 */
		do_action( 'auth_cookie_valid', $cookie_elements, $user );
	
		return $user->ID;
	}

}

?>