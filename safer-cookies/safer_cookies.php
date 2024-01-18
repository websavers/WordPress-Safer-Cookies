<?php
/*
Plugin Name: Safer Cookies
Plugin URI: http://w-shadow.com/blog/2008/07/12/safer-cookies-plugin-for-wordpress/
Description: Ties your login cookie to your IP address so that the cookie can't be used to access your blog from another computer.
Version: 1.2
Author: Janis Elsts
Author URI: http://w-shadow.com/blog/
*/

/*
Created by Janis Elsts (email : whiteshadow@w-shadow.com) 
It's GPL.
*/

/** ************************************************************
	 Override existing cookie generation/validation functions

 The custom functions are pretty much equivalent to the default
 ones, except using $_SERVER['REMOTE_ADDR'] as part of the hash. 	  
****************************************************************/
if ( !function_exists('wp_generate_auth_cookie') ) :

if (version_compare($wp_version, '2.6', '<')){
	//WP 2.5 - 2.5.1
	function wp_generate_auth_cookie($user_id, $expiration) {
		$user = get_userdata($user_id);
	
		//Added the IP to the hash : 
		$key = wp_hash($user->user_login . $expiration . $_SERVER['REMOTE_ADDR']);
		$hash = hash_hmac('md5', $user->user_login . $expiration, $key);
	
		$cookie = $user->user_login . '|' . $expiration . '|' . $hash;
	
		return apply_filters('auth_cookie', $cookie, $user_id, $expiration);
	}
} else {
	//WP 2.6+
	function wp_generate_auth_cookie($user_id, $expiration, $scheme = 'auth') {
		$user = get_userdata($user_id);

		$pass_frag = substr($user->user_pass, 8, 4);
	
		$key = wp_hash($user->user_login . $pass_frag . '|' . $expiration . '|' . $_SERVER['REMOTE_ADDR'], $scheme);
		$hash = hash_hmac('md5', $user->user_login . '|' . $expiration, $key);
	
		$cookie = $user->user_login . '|' . $expiration . '|' . $hash;
	
		return apply_filters('auth_cookie', $cookie, $user_id, $expiration, $scheme);
	}
}

endif;

if ( !function_exists('wp_validate_auth_cookie') ) :

if (version_compare($wp_version, '2.6', '<')){
	//WP 2.5 - 2.5.1
	function wp_validate_auth_cookie($cookie = '') {
		
		if ( empty($cookie) ) {
			if ( empty($_COOKIE[AUTH_COOKIE]) )
				return false;
			$cookie = $_COOKIE[AUTH_COOKIE];
		}
	
		list($username, $expiration, $hmac) = explode('|', $cookie);
	
		$expired = $expiration;
	
		// Allow a grace period for POST and AJAX requests
		if ( defined('DOING_AJAX') || 'POST' == $_SERVER['REQUEST_METHOD'] )
			$expired += 3600;
	
		if ( $expired < time() )
			return false;
	
		//Added the IP to the hash, here too : 
		$key = wp_hash($username . $expiration . $_SERVER['REMOTE_ADDR']);
		$hash = hash_hmac('md5', $username . $expiration, $key);
	
		if ( $hmac != $hash )
			return false;
	
		$user = get_userdatabylogin($username);
		if ( ! $user )
			return false;
	
		return $user->ID;
	}
} else {
	//WP 2.6+
	function wp_validate_auth_cookie($cookie = '', $scheme = 'auth') {
		if ( empty($cookie) ) {
			switch ($scheme){
				case 'auth':
					$cookie_name = AUTH_COOKIE;
					break;
				case 'secure_auth':
					$cookie_name = SECURE_AUTH_COOKIE;
					break;
				case "logged_in":
					$cookie_name = LOGGED_IN_COOKIE;
					break;
				default:
					if ( is_ssl() ) {
						$cookie_name = SECURE_AUTH_COOKIE;
						$scheme = 'secure_auth';
					} else {
						$cookie_name = AUTH_COOKIE;
						$scheme = 'auth';
					}
		    }
	
			if ( empty($_COOKIE[$cookie_name]) )
				return false;
			$cookie = $_COOKIE[$cookie_name];
		}
	
		$cookie_elements = explode('|', $cookie);
		if ( count($cookie_elements) != 3 )
			return false;
	
		list($username, $expiration, $hmac) = $cookie_elements;
	
		$expired = $expiration;
	
		// Allow a grace period for POST and AJAX requests
		if ( defined('DOING_AJAX') || 'POST' == $_SERVER['REQUEST_METHOD'] )
			$expired += 3600;
	
		// Quick check to see if an honest cookie has expired
		if ( $expired < time() ) {
			do_action('auth_cookie_expired', $cookie_elements);
			return false;
		}
	
		$user = get_userdatabylogin($username);
		if ( ! $user ) {
			do_action('auth_cookie_bad_username', $cookie_elements);
			return false;
		}
	
		$pass_frag = substr($user->user_pass, 8, 4);
	
		$key = wp_hash($username . $pass_frag . '|' . $expiration . '|' . $_SERVER['REMOTE_ADDR'], $scheme);
		$hash = hash_hmac('md5', $username . '|' . $expiration, $key);
	
		if ( $hmac != $hash ) {
			do_action('auth_cookie_bad_hash', $cookie_elements);
			return false;
		}
	
		if ( $expiration < time() ) // AJAX/POST grace period set above
			$GLOBALS['login_grace_period'] = 1;
	
		do_action('auth_cookie_valid', $cookie_elements, $user);
	
		return $user->ID;
	}
}
endif;
//*/

?>