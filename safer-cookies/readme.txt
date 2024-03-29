=== Safer Cookies ===
Contributors: whiteshadow, websavers
Tags: cookie, session, admin, login, security
Requires at least: 2.7
Tested up to: 6.4.2
Stable tag: 2.0

Ties the WP session cookie to your IP address so that it can't be used to get access to you blog from another computer.

== Description ==

Normally when you login to your blog WordPress will create a session cookie that is used to authenticate you. If someone was to steal the cookie they would be able to use it to get full access to your blog without having to know your password. This plugin prevents that from happening - it makes the cookie specific to your IP address, so it won't be usable from a different computer.

Use this plugin if you have a static IP. If you have a dynamic IP address and it changes often you will get logged out frequently.

WARNING: If you have a frequently changing dynamic IP or use a VPN or Proxy service, please don't install this. You'll be logged out of WP constantly.

A bit more info can be obtained from the [Safer Cookies homepage](http://w-shadow.com/blog/2008/07/12/safer-cookies-plugin-for-wordpress/ "Safer Cookies homepage")

== Installation ==

Tip: you may not be able to upload this via the WordPress plugin installer because web application firewalls
might intercept it as malicious. That means you should upload via your control panel file manager or SFTP/FTPS.

To install the plugin follow these steps :

1. Download the safer-cookies.zip file to your local machine.
1. Unzip the file 
1. Upload "safer-cookies" folder to the "/wp-content/plugins/" directory
1. Activate the plugin through the 'Plugins' menu in WordPress
1. You will be prompted to log in again. Do so. This is necessary to set the new cookie.

