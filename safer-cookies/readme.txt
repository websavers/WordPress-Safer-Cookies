=== Safer Cookies ===
Contributors: whiteshadow
Tags: cookie, session, admin, login, security
Requires at least: 2.5
Tested up to: 2.9
Stable tag: 1.2

Ties the WP session cookie to your IP address so that it can't be used to get access to you blog from another computer.

== Description ==

Normally when you login to your blog WordPress will create a session cookie that is used to authenticate you. If someone was to steal the cookie they would be able to use it to get full access to your blog without having to know your password. This plugin prevents that from happening - it makes the cookie specific to your IP address, so it won't be usable from a different computer.

Use this plugin if you have a static IP. If you have a dynamic IP address and it changes often you will get logged out frequently.

A bit more info can be obtained from the [Safer Cookies homepage](http://w-shadow.com/blog/2008/07/12/safer-cookies-plugin-for-wordpress/ "Safer Cookies homepage")

== Installation ==

To install the plugin follow these steps :

1. Download the safer-cookies.zip file to your local machine.
1. Unzip the file 
1. Upload "safer-cookies" folder to the "/wp-content/plugins/" directory
1. Activate the plugin through the 'Plugins' menu in WordPress
1. You will be prompted to log in again. Do so. This is necessary to set the new cookie.

