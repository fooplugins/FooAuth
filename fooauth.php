<?php
/**
 * FooAuth
 *
 * Better Authentication For WordPress. Including LDAP single sign on.
 *
 * @package   FooAuth
 * @author    Brad Vincent <bradvin@gmail.com>, Stephen Welgemoed <stwelgemoed@gmail.com>
 * @license   GPL-2.0+
 * @link      https://github.com/fooplugins/FooAuth
 * @copyright 2013 Brad Vincent
 *
 * @wordpress-plugin
 * Plugin Name:       FooAuth
 * Plugin URI:        https://github.com/fooplugins/FooAuth
 * Description:       Better Authentication For WordPress. Including LDAP single sign on.
 * Version:           0.0.1
 * Author:            Brad Vincent, Stephen Welgemoed
 * Author URI:        http://fooplugins.com
 * Text Domain:       fooauth
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Domain Path:       /languages
 * GitHub Plugin URI: https://github.com/fooplugins/FooAuth
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/*----------------------------------------------------------------------------*
 * Public-Facing Functionality
 *----------------------------------------------------------------------------*/

require_once( plugin_dir_path( __FILE__ ) . 'public/class-fooauth.php' );

/*
 * Register hooks that are fired when the plugin is activated or deactivated.
 * When the plugin is deleted, the uninstall.php file is loaded.
 */
register_activation_hook( __FILE__, array( 'FooAuth', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'FooAuth', 'deactivate' ) );

add_action( 'plugins_loaded', array( 'FooAuth', 'get_instance' ) );

/*----------------------------------------------------------------------------*
 * Dashboard and Administrative Functionality
 *----------------------------------------------------------------------------*/

/*
 * TODO:
 *
 * - replace `class-plugin-admin.php` with the name of the plugin's admin file
 * - replace Plugin_Name_Admin with the name of the class defined in
 *   `class-plugin-name-admin.php`
 *
 * If you want to include Ajax within the dashboard, change the following
 * conditional to:
 *
 * if ( is_admin() ) {
 *   ...
 * }
 *
 * The code below is intended to to give the lightest footprint possible.
 */
if ( is_admin() && ( ! defined( 'DOING_AJAX' ) || ! DOING_AJAX ) ) {

	require_once( plugin_dir_path( __FILE__ ) . 'admin/class-fooauth-admin.php' );
	add_action( 'plugins_loaded', array( 'FooAuth_Admin', 'get_instance' ) );

}
