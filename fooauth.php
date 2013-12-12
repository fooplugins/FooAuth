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

define( 'FOOAUTH_FILE', __FILE__);
define( 'FOOAUTH_VERSION', '0.0.1' );

require_once( 'includes/class-fooauth.php' );
add_action( 'plugins_loaded', array( 'FooAuth', 'get_instance' ) );

/*----------------------------------------------------------------------------*
 * Dashboard and Administrative Functionality
 *----------------------------------------------------------------------------*/
//if ( is_admin() && ( ! defined( 'DOING_AJAX' ) || ! DOING_AJAX ) ) {
//
//	require_once( 'admin/class-fooauth-admin.php' );
//	add_action( 'plugins_loaded', array( 'FooAuth_Admin', 'get_instance' ) );
//
//}