<?php
/**
 * Fired when the plugin is uninstalled.
 *
 * @package   FooAuth
 * @author    Brad Vincent <bradvin@gmail.com>
 * @license   GPL-2.0+
 * @link      https://github.com/fooplugins/FooAuth
 * @copyright 2013 Brad Vincent
 */

// If uninstall not called from WordPress, then exit
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// TODO: Define uninstall functionality here