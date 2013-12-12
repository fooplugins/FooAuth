<?php
/**
 * FooAuth
 *
 * @package   FooAuth
 * @author    Brad Vincent <bradvin@gmail.com>
 * @license   GPL-2.0+
 * @link      https://github.com/fooplugins/FooAuth
 * @copyright 2013 Brad Vincent
 */

/**
 * FooAuth class. This class should ideally be used to work with the
 * public-facing side of the WordPress site.
 *
 * @package FooAuth
 * @author  Brad Vincent <bradvin@gmail.com>
 */

require_once 'foopluginbase/class-foo-plugin-base.php';

class FooAuth extends Foo_Plugin_Base_v2_0 {

	/**
	 * Instance of this class.
	 *
	 * @since    1.0.0
	 *
	 * @var      object
	 */
	protected static $instance = null;

	/**
	 * Initialize the plugin by setting localization and loading public scripts
	 * and styles.
	 *
	 * @since     1.0.0
	 */
	private function __construct() {

		//init Foo Plugin Base
		$this->init( FOOAUTH_FILE, 'fooauth', FOOAUTH_VERSION, 'Foo Auth' );
		add_action( 'fooauth-admin_create_settings', array($this, 'create_settings'), 10, 2 );
		add_filter( 'fooauth-settings_page_summary', array($this, 'settings_summary') );
	}

	/**
	 * Return an instance of this class.
	 *
	 * @since     1.0.0
	 *
	 * @return    object    A single instance of this class.
	 */
	public static function get_instance() {

		// If the single instance hasn't been set, set it now.
		if ( null == self::$instance ) {
			self::$instance = new self;
		}

		return self::$instance;
	}

	/**
	 * @param $plugin   FooAuth
	 * @param $settings Foo_Plugin_Settings_v2_0
	 */
	function create_settings($plugin, $settings) {

		$settings->add_tab( 'general', 'General' );

		$settings->add_setting( array(
			'id'      => 'test_checkbox',
			'title'   => __( 'Example Checkbox', $plugin->get_slug() ),
			'desc'    => __( 'An example checkbox that does nothing', $plugin->get_slug() ),
			'default' => 'on',
			'type'    => 'checkbox',
			'tab'     => 'general'
		) );

		$settings->add_setting( array(
			'id'      => 'test_textbox',
			'title'   => __( 'Example Textbox', $plugin->get_slug() ),
			'desc'    => __( 'An example textbox that does nothing', $plugin->get_slug() ),
			'default' => 'on',
			'type'    => 'text',
			'tab'     => 'general'
		) );
	}

	function settings_summary() {
		return 'Welcome to Foo Auth settings!';
	}
}
