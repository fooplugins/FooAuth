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
require_once 'settings.php';
require_once 'providers/ldap/fooauth_singlesign_on.php';

class FooAuth extends Foo_Plugin_Base_v2_0
{

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
    private function __construct()
    {

        //init Foo Plugin Base
        $this->init(FOOAUTH_FILE, 'fooauth', FOOAUTH_VERSION, 'Foo Auth');
        add_filter('fooauth-admin_settings', 'fooauth_create_settings');
        add_filter('fooauth-settings_page_summary', array($this, 'settings_summary'));

        new FooAuth_Single_Signon();
    }

    /**
     * Return an instance of this class.
     *
     * @since     1.0.0
     *
     * @return    FooAuth    A single instance of this class.
     */
    public static function get_instance()
    {

        // If the single instance hasn't been set, set it now.
        if (null == self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    function settings_summary()
    {
        return 'Welcome to Foo Auth settings!';
    }
}
