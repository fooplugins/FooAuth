<?php

/*
Plugin Name: Active Directory Integration 
Version: 1.1.4
Plugin URI: http://www.steindorff.de/wp-ad-integration
Description: Allows WordPress to authenticate, authorize, create and update users through Active Directory
Author: Christoph Steindorff
Author URI: http://www.steindorff.de/

The work is derived from version 1.0.5 of the plugin Active Directory Authentication:
OriginalPlugin URI: http://soc.qc.edu/jonathan/wordpress-ad-auth
OriginalDescription: Allows WordPress to authenticate users through Active Directory
OriginalAuthor: Jonathan Marc Bearak
OriginalAuthor URI: http://soc.qc.edu/jonathan
*/

/*
	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.
	
	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
*/


if (!class_exists('ADIntegrationPlugin')) {
	
// LOG LEVEL	
define('ADI_LOG_DEBUG', 6);
define('ADI_LOG_INFO',  5);
define('ADI_LOG_NOTICE',4);
define('ADI_LOG_WARN',  3);
define('ADI_LOG_ERROR', 2);
define('ADI_LOG_FATAL', 1);
define('ADI_LOG_NONE',  0);

define('ADI_DUPLICATE_EMAIL_ADDRESS_PREVENT', 'prevent');
define('ADI_DUPLICATE_EMAIL_ADDRESS_ALLOW', 'allow');
define('ADI_DUPLICATE_EMAIL_ADDRESS_CREATE', 'create');


class ADIntegrationPlugin {
	
	// version of needed DB table structure
	const DB_VERSION = '0.9';
	const ADI_VERSION = '1.1.4';
	
	// name of our own table
	const TABLE_NAME = 'adintegration';
	
	
	// is the user authenticated?
	public $_authenticated = false;
	
	protected $_minium_WPMU_version = '3.0';
	protected $_minium_WP_version = '3.0';
	
	// log level
	protected $_loglevel = ADI_LOG_NONE;
	
	protected $_logfile = '';
	
	// adLDAP-object
	protected $_adldap;
	
	// Should a new user be created automatically if not already in the WordPress database?
	protected $_auto_create_user = false; 
	
	// Should the users be updated in the WordPress database everytime they logon? (Works only if automatic user creation is set.
	protected $_auto_update_user = false;

	// Account Suffix (will be appended to all usernames created in WordPress, as well as used in the Active Directory authentication process
	protected $_account_suffix = ''; 
	
	// Should the account suffix be appended to the usernames created in WordPress?
	protected $_append_suffix_to_new_users = false;

	// Domain Controllers (separate with semicolons)
	protected $_domain_controllers = '';
	
	// LDAP/AD BASE DN
	protected $_base_dn = '';
	
	// Role Equivalent Groups (wp-role1=ad-group1;wp-role2=ad-group2;...)
	protected $_role_equivalent_groups = '';
	
	// Default Email Domain (eg. 'domain.tld')
	protected $_default_email_domain = '';
	
	// Port on which AD listens (default 389)
	protected $_port = 389;
	
	// Secure the connection between the Drupal and the LDAP servers using TLS.
	protected $_use_tls = false; 
	
	// network timeout (LDAP_OPT_NETWORK_TIMEOUT) in seconds
	protected $_network_timeout = 5;
	
	// Check Login authorization by group membership
	protected $_authorize_by_group = false;
	
	// Group name for authorization.
	protected $_authorization_group = '';
	
	// Maximum number of failed login attempts before the account is blocked
	protected $_max_login_attempts = 3;
	
	// Number of seconds an account is blocked after the maximum number of failed login attempts is reached.
	protected $_block_time = 30;
	
	// Send email to user if his account is blocked.
	protected $_user_notification = false;
	
	// Send email to admin if a user account is blocked.
	protected $_admin_notification = false;
	
	// Administrator's e-mail address(es) where notifications should be sent to.		
	protected $_admin_email = '';
	
	// Set user's display_name to an AD attribute or to username if left blank
	// Possible values: description, displayname, mail, sn, cn, givenname, samaccountname, givenname sn
	protected $_display_name = '';
	
	// Enable/Disable password changes 
	protected $_enable_password_change = false;
	
	// How to deal with duplicate email addresses
	protected $_duplicate_email_prevention = ADI_DUPLICATE_EMAIL_ADDRESS_PREVENT;
	
	// Update users description if $_auto_update_user is true
	protected $_auto_update_description = false;
	
	// default attributes to be read from AD (Windows 2000/20003)
	protected $_default_user_attributes = array (
	    'cn', // Common Name
	    'givenname', // First name
	    'sn', // Last name
		'displayname',  // Display name
		'description', // Description
		'mail', // E-mail
		'samaccountname', // User logon name
		'userprincipalname', // userPrincipalName
		'useraccountcontrol' // userAccountControl
	);
	
	
	// List of additional user attributes that can be defined by the admin
	// The attributes are seperated by a new line and have the format:
	//   <Attribute name>:<type>
	// where type can be one of the following: string, integer, bool, image, time, timestamp
	//   thumbnailphoto:image
	//   whencreated:time
	protected $_additional_user_attributes = '';
	
	// Merged array of _user_attributes and _additional_user_attributes
	protected $_all_user_attributes = array();
	
	// Add all user attributes from AD to WP table usermeta
	protected $_write_usermeta = true;
	
	// Prefix for user meta Data from AD 
	protected $_usermeta_prefix = 'adi_';
	
	// Overwrite local values even if values in Active Directory are empty. 
	protected $_usermeta_empty_overwrite = false;
	
	// Enable Sync Back
	protected $_syncback = false;
	
	// Use global Sync Back User
	protected $_syncback_use_global_user = false;
	
	// Account name of global sync back user
	protected $_syncback_global_user = '';
	
	// Password of global sync back user
	protected $_syncback_global_pwd = '';
	
	// Show AD attributes in user profile
	protected $_show_attributes = false;

	// List of AD attributes in the order they should appear on users profile page
	// Attributes are separated by semicolon or linefeed / newline and have to format:
	//   <Attribute name>:<desription>
	// <description> is used on the profile page
	protected $_attributes_to_show = '';

	// Use the real password when a user is created
	protected $_no_random_password = false;
	
	// Update password on every successfull login
	protected $_auto_update_password = false;
	
	// Enable lost password recovery
	protected $_enable_lost_password_recovery = false;
	
	
	// enable Bulk Import
	protected $_bulkimport_enabled = false;
	
	// AUTHCODE for Bulk Import. Bulk Import will only work, if this AUTHCODE is send as as get-parameter to bulkimport.php
	protected $_bulkimport_authcode = '';
	
	// generate a new AUTHCODE for Bulk Import
	protected $_bulkimport_new_authcode = false;
	
	// Import members of these security groups (separated by semicolons)
	protected $_bulkimport_security_groups = '';

	// name of Bulk Import User in Active Directory
	protected $_bulkimport_user = '';
	
	// password for Bulk Import User (will be stored encrypted)
	protected $_bulkimport_pwd = '';
	
	// use user disabling
	protected $_disable_users = false;
	
	// use local (WordPress) password as fallback if authentication against AD fails
	protected $_fallback_to_local_password = false;
	
	// show disabled and ADI user status on user list
	protected $_show_user_status = true;
	
	// Prevent email change by ADI Users (not for admins)
	protected $_prevent_email_change = false;
	
	// protected $_sso_enabled = false; // TODO: for auto login/SSO feature, has to be added to _load_options(), admin.php etc. 
		

	// All options and its types
	// Has to be static for static call of method uninstall()
	protected static $_all_options = array(
	
			array('name' => 'AD_Integration_version', 'type' => 'string'),
		
			// Server
			array('name' => 'AD_Integration_domain_controllers', 'type' => 'string'),
			array('name' => 'AD_Integration_port', 'type' => 'int'),
			array('name' => 'AD_Integration_use_tls', 'type' => 'bool'),
			array('name' => 'AD_Integration_network_timeout', 'type' => 'integer'),
			array('name' => 'AD_Integration_base_dn', 'type' => 'string'),
			
			// User
			array('name' => 'AD_Integration_account_suffix', 'type' => 'string'),
			array('name' => 'AD_Integration_append_suffix_to_new_users', 'type' => 'bool'),
			array('name' => 'AD_Integration_auto_create_user', 'type' => 'bool'),
			array('name' => 'AD_Integration_auto_update_user', 'type' => 'bool'),
			array('name' => 'AD_Integration_auto_update_description', 'type' => 'bool'),
			array('name' => 'AD_Integration_default_email_domain', 'type' => 'string'),
			array('name' => 'AD_Integration_duplicate_email_prevention', 'type' => 'string'),
			array('name' => 'AD_Integration_prevent_email_change', 'type' => 'bool'),
			array('name' => 'AD_Integration_display_name', 'type' => 'string'),
			array('name' => 'AD_Integration_show_user_status', 'type' => 'bool'),
			array('name' => 'AD_Integration_enable_password_change', 'type' => 'bool'),
			array('name' => 'AD_Integration_no_random_password', 'type' => 'bool'),
			array('name' => 'AD_Integration_auto_update_password', 'type' => 'bool'),
			
			// Authorization
			array('name' => 'AD_Integration_authorize_by_group', 'type' => 'bool'),
			array('name' => 'AD_Integration_authorization_group', 'type' => 'string'),
			array('name' => 'AD_Integration_role_equivalent_groups', 'type' => 'string'),

			// Security
			array('name' => 'AD_Integration_fallback_to_local_password', 'type' => 'bool'),
			array('name' => 'AD_Integration_enable_lost_password_recovery', 'type' => 'bool'),
			array('name' => 'AD_Integration_max_login_attempts', 'type' => 'int'),
			array('name' => 'AD_Integration_block_time', 'type' => 'int'),
			array('name' => 'AD_Integration_user_notification', 'type' => 'bool'),
			array('name' => 'AD_Integration_admin_notification', 'type' => 'bool'),
			array('name' => 'AD_Integration_admin_email', 'type' => 'string'),

			// User Meta
			array('name' => 'AD_Integration_additional_user_attributes', 'type' => 'string'),
			array('name' => 'AD_Integration_usermeta_empty_overwrite', 'type' => 'bool'),
			array('name' => 'AD_Integration_show_attributes', 'type' => 'bool'),
			array('name' => 'AD_Integration_attributes_to_show', 'type' => 'bool'),
			array('name' => 'AD_Integration_syncback', 'type' => 'bool'),
			array('name' => 'AD_Integration_syncback_use_global_user', 'type' => 'bool'),
			array('name' => 'AD_Integration_syncback_global_user', 'type' => 'string'),
			array('name' => 'AD_Integration_syncback_global_pwd', 'type' => 'string'),
			
			// Bulk Import
			array('name' => 'AD_Integration_bulkimport_enabled', 'type' => 'bool'),
			array('name' => 'AD_Integration_bulkimport_authcode', 'type' => 'string'),
			array('name' => 'AD_Integration_bulkimport_new_authcode', 'type' => 'bool'),
			array('name' => 'AD_Integration_bulkimport_security_groups', 'type' => 'string'),
			array('name' => 'AD_Integration_bulkimport_user', 'type' => 'string'),
			array('name' => 'AD_Integration_bulkimport_pwd', 'type' => 'string'),
			array('name' => 'AD_Integration_disable_users', 'type' => 'bool')
		);
		

	
	public $errors = false;

	/**
	 * Constructor
	 */
	public function __construct() {
		global $wp_version, $wpmu_version, $wpdb, $wpmuBaseTablePrefix;

		if (!defined('IS_WPMU')) {
			define('IS_WPMU', ($wpmu_version != ''));
		}
		
		// define folder constant
		if (!defined('ADINTEGRATION_FOLDER')) {  
			define('ADINTEGRATION_FOLDER', basename(dirname(__FILE__)));
		}
	
		$this->setLogFile(dirname(__FILE__).'/adi.log'); 
		
		$this->errors = new WP_Error();
		

		// Load Options
		$this->_load_options();
		
		// Generate authcode if necessary
		if (strlen($this->_bulkimport_authcode) < 20) {
			$this->_generate_authcode();
		}
		
		if (isset($_GET['activate']) and $_GET['activate'] == 'true') {
			add_action('init', array(&$this, 'initialize_options'));
		}
		
		add_action('admin_init', array(&$this, 'register_adi_settings'));
		
		add_action('admin_menu', array(&$this, 'add_options_page'));
		add_filter('contextual_help', array(&$this, 'contextual_help'), 10, 2);
		
		// DO WE HAVE LDAP SUPPORT?
		if (function_exists('ldap_connect')) {
			
			add_filter('authenticate', array(&$this, 'authenticate'), 10, 3);
			
			if (!$this->_enable_lost_password_recovery) { 
				add_action('lost_password', array(&$this, 'disable_function'));
				add_action('retrieve_password', array(&$this, 'disable_function'));
				add_action('password_reset', array(&$this, 'disable_function'));
			}
			
		    add_action('admin_print_styles', array(&$this, 'load_styles'));
		    add_action('admin_print_scripts', array(&$this, 'load_scripts'));
		    
		    // Add new column to the user list
		    if ($this->_show_user_status) {
				add_filter( 'manage_users_columns', array( &$this, 'manage_users_columns' ) );
				add_filter( 'manage_users_custom_column', array( &$this, 'manage_users_custom_column' ), 10, 3 );
			}

			// actions for user disabling
			add_action('personal_options_update', array(&$this, 'profile_update_disable_user'));
			add_action('edit_user_profile_update', array(&$this, 'profile_update_disable_user'));
			add_action('edit_user_profile', array(&$this, 'show_user_profile_disable_user'));
			add_action('show_user_profile', array(&$this, 'show_user_profile_disable_user'));			
			
		    
		    // Sync Back?
		    if ($this->_syncback === true) {
				add_action('personal_options_update', array(&$this, 'profile_update'));
				add_action('edit_user_profile_update', array(&$this, 'profile_update'));
		    }
			

			// TODO: auto_login feature must be tested
			/*
			if ($this->_auto_login) {
				add_action('init', array(&$this, 'auto_login'));
			}
			*/
		    
			
			add_filter('check_password', array(&$this, 'override_password_check'), 10, 4);
			
			
			// Is local password change disallowed?
			if (!$this->_enable_password_change) {
				
				// disable password fields
				add_filter('show_password_fields', array(&$this, 'disable_password_fields'));
				
				// generate a random password for manually added users 
				add_action('check_passwords', array(&$this, 'generate_password'), 10, 3);
			}
			 			
			if (!class_exists('adLDAP')) {
				require 'ad_ldap/adLDAP.php';
			}
		} else {
			$this->_log(ADI_LOG_WARN,'openLDAP not installed or activated in PHP.');
		}
		
		// Adding AD attributes to profile page
		if ($this->_show_attributes) {
			add_action( 'edit_user_profile', array(&$this, 'show_AD_attributes'));
			add_action( 'show_user_profile', array(&$this, 'show_AD_attributes'));
		}
		
		$this->_all_user_attributes = $this->_get_user_attributes();
		
		// Prevent email change
		if ($this->_prevent_email_change) {
			add_action( 'edit_user_profile', array(&$this, 'user_profile_prevent_email_change')); // cosmetic
			add_action( 'show_user_profile', array(&$this, 'user_profile_prevent_email_change')); // cosmetic
			add_action( 'user_profile_update_errors', array(&$this, 'prevent_email_change'), 10, 3 ); // true prevention
		}
	}
	
	
	public function load_styles() {
		wp_register_style('adintegration', plugins_url('css/adintegration.css', __FILE__ )  ,false, '1.7.1', 'screen');
		wp_enqueue_style('adintegration');
	}
	
	
	public function load_scripts() {
		wp_enqueue_script('jquery-ui-tabs');   // this is a wp default script
		wp_enqueue_script('jquery-ui-dialog'); // this is a wp default script
	}
	

	/*************************************************************
	 * Plugin hooks
	 *************************************************************/
	
	/**
	 * Add options for this plugin to the database.
	 */
	public function initialize_options() {
		
		if (IS_WPMU) {
			if (is_super_admin()) {
				add_site_option('AD_Integration_account_suffix', ''); 
				add_site_option('AD_Integration_auto_create_user', false);
				add_site_option('AD_Integration_auto_update_user', false);
				add_site_option('AD_Integration_append_suffix_to_new_users', false);
				add_site_option('AD_Integration_domain_controllers', '');
				add_site_option('AD_Integration_base_dn', '');
				add_site_option('AD_Integration_role_equivalent_groups', '');
				add_site_option('AD_Integration_default_email_domain', '');
				add_site_option('AD_Integration_port', '389');
				add_site_option('AD_Integration_use_tls', false);
				add_site_option('AD_Integration_network_timeout', 5);
				
				// User
				add_site_option('AD_Integration_authorize_by_group', false);
				add_site_option('AD_Integration_authorization_group', '');
				add_site_option('AD_Integration_display_name', '');
				add_site_option('AD_Integration_enable_password_change', false);
				add_site_option('AD_Integration_duplicate_email_prevention', ADI_DUPLICATE_EMAIL_ADDRESS_PREVENT);
				add_site_option('AD_Integration_prevent_email_change', false);
				add_site_option('AD_Integration_auto_update_description', false);
				add_site_option('AD_Integration_show_user_status', false);
				
				add_site_option('AD_Integration_show_attributes', false);
				add_site_option('AD_Integration_attributes_to_show', '');
				add_site_option('AD_Integration_additionl_user_attributes', '');
				add_site_option('AD_Integration_usermeta_empty_overwrite', false);
				add_site_option('AD_Integration_no_random_password', false);
				add_site_option('AD_Integration_auto_update_password', false);

				add_site_option('AD_Integration_max_login_attempts', '3');
				add_site_option('AD_Integration_block_time', '30');
				add_site_option('AD_Integration_user_notification', false);
				add_site_option('AD_Integration_admin_notification', false);
				add_site_option('AD_Integration_admin_email', '');
				add_site_option('AD_Integration_disable_users', false);
				add_site_option('AD_Integration_fallback_to_local_password', false);
				add_site_option('AD_Integration_enable_lost_password_recovery', false);
				
				add_site_option('AD_Integration_syncback', false);
				add_site_option('AD_Integration_syncback_use_global_user', false);
				add_site_option('AD_Integration_syncback_global_user', '');
				add_site_option('AD_Integration_syncback_global_pwd', '');

				add_site_option('AD_Integration_bulkimport_enabled', false);
				add_site_option('AD_Integration_bulkimport_authcode', '');
				add_site_option('AD_Integration_bulkimport_new_authcode', false);
				add_site_option('AD_Integration_bulkimport_security_groups', '');
				add_site_option('AD_Integration_bulkimport_user', '');
				add_site_option('AD_Integration_bulkimport_pwd', '');
			}
		} else {
			if (current_user_can('manage_options')) {
				add_option('AD_Integration_account_suffix', '');
				add_option('AD_Integration_auto_create_user', false);
				add_option('AD_Integration_auto_update_user', false);
				add_option('AD_Integration_append_suffix_to_new_users', false);
				add_option('AD_Integration_domain_controllers', '');
				add_option('AD_Integration_base_dn', '');
				add_option('AD_Integration_role_equivalent_groups', '');
				add_option('AD_Integration_default_email_domain', '');
				add_option('AD_Integration_port', '389');
				add_option('AD_Integration_use_tls', false);
				add_option('AD_Integration_network_timeout', 5);
				
				add_option('AD_Integration_authorize_by_group', false);
				add_option('AD_Integration_authorization_group', '');
				add_option('AD_Integration_display_name', '');
				add_option('AD_Integration_enable_password_change', false);
				add_option('AD_Integration_duplicate_email_prevention', ADI_DUPLICATE_EMAIL_ADDRESS_PREVENT);
				add_option('AD_Integration_prevent_email_change', false);
				add_option('AD_Integration_auto_update_description', false);
				add_option('AD_Integration_show_user_status', false);
				
				add_option('AD_Integration_show_attributes', false);
				add_option('AD_Integration_attributes_to_show', '');
				add_option('AD_Integration_additional_user_attributes', '');
				add_option('AD_Integration_usermeta_empty_overwrite', false);
				
				add_option('AD_Integration_no_random_password', false);
				add_option('AD_Integration_auto_update_password', false);
				
				
				add_option('AD_Integration_max_login_attempts', '3');
				add_option('AD_Integration_block_time', '30');
				add_option('AD_Integration_user_notification', false);
				add_option('AD_Integration_admin_notification', false);
				add_option('AD_Integration_admin_email', '');
				add_option('AD_Integration_disable_users', false);
				add_option('AD_Integration_fallback_to_local_password', false);
				add_option('AD_Integration_enable_lost_password_recovery', false);

				
				add_option('AD_Integration_syncback', false);
				add_option('AD_Integration_syncback_use_global_user', false);
				add_option('AD_Integration_syncback_global_user', '');
				add_option('AD_Integration_syncback_global_pwd', '');				
				
				add_option('AD_Integration_bulkimport_enabled', false);
				add_option('AD_Integration_bulkimport_authcode', '');
				add_option('AD_Integration_bulkimport_new_authcode', false);
				add_option('AD_Integration_bulkimport_security_groups', '');
				add_option('AD_Integration_bulkimport_user', '');
				add_option('AD_Integration_bulkimport_pwd', '');
			}
		}
		
	}
	
	
	public function register_adi_settings()
	{

		// Server
		register_setting('ADI-server-settings',	'AD_Integration_domain_controllers');
		register_setting('ADI-server-settings', 'AD_Integration_port', array(&$this, 'sanitize_port'));
		register_setting('ADI-server-settings', 'AD_Integration_use_tls', array(&$this, 'sanitize_bool'));
		register_setting('ADI-server-settings', 'AD_Integration_base_dn');
		register_setting('ADI-server-settings', 'AD_Integration_network_timeout', array(&$this, 'sanitize_network_timeout'));
		
		// User
		register_setting('ADI-user-settings', 'AD_Integration_auto_create_user', array(&$this, 'sanitize_bool'));
		register_setting('ADI-user-settings', 'AD_Integration_auto_update_user', array(&$this, 'sanitize_bool'));
		register_setting('ADI-user-settings', 'AD_Integration_auto_update_description', array(&$this, 'sanitize_bool'));
		register_setting('ADI-user-settings', 'AD_Integration_default_email_domain', array(&$this, 'sanitize_default_email_domain'));
		register_setting('ADI-user-settings', 'AD_Integration_account_suffix', array(&$this, 'sanitize_account_suffix'));
		register_setting('ADI-user-settings', 'AD_Integration_append_suffix_to_new_users', array(&$this, 'sanitize_bool'));
		register_setting('ADI-user-settings', 'AD_Integration_display_name');
		register_setting('ADI-user-settings', 'AD_Integration_enable_password_change', array(&$this, 'sanitize_bool'));
		register_setting('ADI-user-settings', 'AD_Integration_duplicate_email_prevention');
		register_setting('ADI-user-settings', 'AD_Integration_prevent_email_change', array(&$this, 'sanitize_bool'));
		register_setting('ADI-user-settings', 'AD_Integration_no_random_password', array(&$this, 'sanitize_bool'));
		register_setting('ADI-user-settings', 'AD_Integration_auto_update_password', array(&$this, 'sanitize_bool'));
		register_setting('ADI-user-settings', 'AD_Integration_show_user_status', array(&$this, 'sanitize_bool'));
		
		// Authorization
		register_setting('ADI-auth-settings', 'AD_Integration_authorize_by_group', array(&$this, 'sanitize_bool'));
		register_setting('ADI-auth-settings', 'AD_Integration_authorization_group');
		register_setting('ADI-auth-settings', 'AD_Integration_role_equivalent_groups', array(&$this, 'sanitize_role_equivalent_groups'));
		
		// Security
		register_setting('ADI-security-settings', 'AD_Integration_fallback_to_local_password', array(&$this, 'sanitize_bool'));
		register_setting('ADI-security-settings', 'AD_Integration_enable_lost_password_recovery', array(&$this, 'sanitize_bool'));
		register_setting('ADI-security-settings', 'AD_Integration_max_login_attempts', array(&$this, 'sanitize_max_login_attempts'));
		register_setting('ADI-security-settings', 'AD_Integration_block_time', array(&$this, 'sanitize_block_time'));
		register_setting('ADI-security-settings', 'AD_Integration_user_notification', array(&$this, 'sanitize_bool'));
		register_setting('ADI-security-settings', 'AD_Integration_admin_notification', array(&$this, 'sanitize_bool'));
		register_setting('ADI-security-settings', 'AD_Integration_admin_email', array(&$this, 'sanitize_admin_email'));
						
		
		// User Meta
		register_setting('ADI-usermeta-settings', 'AD_Integration_show_attributes', array(&$this, 'sanitize_bool'));
		register_setting('ADI-usermeta-settings', 'AD_Integration_attributes_to_show', array(&$this, 'sanitize_attributes_to_show'));
		register_setting('ADI-usermeta-settings', 'AD_Integration_additional_user_attributes', array(&$this, 'sanitize_additional_user_attributes'));
		register_setting('ADI-usermeta-settings', 'AD_Integration_usermeta_empty_overwrite', array(&$this, 'sanitize_bool'));
		register_setting('ADI-usermeta-settings', 'AD_Integration_syncback', array(&$this, 'sanitize_bool'));
		register_setting('ADI-usermeta-settings', 'AD_Integration_syncback_use_global_user', array(&$this, 'sanitize_bool'));
		register_setting('ADI-usermeta-settings', 'AD_Integration_syncback_global_user', array(&$this, 'sanitize_syncback_global_user'));
		register_setting('ADI-usermeta-settings', 'AD_Integration_syncback_global_pwd', array(&$this, 'sanitize_syncback_global_user_pwd'));

		// Bulk Import
		register_setting('ADI-bulkimport-settings', 'AD_Integration_bulkimport_enabled', array(&$this, 'sanitize_bool'));
		register_setting('ADI-bulkimport-settings', 'AD_Integration_bulkimport_new_authcode', array(&$this, 'sanitize_new_authcode'));
		register_setting('ADI-bulkimport-settings', 'AD_Integration_bulkimport_security_groups');
		register_setting('ADI-bulkimport-settings', 'AD_Integration_bulkimport_user', array(&$this, 'sanitize_bulkimport_user'));
		register_setting('ADI-bulkimport-settings', 'AD_Integration_bulkimport_pwd', array(&$this, 'sanitize_bulkimport_user_pwd'));
		register_setting('ADI-bulkimport-settings', 'AD_Integration_disable_users', array(&$this, 'sanitize_bool'));
	}
	

	/**
	 * Add an options pane for this plugin.
	 */
	public function add_options_page() {
	
		if (IS_WPMU && is_super_admin()) {
			// WordPress MU
			if (function_exists('add_submenu_page')) {
				add_submenu_page('wpmu-admin.php', __('Active Directory Integration'), __('Active Directory Integration'), 'manage_options', 'active-directory-integration', array(&$this, 'display_options_page'));
			}
		}
	
		if (!IS_WPMU) {
			// WordPress Standard
			if (function_exists('add_options_page')) {
				//add_options_page('Active Directory Integration', 'Active Directory Integration', 'manage_options', __FILE__, array(&$this, 'display_options_page'));
				add_options_page('Active Directory Integration', 'Active Directory Integration', 'manage_options', 'active-directory-integration', array(&$this, 'display_options_page'));
			}
		}
	}

	
	/**
	 * If the REMOTE_USER evironment is set, use it as the username.
	 * This assumes that you have externally authenticated the user.
	 */
	public function authenticate($user = NULL, $username = '', $password = '') {
		
		global $wp_version, $wpmu_version;
		
		$this->_log(ADI_LOG_INFO,'method authenticate() called');		
		
		if (IS_WPMU) {
			$version = $wpmu_version;
		} else {
			$version = $wp_version;
		}
		
		// log debug informations
		$this->_log(ADI_LOG_INFO,"------------------------------------------\n".
								 'PHP version: '.phpversion()."\n".
								 'WP  version: '.$version."\n".
								 'ADI version: '.ADIntegrationPlugin::ADI_VERSION."\n". 
								 'OS Info    : '.php_uname()."\n".
								 'Web Server : '.php_sapi_name()."\n".
								 'adLDAP ver.: '.adLDAP::VERSION."\n".
								 '------------------------------------------');
		
		// IMPORTANT!
		$this->_authenticated = false;
		$user_id = NULL;
		$username = strtolower($username);
		$password = stripslashes($password);

		
		// Don't use Active Directory for admin user (ID 1)
		// $user = get_userdatabylogin($username); // deprecated 
		$user = get_user_by('login', $username);
		
		if (is_object($user) && ($user->ID == 1)) {
			$this->_log(ADI_LOG_NOTICE,'User with ID 1 will never be authenticated by Active Directory Integration.');
			return false;
		}
		
		// extract account suffix from username if not set
		// (after loading of options)
		// Extended for issue #0043
		if (strpos($username,'@') !== false) {
			$this->_log(ADI_LOG_NOTICE,'@domain found.');
			$parts = explode('@',trim($username));
			$puser = $parts[0];
			$pdomain = '@'.$parts[1];
			if (trim($this->_account_suffix) == '') {
				// without Account Suffix
				$username = $puser;
				$this->_account_suffix = $pdomain;
				$this->_append_suffix_to_new_users = true;
				$this->_log(ADI_LOG_NOTICE,'No account suffix set. Using user domain "' . $pdomain . '" as account suffix.');
			} else {
				// with Account Suffix
				// let's see if users domain is in the list of all account suffixes
				$account_suffix_found = false;
				$account_suffixes = explode(";", $this->_account_suffix);
				foreach($account_suffixes AS $account_suffix) {
					if (trim($account_suffix) == $pdomain) {
						// user domain same as _account_suffix (leave _append_suffix_to_new_users untouched)
						$username = $puser;
						$account_suffix_found = true;
						$this->_log(ADI_LOG_NOTICE,'user domain "' . $pdomain . '" in list of account suffixes.');
						break;
					}
				}
				if ($account_suffix_found === false) {
					// 
					$this->_append_suffix_to_new_users = false;
					$this->_account_suffix = '';
					$this->_log(ADI_LOG_NOTICE,'user domain "' . $pdomain . '" NOT in list of account suffixes.');
				}
			}
		}
		
		
		
		$this->_log(ADI_LOG_NOTICE,'username: '.$username);
		$this->_log(ADI_LOG_NOTICE,'password: **not shown**');
		
		
		// Log informations
		$this->_log(ADI_LOG_INFO,"Options for adLDAP connection:\n".
					  "- account_suffix: $this->_account_suffix\n".					
					  "- base_dn: $this->_base_dn\n".
					  "- domain_controllers: $this->_domain_controllers\n".
					  "- ad_port: $this->_port\n".
					  "- use_tls: ".(int) $this->_use_tls."\n".
					  "- network timeout: ". $this->_network_timeout);

		// Connect to Active Directory
		try {
			$this->_adldap = @new adLDAP(array(
						"base_dn" => $this->_base_dn, 
						"domain_controllers" => explode(';', $this->_domain_controllers),
						"ad_port" => $this->_port,               		// AD port
						"use_tls" => $this->_use_tls,             		// secure?
						"network_timeout" => $this->_network_timeout	// network timeout*/ 
						));
		} catch (Exception $e) {
    		$this->_log(ADI_LOG_ERROR,'adLDAP exception: ' . $e->getMessage());
    		return false;
		}
					
		$this->_log(ADI_LOG_NOTICE,'adLDAP object created.');							
					
		
		
		// Check for maximum login attempts
		$this->_log(ADI_LOG_INFO,'max_login_attempts: '.$this->_max_login_attempts);
		if ($this->_max_login_attempts > 0) {
			$failed_logins = $this->_get_failed_logins_within_block_time($username);
			$this->_log(ADI_LOG_INFO,'users failed logins: '.$failed_logins);
			if ($failed_logins >= $this->_max_login_attempts) {
				$this->_authenticated = false;

				$this->_log(ADI_LOG_ERROR,'Authentication failed again');
				$this->_log(ADI_LOG_ERROR,"Account '$username' blocked for $this->_block_time seconds");
				
				// e-mail notfications if user is blocked
				if ($this->_user_notification) {
					$this->_notify_user($username);
					$this->_log(ADI_LOG_NOTICE,"Notification send to user.");
				}
				if ($this->_admin_notification) {
					$this->_notify_admin($username);
					$this->_log(ADI_LOG_NOTICE,"Notification send to admin(s).");
				}
				
				// Show the blocking page to the user (only if we are not in debug/log mode)
				if ($this->_loglevel == ADI_LOG_NONE) {
					$this->_display_blocking_page($username);
				}
				die(); // important !
			} 
		}
		
		

		// This is where the action is.
		$account_suffixes = explode(";",$this->_account_suffix);
		foreach($account_suffixes AS $account_suffix) {
			$account_suffix = trim($account_suffix);
			$this->_log(ADI_LOG_NOTICE,'trying account suffix "'.$account_suffix.'"');			
			$this->_adldap->set_account_suffix($account_suffix);
			if ( $this->_adldap->authenticate($username, $password) === true ) // Authenticate
			{	
				$this->_log(ADI_LOG_NOTICE,'Authentication successfull for "' . $username . $account_suffix.'"');
				$this->_authenticated = true;
				break;
			}
		}
		

		if ( $this->_authenticated == false )
		{
			$this->_log(ADI_LOG_ERROR,'Authentication failed');
			$this->_authenticated = false;
			$this->_store_failed_login($username);
			return false;			
		}
		
		// Cleanup old database entries 
		$this->_cleanup_failed_logins($username);

		// Check the authorization
		if ($this->_authorize_by_group) {
			if ($this->_check_authorization_by_group($username)) {
				$this->_authenticated = true;
			} else {
				$this->_authenticated = false;
				return false;	
			}
		}
		
		$ad_username = $username;
		
		// should the account suffix be used for the new username?
		if ($this->_append_suffix_to_new_users) {
			$username .= $account_suffix;
		}

		// getting user data (again!)
		// $user = get_userdatabylogin($username); // deprecated
		$user = get_user_by('login', $username);
		
		// role
		$user_role = $this->_get_user_role_equiv($ad_username); // important: use $ad_username not $username

		// userinfo from AD
		$this->_log(ADI_LOG_DEBUG, 'ATTRIBUTES TO LOAD: '.print_r($this->_all_user_attributes, true));
		$userinfo = $this->_adldap->user_info($ad_username, $this->_all_user_attributes);
		$userinfo = $userinfo[0];
		$this->_log(ADI_LOG_DEBUG,"USERINFO[0]: \n".print_r($userinfo,true));
		
		// get display name
		$display_name = $this->_get_display_name_from_AD($username, $userinfo);
	
		// Create new users automatically, if configured
		if (!$user OR ($user->user_login != $username)) {
			
			if ($this->_auto_create_user || trim($user_role) != '' ) {
				// create user
				$user_id = $this->_create_user($ad_username, $userinfo, $display_name, $user_role, $password);
			} else {
				// Bail out to avoid showing the login form
				$this->_log(ADI_LOG_ERROR,'This user exists in Active Directory, but has not been granted access to this installation of WordPress.');
				return new WP_Error('invalid_username', __('<strong>ERROR</strong>: This user exists in Active Directory, but has not been granted access to this installation of WordPress.'));
			}
			
		} else {
			
			//  Update known users if configured
			if ($this->_auto_create_user AND $this->_auto_update_user) {
				// Update users role
				$user_id = $this->_update_user($ad_username, $userinfo, $display_name, $user_role, $password);
			}
		}
		
		// load user object
		if (!$user_id) {
			if (version_compare($wp_version, '3.1', '<')) {
				require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'registration.php');
			}
			$user_id = username_exists($username);
			$this->_log(ADI_LOG_NOTICE,'user_id: '.$user_id);
		}
		$user = new WP_User($user_id);
		
		// user disabled?
		if (get_user_meta($user_id, 'adi_user_disabled', true)) {
			$this->_log(ADI_LOG_WARN,'User with ID ' . $user_id .' is disabled.');
			$this->_authenticated = false;
			return false;
		}

		$this->_log(ADI_LOG_NOTICE,'FINISHED');
		return $user;
	}	
	

	/*
	 * Use local (WordPress) password check if needed and allowed
	 */
	public function override_password_check($check, $password, $hash, $user_id) {
		
		// Always use local password handling for user_id 1 (admin)
		if ($user_id == 1) {
			$this->_log(ADI_LOG_DEBUG,'UserID 1: using local (WordPress) password check.');
			return $check;
		}
		
		// return true for users authenticated by ADI (should never happen, but who knows?)
		if ( $this->_authenticated == true ) 
		{
			$this->_log(ADI_LOG_DEBUG,'User successfully authenticated by ADI: override local (WordPress) password check.');
			return true;
		}
		
		// return false if user is disabled
		if (get_user_meta($user_id,'adi_user_disabled', true)) {
			$reason = get_user_meta($user_id,'adi_user_disabled_reason', true);
			$this->_log(ADI_LOG_DEBUG,'User is disabled. Reason: '.$reason);
			return false;
		}
		
		
		// Only check for local password if this is not an AD user and if fallback to local password is active
		$usercheck =  get_user_meta($user_id,'adi_samaccountname', true);
		if ($usercheck != '') {
			if ($this->_fallback_to_local_password) {
				$this->_log(ADI_LOG_DEBUG,'User from AD. Falling back to local (WordPress) password check.');
				return $check;
			} else {
				$this->_log(ADI_LOG_DEBUG,'User from AD and fallback to local (WordPress) password deactivated. Authentication failed.');
				return false;
			}
		}
		
		// use local password check in all other cases
		$this->_log(ADI_LOG_DEBUG,'Using local (WordPress) password check.');
		return $check;
	}
	
	/**
	 * Auto Login / Single Sign On
	 * Code by Alex Nolan
	 */
	public function auto_login() {
		// TODO: This has to be tested - carefully
		// looks pretty insecure
		/*
		if (!is_user_logged_in() && isset($_SERVER['LOGON_USER'])) {
			$user_login = substr($_SERVER['LOGON_USER'], strrpos($_SERVER['LOGON_USER'],'\\')+1, strlen($_SERVER['LOGON_USER'])-strrpos($_SERVER['LOGON_USER'],'\\'));
			$user = get_userdatabylogin($user_login); // TODO: deprecated
			$user_id = $user->ID;
			wp_set_current_user($user_id, $user_login);
			wp_set_auth_cookie($user_id);
			do_action('wp_login', $user_login);
		}
		*/
    }	

	/*
	 * Generate a password for the user. This plugin does not
	 * require the user to enter this value, but we want to set it
	 * to something nonobvious.
	 */
	public function generate_password($username, $password1, $password2) {
		$password1 = $password2 = $this->_get_password();
	}

	/*
	 * Used to disable certain display elements, e.g. password
	 * fields on profile screen.
	 */
	public function disable_password_fields($show_password_fields) {
		return false;
	}

	/*
	 * Used to disable certain login functions, e.g. retrieving a
	 * user's password.
	 */
	public function disable_function() {
		die('Disabled');
	}
	
	/**
	 * Shows the contexual help on the options/admin screen.
	 * 
	 * @param $help
	 * @param $screen
	 * @return string help message
	 */
	public function contextual_help ($help, $screen) {
		if ($screen == 'settings_page_' . ADINTEGRATION_FOLDER . '/ad-integration'
		                 || $screen == 'wpmu-admin_page_' . ADINTEGRATION_FOLDER . '/ad-integration') {
			$help .= '<h5>' . __('Active Directory Integration Help','ad-integration') . '</h5><div class="metabox-prefs">';
			$help .= '<a href="http://blog.ecw.de/wp-ad-integration" target="_blank">'.__ ('Overview','ad-integration').'</a><br/>';
			$help .= '<a href="http://wordpress.org/extend/plugins/active-directory-integration/faq/" target="_blank">'.__ ('FAQ', 'ad-integration').'</a><br/>';
			$help .= '<a href="http://wordpress.org/extend/plugins/active-directory-integration/changelog/" target="_blank">'.__ ('Changelog', 'ad-integration').'</a><br/>';
			$help .= '<a href="http://wordpress.org/tags/active-directory-integration" target="_blank">'.__ ('Support-Forum', 'ad-integration').'</a><br/>';
			$help .= '<a href="http://bt.ecw.de/" target="_blank">'.__ ('Bug Tracker', 'ad-integration').'</a><br/>';
			$help .= '</div>';
		}
		return $help;
	}
	
	/**
	 * Generate an error message for the users if Sync Back failed.
	 */
	public function generate_error(&$errors, $update, &$user) {
		$errors = $this->errors;
	}
	
	
	
	public function setLogLevel($level = 0) {
		$this->_loglevel = (int)$level;
	}

	public function setLogFile($filename) {
		$this->_logfile = $filename;
	}
	
	
	public function disableDebug() {
		echo '<pre>';
		$this->debug = false;
		echo '</pre>';
	}
	
	
	
	
	/**
	 * HOOKS: Actions and Filters
	 */
	
	
	/**
	 * Show the disable user checkbox if needed
	 * Action(s): edit_user_profile, show_user_profile
	 * 
	 * @param object $user 
	 */
	public function show_user_profile_disable_user($user) {
		
		global $user_ID;
		
		// User disabled only visible for admins and not for user with ID 1 (admin) and not for ourselves
		if (current_user_can('level_10') && ($user->ID != 1) && ($user->ID != $user_ID)) {

			// Load up the localization file if we're using WordPress in a different language
			// Place it in this plugin's folder and name it "ad-integration-[value in wp-config].mo"
			load_plugin_textdomain( 'ad-integration', false, dirname( plugin_basename( __FILE__ ) ) );
			
			$user_disabled = get_user_meta($user->ID, 'adi_user_disabled', true);
			?>
			<input type="hidden" name="adi_user_disabling" value="1" />
			<table class="form-table">
				<tr>
					<th><label><?php _e('User Disabled','ad-integration');?></label></th>
					<td>
						<input type="checkbox" name="adi_user_disabled" id="adi_user_disabled"<?php if ($user_disabled) echo ' checked="checked"' ?> value="1" />
						<?php _e('If selected, the user can not log in and his e-mail address will be changed for security reasons. The e-mail address is restored if the user is reenabled.','ad-integration'); ?>
						<?php 
						if ($user_disabled) {
							?>
							<p class="description"><?php _e('Information on last disabling: ', 'ad-integration');
							echo get_user_meta($user->ID, 'adi_user_disabled_reason', true);?></p>
							<?php 
						}?>
						<p class="description"><?php _e('Attention: This flag is automatically set (or unset) by Bulk Import and its state may change on next run of Bulk Import.','ad-integration'); ?></p>
					</td>
				</tr>
			</table>
		<?php 
		}	
	}

	
	/**
	 * Update disable status as set on profile page
	 * Action(s): personal_options_update, edit_user_profile_update
	 * 
	 * @param object $user_id
	 */
	public function profile_update_disable_user($user_id)
	{
		global $user_login;
		
		// Disable User
		if (isset($_POST['adi_user_disabling'])) {
			if (isset($_POST['adi_user_disabled'])) {
				// Disable if user was not disabled only
				if (get_user_meta($user_id, 'adi_user_disabled', true) == false) {
					$this->_disable_user($user_id, sprintf(__('User manually disabled by "%s".', 'ad-integration'), $user_login));
				}
			} else {
				// Reenable if user was disabled only
				if (get_user_meta($user_id, 'adi_user_disabled', true) == true) {
					$this->_enable_user($user_id);
				}
			}
		}
	}
	
	/*
	 * Display the options for this plugin.
	 */
	public function display_options_page() {
		include dirname( __FILE__ ) .'/admin.php';
	}	
				
	
	/**
	 * Show defined AD attributes on profile page
	 */
	public function show_AD_attributes($user) {
		
		global $user_ID;
		
		// Load up the localization file if we're using WordPress in a different language
		// Place it in this plugin's folder and name it "ad-integration-[value in wp-config].mo"
		load_plugin_textdomain( 'ad-integration', false, dirname( plugin_basename( __FILE__ ) ) );
		
		// Additional Attributes
		if ($this->_show_attributes) {
			
			$all_attributes = $this->_get_attributes_array();
		
			$list = str_replace(";", "\n", $this->_attributes_to_show);
			$list = explode("\n", $list);
			
			$attributes = array();
			foreach($list AS $line) {
				$parts = explode(':',$line);
				if (isset($parts[0])) {
					if (trim($parts[0] != '')) {
						$attributes[] = trim($parts[0]);
					}
				}
			}

			if (count($attributes) > 0) {
				wp_nonce_field('ADI_UserProfileUpdate','ADI_UserProfileUpdate_NONCE');
				echo '<h3>' . __('Additional Informations', 'ad-integration').'</h3>';
				
				$adi_samaccountname = get_user_meta($user->ID, 'adi_samaccountname', true); 
				?>
				<input type="hidden" name="adi_samaccountname" value="<?php echo $adi_samaccountname; ?>" />
				<table class="form-table">
				<?php 
				foreach ($attributes AS $attribute) {
					$no_attribute = false;
					if (isset($all_attributes[$attribute]['metakey'])) {
						$metakey = $all_attributes[$attribute]['metakey'];
						$value = get_user_meta($user->ID, $metakey, true);
					} else {
						$value = '';
						$no_attribute = true;
					}
					
					if (isset($all_attributes[$attribute]['description'])) {
						$description = trim($all_attributes[$attribute]['description']);
					} else {
						// if value is empty and we've found no description then this is no attribute
						if ($value == '') {
							$no_attribute = true;
						}
					} 
					
					?>
					<tr>
					  <?php if ($no_attribute) { // use as sub-headline ?>
					  	<th colspan="2">
					  	  <?php echo $description; ?>
					  	</th>
					  <?php } else {?>	
					    <th><label for="<?php echo $metakey ?>"><?php echo $description; ?></label></th>
					    <td><?php
					    // editable only if this is our own personal profile page if Global Sync Back user is not set.
					    if (($this->_syncback == true)
					    		&& isset($all_attributes[$attribute]['sync']) 
					        	&& ($all_attributes[$attribute]['sync'] == true) 
					        	&& (($user->ID == $user_ID) || ($this->_syncback_use_global_user === true))) {
					        // use textarea if we have a list
					        if (isset($all_attributes[$attribute]['type']) && ($all_attributes[$attribute]['type'] == 'list')) {
					        	echo '<textarea name="'.$metakey.'" id="'.$metakey.'" cols="30" rows="3">'.esc_html($value).'</textarea>';
					        } else {
						    	echo '<input type="text" name="'.$metakey.'" id="'.$metakey.'" value="'.esc_html($value).'" class="regular-text code">';
					        }
					    } else {
					    	echo nl2br(esc_html($value));
					  	}
					  ?></td>
					  <?php } ?>
					</tr>
				<?php 
				}
				
				// show this only if Global Sync Back user is not set AND your are your own personal profile page AND we have an AD-user
				if (($this->_syncback_use_global_user === false)
					 && ($user->ID == $user_ID)
					 && ($this->_syncback == true)
					 && ($adi_samaccountname != '')) {
					?>
					<tr>
						<th><label for="adi_syncback_password" class="adi_syncback_password"><?php _e('Your password','ad-integration');?></label></th>
						<td>
							<input type="password" name="adi_synback_password" id="adi_syncback_password" class="regulat-text code" />
							<?php _e('If you want to save the changes on "Additional Informations" back to the Active Directory you must enter your password.')?>
						</td>
					</tr>
					<?php
				}
				
				?>
				</table>
				<?php
			}
		}
	}
	

	
	
	/**
	 * Update user meta from profile page
	 * Here we can write user meta informations back to AD. User disable status is set in profile_update_disable_user().
	 * 
	 * @param integer $user_id
	 */
	public function profile_update($user_id)
	{
		global $wp_version, $user_login;
		
		// Add an action, so we can show errors on profile page
		add_action('user_profile_update_errors', array(&$this,'generate_error'), 10, 3);
		
		$this->_log(ADI_LOG_DEBUG,'SyncBack: Start of profile update');
		
		$attributes_to_sync = array();
		
		// check if synback is on and we have a user from AD and not local user
		if ($this->_syncback === true)
		{
		
			// Go through attributes and update user meta if necessary.
			$attributes = $this->_get_attributes_array();
			foreach($attributes AS $key => $attribute) {
				if ($attribute['sync'] == true) {
					if (isset($_POST[$attribute['metakey']])) {
						
						if ($attribute['type'] == 'list') {
							// List
							$list = explode("\n",str_replace("\r",'',$_POST[$attribute['metakey']]));
							$i=0;
							foreach ($list AS $line) {
								if (trim($line) != '') {
									$attributes_to_sync[$key][$i] = $line;
									$i++;
								}
							}
							if ($i == 0) {
								$attributes_to_sync[$key][0] = ' '; // Use a SPACE !!!
							}
						} else {
							// single value
							if ($_POST[$attribute['metakey']] == '') {
								$attributes_to_sync[$key][0] = ' '; // Use a SPACE !!!!
							} else {
								$attributes_to_sync[$key][0] = $_POST[$attribute['metakey']];
							}
						}
						update_user_meta($user_id, $attribute['metakey'], $_POST[$attribute['metakey']]);
					}
				}
			}
			
			// Only SyncBack if we have an AD-user and not a local user
			if (isset($_POST['adi_samaccountname']) && ($_POST['adi_samaccountname'] != '')) { 
			
				// Get User Data
				$userinfo = get_userdata($_POST['user_id']);
				$username = $userinfo->user_login;
				
				// use personal_account_suffix
				$personal_account_suffix = trim(get_user_meta($user_id,'ad_integration_account_suffix', true));
				if ($personal_account_suffix != '') {
					$account_suffix = $personal_account_suffix;
				} else {
					// extract account suffix from username if not set
					// (after loading of options)
					if (trim($this->_account_suffix) == '') {
						if (strpos($username,'@') !== false) {
							$parts = explode('@',$username);
							$username = $parts[0];
							$this->_account_suffix = '@'.$parts[1];
							$this->_append_suffix_to_new_users = true; // TODO not really, hm?
						}
					} else {				
						// choose first possible account suffix (this should never happen)
						$suffixes = explode(';',$this->_account_suffix);
						$account_suffix = $suffixes[0];
						$this->_log(ADI_LOG_WARN,'No personal account suffix found. Now using first account suffix "'.$account_suffix.'".');
					}
				}
				

				// establish adLDAP connection
				// Connect to Active Directory
				if ($this->_syncback_use_global_user === true) {
					$ad_username = $this->_syncback_global_user;
					$ad_password = $this->_decrypt($this->_syncback_global_pwd);
				} else {
					if (isset($_POST['adi_synback_password']) && ($_POST['adi_synback_password'] != '')) {
						$ad_username = $username.$account_suffix;  
						$ad_password = stripslashes($_POST['adi_synback_password']);
					} else {
						// No Global Sync User and no password given, so stop here.
						$this->errors->add('syncback_no_password',__('No password given, so additional attributes are not written back to Active Directory','ad-integration'));
						return false;
					}
				}
				
				// Log informations
				$this->_log(ADI_LOG_INFO,"SyncBack: Options for adLDAP connection:\n".
							  "- base_dn: $this->_base_dn\n".
							  "- domain_controllers: $this->_domain_controllers\n".
							  "- ad_username: $ad_username\n".
							  "- ad_password: **not shown**\n".
							  "- ad_port: $this->_port\n".
							  "- use_tls: ".(int) $this->_use_tls."\n".
							  "- network timeout: ". $this->_network_timeout);
							
				try {
					$ad =  @new adLDAP(array(
											"base_dn" => $this->_base_dn, 
											"domain_controllers" => explode(';', $this->_domain_controllers),
											"ad_username" => $ad_username,      // AD Bind User
											"ad_password" => $ad_password,      // password
											"ad_port" => $this->_port,          // AD port
											"use_tls" => $this->_use_tls,             		// secure?
											"network_timeout" => $this->_network_timeout	// network timeout
											));
				} catch (Exception $e) {
		    		$this->_log(ADI_LOG_ERROR,'adLDAP exception: ' . $e->getMessage());
		    		$this->errors->add('syncback_wrong_password',__('Error on writing additional attributes back to Active Directory. Wrong password?','ad-integration'),'');
					return false; 
				}
				$this->_log(ADI_LOG_DEBUG,'Connected to AD');
				
				
				//  Now we can modify the user
				$this->_log(ADI_LOG_DEBUG,'attributes to sync: '.print_r($attributes_to_sync, true));
				$this->_log(ADI_LOG_DEBUG,'modifying user: '.$username);
				$modified = @$ad->user_modify_without_schema($username, $attributes_to_sync);
				if (!$modified) {
					$this->_log(ADI_LOG_WARN,'SyncBack: modifying user failed');
					$this->_log(ADI_LOG_DEBUG,$ad->get_last_errno().': '.$ad->get_last_error());
		    		$this->errors->add('syncback_modify_failed',__('Error on writing additional attributes back to Active Directory. Please contact your administrator.','ad-integration') . "<br/>[Error " . $ad->get_last_errno().'] '.$ad->get_last_error(),'');
		    		return false;
				} else {
					$this->_log(ADI_LOG_NOTICE,'SyncBack: User successfully modified.');
					return true;
				}
			} else {
				return true;
			}
		}
	}
	
	/**
	 * Disable email field in user profile if needed (actions edit_user_profile and show_user_profile)
	 * This is not safe and only for cosmetic reasons, but we also have the method prevent_email_change() (see below).
	 * 
	 * @param object $user
	 */
	public function user_profile_prevent_email_change($user)
	{
		// disable email field if needed (dirty hack)
		if ($this->_prevent_email_change && $this->_is_adi_user($user->ID) && (!current_user_can('level_10'))) {
			?>
			<script type="text/javascript">
				var email = document.getElementById('email');
				if (email) {
					email.setAttribute('disabled','disabled');
				}
			</script>
			<?php 
		}		
	}	
	
	/**
	 * Prevent ADI users from changing their email (action user_profile_update_errors)
	 * 
	 * @param object $errors
	 * @param bool $update
	 * @param object $user
	 */
	public function prevent_email_change(&$errors, $update, &$user)
	{
		if ($this->_prevent_email_change && ($this->_is_adi_user($user->ID)) && (!current_user_can('level_10'))) {
		    $old = get_user_by('id', $user->ID);
		
		    if( $user->user_email != $old->user_email ) {
		    	// reset to old email
				$this->_log(ADI_LOG_DEBUG, 'Prevent email change on profile update for user "'.$user->user_login.'" ('.$user->ID.').');
		        $user->user_email = $old->user_email;
		    }
		}
	}	
	
	
	/**
	 *  Add new column to the user list page
	 *  
	 *  @param array $columns 
	 */
	public function manage_users_columns($columns) {
		global $wp_version;
		$columns['adi_user'] = __('ADI User', 'ad-integration');
		$columns['adi_user_disabled'] = __('Disabled', 'ad-integration');
		return $columns;
	}
	

	
	/**
	 *  Add column content for each user on user list
	 *  
	 * @param mixed $value Value to show
	 * @param string $column_name Name of column in user table
	 * @param integer $user_id ID of user (the row)  
	 */
	public function manage_users_custom_column( $value, $column_name, $user_id ) {

		// Column "Disabled"
		if ( $column_name == 'adi_user' ) {
			$sam = get_user_meta($user_id, 'adi_samaccountname', true);
			if ($sam != '') {
				$value = '<div class="user_adi">&nbsp;</div>';
			} else {
				$value = '';
			}
		}
		
		// Column "Reason"
		if ( $column_name == 'adi_user_disabled' ) {
			if (get_user_meta($user_id, 'adi_user_disabled', true)) {
				//$value = __('Yes', 'ad-integration'). ' - ';
				$value = '<div class="user_disabled">' . __(get_user_meta($user_id, 'adi_user_disabled_reason', true), 'ad-integration') . '</div>';
			} else {
				$value = '';
			}
		}
		
		return $value;
	}	
		
	
	/****************************************************************
	 * STATIC FUNCTIONS
	 ****************************************************************/

	/**
	 * Determine global table prefix, usually "wp_".
	 * 
	 * @return string table prefix
	 */
	public static function global_db_prefix() {
		global $wpmu_version, $wpdb, $wpmuBaseTablePrefix;
		
		// define table prefix
		if ($wpmu_version != '') {
			return $wpmuBaseTablePrefix;
		} else {
			return $wpdb->prefix;
		}
	}

	
	/**
	 * Adding the needed table to database and store the db version in the
	 * options table on plugin activation.
	 */
	public static function activate() {
		global $wpdb, $wpmu_version;
		
		$table_name = ADIntegrationPlugin::global_db_prefix() . ADIntegrationPlugin::TABLE_NAME;
		
		
		// get current version and write version of plugin to options table
		if (isset($wpmu_version) && $wpmu_version != '') {
			$version_installed = get_site_option('AD_Integration_version');
			update_site_option('AD_Integration_version', ADIntegrationPlugin::ADI_VERSION);
		} else {
			$version_installed = get_option('AD_Integration_version');
			update_option('AD_Integration_version', ADIntegrationPlugin::ADI_VERSION);
		}
		
		// get current db version
		if (isset($wpmu_version) && $wpmu_version != '') {
			$db_version = get_site_option('AD_Integration_db_version');
		} else {
			$db_version = get_option('AD_Integration_db_version');
		}
		
		if (($wpdb->get_var("show tables like '$table_name'") != $table_name) OR ($db_version != ADIntegrationPlugin::DB_VERSION)) { 
	      
	    	$sql = 'CREATE TABLE ' . $table_name . ' (
		  			id bigint(20) NOT NULL AUTO_INCREMENT,
		  			user_login varchar(60),
		  			failed_login_time bigint(11),
		  			UNIQUE KEY id (id)
				  );';
	
			require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
	      	dbDelta($sql);
	      
	   		// store db version in the options
	      	if (isset($wpmu_version) && $wpmu_version != '') {
	      		add_site_option('AD_Integration_db_version', ADIntegrationPlugin::DB_VERSION);
	      	} else {
		   		add_option('AD_Integration_db_version', ADIntegrationPlugin::DB_VERSION);
	      	}
		}

		// Upgrade?
		if (version_compare(ADIntegrationPlugin::ADI_VERSION, $version_installed,'>')) {
			
			if (version_compare('1.0.1', $version_installed, '>') || ($version_installed == false)) {
				// remove old needless options
		      	if (isset($wpmu_version) && $wpmu_version != '') {
		      		delete_site_option('AD_Integration_bind_user');
		      		delete_site_option('AD_Integration_bind_pwd');
		      	} else {
			   		delete_option('AD_Integration_bind_user');
		      		delete_option('AD_Integration_bind_pwd');
		      	}
			}
		}
		
	}
	
	
	/**
	 * Delete the table from database and delete the db version from the
	 * options table on plugin deactivation.
	 */
	public static function deactivate() {
		global $wpdb, $wpmu_version;
		
		$table_name = ADIntegrationPlugin::global_db_prefix() . ADIntegrationPlugin::TABLE_NAME;
		
		// drop table
		$wpdb->query('DROP TABLE IF EXISTS '.$table_name);
		
		// delete option
		if (isset($wpmu_version) && $wpmu_version != '') {
			delete_site_option('AD_Integration_db_version');
		} else {
			delete_option('AD_Integration_db_version');
		}
	}	
	
	
	/**
	 * removes the plugin options from options table.
	 * 
	 * @param bool $echo print results as HTML  
	 */
	public static function uninstall($echo=false) {
		foreach(self::$_all_options as $option) {
			$delete_setting = delete_option($option['name']);
			if ($echo) {
				if($delete_setting) {
					echo '<font color="green">';
					printf(__('Setting Key \'%s\' has been deleted.', 'ad-integration'), "<strong><em>{$option['name']}</em></strong>");
					echo '</font><br />';
				} else {
					echo '<font color="red">';
					printf(__('Error deleting Setting Key \'%s\'.', 'ad-integration'), "<strong><em>{$option['name']}</em></strong>");
					echo '</font><br />';
				}
			}
		}
	}
	
	
	/********************************************
	 * Sanitize methods for register_settings
	 ********************************************/
	
	/**
	 * Sanitize AD Servers port
	 * 
	 * @param string $port
	 * @return integer sanitized port number
	 */
	public function sanitize_port($port) {
		$port = intval($port);
		if (($port < 0) || ($port > 65535)) {
			$port = 389;
		} 
		return $port;
	}
	
	/**
	 * Sanitize default email domain
	 * trim, strip possible @
	 * 
	 * @param string $domain
	 * @return string sanitized domain
	 */
	public function sanitize_default_email_domain($domain)
	{
		$domain = preg_replace('/[^\A-Za-z0-9-\.]/', '', $domain);
		return $domain;
	}
	
	/**
	 * Strip spaces from beginning or end of suffixes
	 * Our seperator (;) is an allowed character in UPN suffixes but not recommended, so fuck the shit.
	 * 
	 * @param string $suffix
	 * @return string 
	 */
	public function sanitize_account_suffix($suffix)
	{
		$parts = explode(';', $suffix);
		$results = array();
		foreach($parts as $part)
		{
			$results[] = trim($part);
		}
		return implode(';', $results);	
	}
	
	/**
	 * Sanitize Additional User Attributes
	 * trim, delete empty line
	 * 
	 * @param string $text
	 * @return string
	 */	
	public function sanitize_attributes_to_show($text)
	{
		$lines = explode("\n", $text);
		$sanitized_lines = array();
		foreach ($lines AS $line) {
			$line = trim($line);
			if ($line != '') {
				$sanitized_lines[] = $line;
			}
		}
		return implode("\n", $sanitized_lines);
	}	

	
	/**
	 * Strips out wrong entries from role_equivalent_groups and converts the WP role to lowercase.
	 * 
	 * @param string $text
	 * @return string
	 */
	public function sanitize_role_equivalent_groups($text)
	{
		$groups = explode(";", $text);
		$sanitized_groups = array();
		foreach ($groups AS $group) {
			$group = trim($group);
			$pos = strpos($group, '=');
			if ($pos != 0) { // yes != 0, since int 0 is also unwanted
				$ad_group = substr($group,0,$pos);
				$role = strtolower(substr($group,$pos+1)); // roles are always lowercase / Issue #0055
				if ($role != '') {
					$sanitized_groups[] = $ad_group . '=' . $role;
				}
			}
		}
		return implode(";", $sanitized_groups);
	}		
	
	/**
	 * Sanitize Additional User Attributes
	 * trim, delete empty line, all to lowercase.
	 * 
	 * @param string $text
	 * @return string
	 */
	public function sanitize_additional_user_attributes($text) {
		$lines = explode("\n", $text);
		$sanitized_lines = array();
		foreach ($lines AS $line) {
			$line = trim($line);
			if ($line != '') {
				$sanitized_lines[] = strtolower($line); // all in lower case
			}
		}
		return implode("\n", $sanitized_lines);
	}

	/**
	 * Maximum number of login attempts must be a postive integer.
	 * 
	 * @param integer $attempts
	 * @return integer 3 if $attempts is lower than 1
	 */
	public function sanitize_max_login_attempts($attempts) {
		$attempts = intval($attempts);
		if ($attempts < 1) {
			$attempts = 3;
		}
		return $attempts;
	}
	
	/**
	 * Block time must be a postive integer.
	 * 
	 * @param integer $seconds
	 * @return integer 30 if $seconds is lower than 1
	 */
	public function sanitize_block_time($seconds) {
		$seconds = intval($seconds);
		if ($seconds < 1) {
			$seconds = 30;
		}
		return $seconds;
	}
	
	/**
	 * Check if $email is a correct email address.
	 * 
	 * @param string $email
	 * @return string if we have no correct email address we return an empty string
	 */
	public function sanitize_admin_email($email) {
		if (!is_email($email)) {
			return '';
		}
		return $email;
	}
	
	/**
	 * If $value is true (as expression) returns true, otherwise false
	 * 
	 * @param mixed $value
	 * @return bool
	 */
	public function sanitize_bool($value) {
		return ($value == true);
	}

	
	/**
	 * Sanitize Global Sync User
	 * 
	 * @param string $user
	 * @return string sanitized username
	 */
	public function sanitize_syncback_global_user($user)
	{
		return trim($user);
	}
	
	/**
	 * Encrypts the Sync Back User Password
	 * 
	 * @param string $pwd unencrypted password
	 * @return encrypted (sanitized) password
	 */	
	public function sanitize_syncback_global_user_pwd($pwd)
	{
		// Password left unchanged so get it from $db
		if ($pwd == '') {
			if (IS_WPMU) { 
				$pwd = get_site_option('AD_Integration_syncback_global_pwd');
			} else {
				$pwd = get_option('AD_Integration_syncback_global_pwd');
			}
		} else {
			$pwd = $this->_encrypt($pwd);
		}
		return $pwd;
	}	
	
	
	/**
	 * Sanitize Buk Import User
	 * 
	 * @param string $user
	 * @return string sanitized username
	 */
	public function sanitize_bulkimport_user($user)
	{
		return trim($user);
	}
	
	
	/**
	 * Encrypts the Bulk Import User Password
	 * 
	 * @param string $pwd unencrypted password
	 * @return encrypted (sanitized) password
	 */
	public function sanitize_bulkimport_user_pwd($pwd)
	{
		// Password left unchanged so get it from $db
		if ($pwd == '') {
			if (IS_WPMU) { 
				$pwd = get_site_option('AD_Integration_bulkimport_pwd');
			} else {
				$pwd = get_option('AD_Integration_bulkimport_pwd');
			}
		} else {
			$pwd = $this->_encrypt($pwd);
		}
		return $pwd;
	}	
	
	
	
	/**
	 * Sanitize new authcode
	 * new_authcode is always resetted to false after a new authcode is generated
	 * 
	 * @param bool $new
	 */
	public function sanitize_new_authcode($new)
	{
		if ($new) {
			$this->_generate_authcode();
		}
		return false;
	}	
	
	/**
	 * LDAP network timeout must be a postive integer.
	 * 
	 * @param $seconds
	 * @return integer 5 if $seconds is lower than 1
	 */
	
	public function sanitize_network_timeout($seconds)
	{
		$seconds = intval($seconds);
		if ($seconds < 1) {
			$seconds = 5;
		}
		return $seconds;
	}
	

	
	/*************************************************************
	 * Protected Methods
	 *************************************************************/
	
	
	/**
	 * Loads the options from WordPress-DB
	 */
	protected function _load_options() {
		
		if (IS_WPMU) {
			$this->_log(ADI_LOG_INFO,'loading options (WPMU) ...');
			
			// Server (5)
			$this->_domain_controllers 			= get_site_option('AD_Integration_domain_controllers');
			$this->_port 						= get_site_option('AD_Integration_port');
			$this->_use_tls 					= get_site_option('AD_Integration_use_tls');
			$this->_network_timeout				= (int)get_site_option('AD_Integration_network_timeout');
			$this->_base_dn						= get_site_option('AD_Integration_base_dn');

			// User (13)
			$this->_account_suffix		 		= get_site_option('AD_Integration_account_suffix');
			$this->_append_suffix_to_new_users 	= get_site_option('AD_Integration_append_suffix_to_new_users');
			$this->_auto_create_user 			= (bool)get_site_option('AD_Integration_auto_create_user');
			$this->_auto_update_user 			= (bool)get_site_option('AD_Integration_auto_update_user');
			$this->_auto_update_description		= (bool)get_site_option('AD_Integration_auto_update_description');
			$this->_default_email_domain 		= get_site_option('AD_Integration_default_email_domain');
			$this->_duplicate_email_prevention  = get_site_option('AD_Integration_duplicate_email_prevention');
			$this->_prevent_email_change  		= (bool)get_site_option('AD_Integration_prevent_email_change');
			$this->_display_name				= get_site_option('AD_Integration_display_name');
			$this->_show_user_status			= (bool)get_site_option('AD_Integration_show_user_status');
			$this->_enable_password_change      = get_site_option('AD_Integration_enable_password_change');
			$this->_no_random_password			= (bool)get_site_option('AD_Integration_no_random_password');
			$this->_auto_update_password		= (bool)get_site_option('AD_Integration_auto_update_password');
			
			// Authorization (3)
			$this->_authorize_by_group 			= (bool)get_site_option('AD_Integration_authorize_by_group');
			$this->_authorization_group 		= get_site_option('AD_Integration_authorization_group');
			$this->_role_equivalent_groups 		= get_site_option('AD_Integration_role_equivalent_groups');
			
			// Security (7)
			$this->_fallback_to_local_password	= get_site_option('AD_Integration_fallback_to_local_password');
			$this->_enable_lost_password_recovery = (bool)get_site_option('AD_Integration_enable_lost_password_recovery');
			$this->_max_login_attempts 			= (int)get_site_option('AD_Integration_max_login_attempts');
			$this->_block_time 					= (int)get_site_option('AD_Integration_block_time');
			$this->_user_notification	  		= (bool)get_site_option('AD_Integration_user_notification');
			$this->_admin_notification			= (bool)get_site_option('AD_Integration_admin_notification');
			$this->_admin_email					= get_site_option('AD_Integration_admin_email');

			// User Meta (8)
			$this->_additional_user_attributes	= get_site_option('AD_Integration_additional_user_attributes');
			$this->_usermeta_empty_overwrite	= (bool)get_site_option('AD_Integration_usermeta_empty_overwrite');
			$this->_show_attributes				= (bool)get_site_option('AD_Integration_show_attributes');
			$this->_attributes_to_show			= get_site_option('AD_Integration_attributes_to_show');
			$this->_syncback					= (bool)get_site_option('AD_Integration_syncback');
			$this->_syncback_use_global_user	= (bool)get_site_option('AD_Integration_syncback_use_global_user');
			$this->_syncback_global_user		= get_site_option('AD_Integration_syncback_global_user');
			$this->_syncback_global_pwd			= get_site_option('AD_Integration_syncback_global_pwd');
			
			// Bulk Import (7)
			$this->_bulkimport_enabled			= (bool)get_site_option('AD_Integration_bulkimport_enabled');
			$this->_bulkimport_authcode 		= get_site_option('AD_Integration_bulkimport_authcode');
			$this->_bulkimport_new_authcode		= (bool)get_site_option('AD_Integration_bulkimport_new_authcode');
			$this->_bulkimport_security_groups	= get_site_option('AD_Integration_bulkimport_security_groups');
			$this->_bulkimport_user				= get_site_option('AD_Integration_bulkimport_user');
			$this->_bulkimport_pwd				= get_site_option('AD_Integration_bulkimport_pwd');
			$this->_disable_users				= (bool)get_site_option('AD_Integration_disable_users');
						
		} else {
			$this->_log(ADI_LOG_INFO,'loading options ...');
			
			// Server (5)
			$this->_domain_controllers 			= get_option('AD_Integration_domain_controllers');
			$this->_port 						= get_option('AD_Integration_port');
			$this->_use_tls 					= get_option('AD_Integration_use_tls');
			$this->_network_timeout				= (int)get_option('AD_Integration_network_timeout');
			$this->_base_dn						= get_option('AD_Integration_base_dn');

			// User (13)
			$this->_account_suffix		 		= get_option('AD_Integration_account_suffix');
			$this->_append_suffix_to_new_users 	= get_option('AD_Integration_append_suffix_to_new_users');
			$this->_auto_create_user 			= (bool)get_option('AD_Integration_auto_create_user');
			$this->_auto_update_user 			= (bool)get_option('AD_Integration_auto_update_user');
			$this->_auto_update_description		= (bool)get_option('AD_Integration_auto_update_description');
			$this->_default_email_domain 		= get_option('AD_Integration_default_email_domain');
			$this->_duplicate_email_prevention  = get_option('AD_Integration_duplicate_email_prevention');
			$this->_prevent_email_change  		= (bool)get_option('AD_Integration_prevent_email_change');
			$this->_display_name				= get_option('AD_Integration_display_name');
			$this->_show_user_status			= (bool)get_option('AD_Integration_show_user_status');
			$this->_enable_password_change      = get_option('AD_Integration_enable_password_change');
			$this->_no_random_password			= (bool)get_option('AD_Integration_no_random_password');
			$this->_auto_update_password		= (bool)get_option('AD_Integration_auto_update_password');
			
			// Authorization (3)
			$this->_authorize_by_group 			= (bool)get_option('AD_Integration_authorize_by_group');
			$this->_authorization_group 		= get_option('AD_Integration_authorization_group');
			$this->_role_equivalent_groups 		= get_option('AD_Integration_role_equivalent_groups');
			
			// Security (6)
			$this->_fallback_to_local_password	= get_option('AD_Integration_fallback_to_local_password');
			$this->_enable_lost_password_recovery = (bool)get_option('AD_Integration_enable_lost_password_recovery');
			$this->_max_login_attempts 			= (int)get_option('AD_Integration_max_login_attempts');
			$this->_block_time 					= (int)get_option('AD_Integration_block_time');
			$this->_user_notification	  		= (bool)get_option('AD_Integration_user_notification');
			$this->_admin_notification			= (bool)get_option('AD_Integration_admin_notification');
			$this->_admin_email					= get_option('AD_Integration_admin_email');

			// User Meta (8)
			$this->_additional_user_attributes	= get_option('AD_Integration_additional_user_attributes');
			$this->_usermeta_empty_overwrite	= (bool)get_option('AD_Integration_usermeta_empty_overwrite');
			$this->_show_attributes				= (bool)get_option('AD_Integration_show_attributes');
			$this->_attributes_to_show			= get_option('AD_Integration_attributes_to_show');
			$this->_syncback					= (bool)get_option('AD_Integration_syncback');
			$this->_syncback_use_global_user	= (bool)get_option('AD_Integration_syncback_use_global_user');
			$this->_syncback_global_user		= get_option('AD_Integration_syncback_global_user');
			$this->_syncback_global_pwd			= get_option('AD_Integration_syncback_global_pwd');
			
			// Bulk Import (7)
			$this->_bulkimport_enabled			= (bool)get_option('AD_Integration_bulkimport_enabled');
			$this->_bulkimport_authcode 		= get_option('AD_Integration_bulkimport_authcode');
			$this->_bulkimport_new_authcode		= (bool)get_option('AD_Integration_bulkimport_new_authcode');
			$this->_bulkimport_security_groups	= get_option('AD_Integration_bulkimport_security_groups');
			$this->_bulkimport_user				= get_option('AD_Integration_bulkimport_user');
			$this->_bulkimport_pwd				= get_option('AD_Integration_bulkimport_pwd');
			$this->_disable_users				= (bool)get_option('AD_Integration_disable_users');
			
		}
	}
	
	
	/**
	 * Get array of descriptions for default AD attributes
	 * This function is needed for i18n.
	 * @return array 
	 */
	protected function _get_attribute_descriptions() {
		$descriptions = array();
		
		// General
	    $descriptions['cn'] = __('Common Name','ad-integration');
	    $descriptions['givenname'] = __('First name','ad-integration');
		$descriptions['initials'] = __('Initials','ad-integration');
	    $descriptions['sn'] = __('Last name','ad-integration');
		$descriptions['displayname'] = __('Display name','ad-integration');
		$descriptions['description'] = __('Description','ad-integration');
		$descriptions['physicaldeliveryofficename'] = __('Office','ad-integration');
		$descriptions['telephonenumber'] = __('Telephone number','ad-integration');
		$descriptions['mail'] = __('E-mail','ad-integration');
		$descriptions['wwwhomepage'] = __('Web Page','ad-integration');
		
		// Account
		$descriptions['samaccountname'] = __('User logon name','ad-integration');

		// Address
		$descriptions['streetaddress'] = __('Street','ad-integration');
		$descriptions['postofficebox'] = __('P.O. Box','ad-integration');
		$descriptions['l'] = __('City','ad-integration');
		$descriptions['st'] = __('State','ad-integration');
		$descriptions['postalcode'] = __('ZIP/Postal cide','ad-integration');
		$descriptions['c'] = __('Country abbreviation','ad-integration');
		$descriptions['co'] = __('Country','ad-integration');
		$descriptions['countrycode'] = __('Country code (number)','ad-integration');

		// Telephones
		$descriptions['homephone'] = __('Home','ad-integration');
		$descriptions['otherhomephone'] = __('Home (other)','ad-integration');
		$descriptions['pager'] = __('Pager','ad-integration');
		$descriptions['otherpager'] = __('Pager (other)','ad-integration');
		$descriptions['mobile'] = __('Mobile','ad-integration');
		$descriptions['othermobile'] = __('Mobile (Other)','ad-integration');
		$descriptions['facsimiletelephonenumber'] = __('Fax','ad-integration');
		$descriptions['otherfacsimiletelephonenumber'] = __('Fax (other)','ad-integration');
		$descriptions['ipphone'] = __('IP Phone','ad-integration');
		$descriptions['otheripphone'] = __('IP Phone (other)','ad-integration');
		$descriptions['info'] = __('Notes','ad-integration');
		
		// Organization
		$descriptions['title'] = __('Title','ad-integration');
		$descriptions['department'] = __('Department','ad-integration');
		$descriptions['company'] = __('Company','ad-integration');
		$descriptions['manager'] = __('Manager','ad-integration');
		$descriptions['directreports'] = __('Direct reports','ad-integration');
		
		return $descriptions;
		
	}
	
	/**
	 * Get array of descriptions for default AD attributes
	 * plus additional user defined attributes
	 * 
	 * @return array descriptions in associative array
	 * @deprecated
	 */
	protected function _get_all_attribute_descriptions()
	{
		// get descriptions for default AD attributes first
		$descriptions = $this->_get_attribute_descriptions();
			
		// and now for additional AD attributes to show
		if (trim($this->_attributes_to_show) != '') {
			$lines = explode("\n", $this->_attributes_to_show);
			foreach ($lines AS $line) {
				$parts = explode(":", $line, 2); // limit is important here
				$attribute = trim($parts[0]); 
				$description = '';
				if ($attribute != '') {
					if (isset($parts[1])) {
						// remove possible sync flag
						$part = trim($parts[1]);
						if (substr($part,-2) == ':*') {
							$description = substr($part,0,-2);
						} else {
							$description = $part;
						}
					}
					if ($description == '') {
						if (isset($descriptions[$attribute])) {
							$description = $descriptions[$attribute];
						} else {
							$description = $attribute;
						}
					}
					$descriptions[$attribute] = $description;
				}
			}
		}
		return $descriptions;
	}
	
		
	
	/**
	 * Get list list of attributes to load from AD (default + additional)
	 * 
	 * @return array all attributes to load
	 */
	protected function _get_user_attributes()
	{
		// default attributes
		$attributes = $this->_default_user_attributes;
		
		// additional attributes
		if (trim($this->_additional_user_attributes) != '') {
			$lines = explode("\n", str_replace("\r",'',$this->_additional_user_attributes));
			foreach ($lines AS $line) {
				$parts = explode(":",$line);
				if ($parts[0] != '') {
					if (!in_array($parts[0], $attributes)) {
						$attributes[] = $parts[0];
					}
				}
			}
		}
		return $attributes;
	}
	
	
	/**
	 * Get associative array of attributes, types, metakeys, descriptions, sync flag and show flag for AD attributes
	 *  
	 * @return array
	 */
	protected function _get_attributes_array()
	{
		$attributes = array();
		
		// default attributes
		// type is always string, meta key is set to ADI_<attribute> and description is loaded
		
		$descriptions = $this->_get_attribute_descriptions();  // default descriptions
		foreach($this->_default_user_attributes AS $attribute) {
			$attributes[$attribute]['type'] = 'string';
			$attributes[$attribute]['metakey'] = $this->_usermeta_prefix.$attribute;
			if (isset($descriptions[$attribute])) {
				$attributes[$attribute]['description'] = $descriptions[$attribute];
			} else {
				$attributes[$attribute]['description'] = $attribute;
			}
			$attributes[$attribute]['sync'] = false;
			$attributes[$attribute]['show'] = false;
		}
		
		// additional attributes
		// type and metakey
		if (trim($this->_additional_user_attributes) != '') {
			$lines = explode("\n", str_replace("\r",'',$this->_additional_user_attributes));
			foreach ($lines AS $line) {
				$parts = explode(":",$line);
				if (isset($parts[0]) && (trim($parts[0]) != '')) {
					
					$attribute = trim($parts[0]);
					
					// type
					if (!isset($parts[1])) {
						 $parts[1] = 'string';
					} else {
						$parts[1] = strtolower(trim($parts[1]));
					}
					if (!in_array($parts[1], array('string','list','integer','bool','time','timestamp','octet'))) {
						$parts[1] = 'string';
					}
					$attributes[$attribute]['type'] = $parts[1];
					
					// meta key
					if (!isset($parts[2])) {
						$parts[2] = $this->_usermeta_prefix.$attribute;
					} else {
						$parts[2] = trim($parts[2]);
					}
					$attributes[$attribute]['metakey'] = $parts[2];
					
					// description
					if (isset($descriptions[$attribute])) {
						$attributes[$attribute]['description'] = $descriptions[$attribute];
					} else {
						$attributes[$attribute]['description'] = $attribute;
					}
					
					$attributes[$attribute]['sync'] = false;
					$attributes[$attribute]['show'] = false;
				}
			}
		}
		
		// and now for additional AD attributes to show
		if (trim($this->_attributes_to_show) != '') {
			$lines = explode("\n", $this->_attributes_to_show);
			foreach ($lines AS $line) {
				$parts = explode(":", $line, 2); // limit is important here
				$attribute = trim($parts[0]); 
				$description = '';
				$sync = false;
				if ($attribute != '') {
					if (isset($parts[1])) {
						// remove possible sync flag
						$part = trim($parts[1]);
						if (substr($part,-2) == ':*') {
							$description = substr($part,0,-2);
							$sync = true;
						} else {
							$description = $part;
						}
					}
					if ($description == '') {
						if (isset($descriptions[$attribute])) {
							$description = $descriptions[$attribute];
						} else {
							$description = $attribute;
						}
					}
					$attributes[$attribute]['description'] = $description;				
					$attributes[$attribute]['sync'] = $sync;
					$attributes[$attribute]['show'] = true;
				}
			}
		}
		
		return $attributes;
	}

	
	/**
	 * Returns formatted value according to attribute type
	 * 
	 * @param string $type (string, integer, bool, time, timestamp, octet)
	 * @param mixed $value
	 * @return mixed formatted value
	 */
	protected function _format_attribute_value($type, $value)
	{
		switch ($type) {
			case 'string': return $value;
			case 'integer': return (int)$value;
			case 'bool': return (bool)$value;
			case 'time': // ASN.1 GeneralizedTime
				$timestamp = mktime(substr($value,8,2),substr($value,10,2),substr(12,2),substr($value,4,2),substr($value,6,2),substr($value,0,4));
				if (substr($value, -1) == 'Z') {
					$offset = get_option('gmt_offset',0) * 3600;
				} else {
					$offset = 0;
				}
				return date_i18n(get_option('date_format','Y-m-d').' / '.get_option('time_format','H:i:s'), $timestamp + $offset, true); 
			case 'timestamp': 
				$timestamp = ($value / 10000000) - 11644473600 + get_option('gmt_offset',0) * 3600; 
				return date_i18n(get_option('date_format','Y-m-d').' / '.get_option('time_format','H:i:s'), $timestamp, true);
			case 'octet': return base64_encode($value);
		}
		return $value;
	}
	
	
	/**
	 * Returns true if the user is an ADI User
	 * 
	 * @param integer $user_id
	 */
	protected function _is_adi_user($user_id)
	{
		return (get_user_meta($user_id, 'adi_samaccountname', true) != ''); 
	}
		
	
	/**
	 * Saves the options to the sitewide options store. This is only needed for WPMU.
	 * 
	 * @param $arrPost the POST-Array with the new options
	 * @return unknown_type
	 */
	protected function _save_wpmu_options($arrPost) {
		
 		if (IS_WPMU) {

 			if ( !empty( $arrPost['AD_Integration_additional_user_attributes'] ) )
			 	update_site_option('AD_Integration_additional_user_attributes', $arrPost['AD_Integration_additional_user_attributes']);
 			
			if ( !empty( $arrPost['AD_Integration_auto_create_user'] ) )
			 	update_site_option('AD_Integration_auto_create_user', (bool)$arrPost['AD_Integration_auto_create_user']);
			 
			if ( !empty( $arrPost['AD_Integration_auto_update_user'] ) )
			 	update_site_option('AD_Integration_auto_update_user', (bool)$arrPost['AD_Integration_auto_update_user']);
			
			 	if ( !empty( $arrPost['AD_Integration_auto_update_description'] ) )
			 	update_site_option('AD_Integration_auto_update_description', (bool)$arrPost['AD_Integration_auto_update_description']);
			 
			if ( !empty( $arrPost['AD_Integration_account_suffix'] ) )
			 	update_site_option('AD_Integration_account_suffix', $arrPost['AD_Integration_account_suffix']);
			 
			if ( !empty( $arrPost['AD_Integration_append_suffix_to_new_users'] ) )
			 	update_site_option('AD_Integration_append_suffix_to_new_users', $arrPost['AD_Integration_append_suffix_to_new_users']);

 			if ( !empty( $arrPost['AD_Integration_attributes_to_show'] ) )
			 	update_site_option('AD_Integration_attributes_to_show', $arrPost['AD_Integration_attributes_to_show']);
			 	
			if ( !empty( $arrPost['AD_Integration_domain_controllers'] ) )
			 	update_site_option('AD_Integration_domain_controllers', $arrPost['AD_Integration_domain_controllers']);
			 
			if ( !empty( $arrPost['AD_Integration_base_dn'] ) )
			 	update_site_option('AD_Integration_base_dn', $arrPost['AD_Integration_base_dn']);
			 
			if ( !empty( $arrPost['AD_Integration_port'] ) )
			 	update_site_option('AD_Integration_port', $arrPost['AD_Integration_port']);
			 
			if ( !empty( $arrPost['AD_Integration_use_tls'] ) )
			 	update_site_option('AD_Integration_use_tls', $arrPost['AD_Integration_use_tls']);
			 
			if ( !empty( $arrPost['AD_Integration_default_email_domain'] ) )
			 	update_site_option('AD_Integration_default_email_domain', $arrPost['AD_Integration_default_email_domain']);
			 
			if ( !empty( $arrPost['AD_Integration_authorize_by_group'] ) )
			 	update_site_option('AD_Integration_authorize_by_group', (bool)$arrPost['AD_Integration_authorize_by_group']);
			 
			if ( !empty( $arrPost['AD_Integration_authorization_group'] ) )
			 	update_site_option('AD_Integration_authorization_group', $arrPost['AD_Integration_authorization_group']);
			 
			if ( !empty( $arrPost['AD_Integration_role_equivalent_groups'] ) )
			 	update_site_option('AD_Integration_role_equivalent_groups', $arrPost['AD_Integration_role_equivalent_groups']);
			 
			if ( !empty( $arrPost['AD_Integration_max_login_attempts'] ) )
			 	update_site_option('AD_Integration_max_login_attempts', (int)$arrPost['AD_Integration_max_login_attempts']);
			 
			if ( !empty( $arrPost['AD_Integration_block_time'] ) )
			 	update_site_option('AD_Integration_block_time', (int)$arrPost['AD_Integration_block_time']);
			 
			if ( !empty( $arrPost['AD_Integration_user_notification'] ) )
			 	update_site_option('AD_Integration_user_notification', (bool)$arrPost['AD_Integration_user_notification']);
			 
			if ( !empty( $arrPost['AD_Integration_admin_notification'] ) )
			 	update_site_option('AD_Integration_admin_notification', (bool)$arrPost['AD_Integration_admin_notification']);
			 
			if ( !empty( $arrPost['AD_Integration_admin_email'] ) )
			 	update_site_option('AD_Integration_admin_email', $arrPost['AD_Integration_admin_email']);
			 
			if ( !empty( $arrPost['AD_Integration_display_name'] ) )
			 	update_site_option('AD_Integration_display_name', $arrPost['AD_Integration_display_name']);
			 
			if ( !empty( $arrPost['AD_Integration_enable_password_change'] ) )
				update_site_option('AD_Integration_enable_password_change', $arrPost['AD_Integration_enable_password_change']);
				
			if ( !empty( $arrPost['AD_Integration_enable_lost_password_recovery'] ) )
				update_site_option('AD_Integration_enable_lost_password_recovery', $arrPost['AD_Integration_enable_lost_password_recovery']);

			if ( !empty( $arrPost['AD_Integration_show_attributes'] ) )
				update_site_option('AD_Integration_show_attributes', $arrPost['AD_Integration_show_attributes']);
				
			if ( !empty( $arrPost['AD_Integration_usermeta_empty_overwrite'] ) )
				update_site_option('AD_Integration_usermeta_empty_overwrite', $arrPost['AD_Integration_usermeta_empty_overwrite']);				
				
			if ( !empty( $arrPost['AD_Integration_no_random_password'] ) )				
				update_site_option('AD_Integration_no_random_password', (bool)$arrPost['AD_Integration_no_random_password']);

			if ( !empty( $arrPost['AD_Integration_auto_update_password'] ) )				
				update_site_option('AD_Integration_auto_update_password', (bool)$arrPost['AD_Integration_auto_update_password']);
				
			if ( !empty( $arrPost['AD_Integration_syncback'] ) )				
				update_site_option('AD_Integration_syncback', (bool)$arrPost['AD_Integration_syncback']);

			if ( !empty( $arrPost['AD_Integration_syncback_use_global_user'] ) )				
				update_site_option('AD_Integration_syncback_use_global_user', (bool)$arrPost['AD_Integration_syncback_use_global_user']);

			if ( !empty( $arrPost['AD_Integration_syncback_global_user'] ) )				
				update_site_option('AD_Integration_syncback_global_user', $arrPost['AD_Integration_syncback_global_user']);
				
			if ( !empty( $arrPost['AD_Integration_syncback_global_pwd'] ) )				
				update_site_option('AD_Integration_syncback_global_pwd', $arrPost['AD_Integration_syncback_global_pwd']);
				
				
			// let's load the new values
			$this->_load_options();
		}
	}
	
	/**
	 * Determine the display_name to be stored in WP database.
	 * 
	 * @param $username the username used to login
	 * @param $userinfo the array with data returned from AD
	 * @return string display_name
	 */
	protected function _get_display_name_from_AD($username, $userinfo) {
		
		$display_name = '';
		
		if (($this->_display_name == '') OR ($this->_display_name == 'sAMAccountName')) {
			return $username;
		}

		if ($this->_display_name == 'givenname sn') {
			if (isset($userinfo['givenname'][0]) && isset($userinfo['sn'][0])) {
				$display_name = $userinfo['givenname'][0].' '.$userinfo['sn'][0];
			}
		 } else {
			if (isset($userinfo[$this->_display_name][0])) {
				$display_name = $userinfo[$this->_display_name][0];
			}
		 }
		
		if ($display_name == '') {
			return $username;
		} else {
			return $display_name;
		}
	}
	
	/**
	 * Stores the username and the current time in the db.
	 * 
	 * @param $username
	 * @return query result
	 */
	protected function _store_failed_login($username) {
		global $wpdb;
		
		$this->_log(ADI_LOG_WARN,'storing failed login for user "'.$username.'"');
		$table_name = ADIntegrationPlugin::global_db_prefix() . ADIntegrationPlugin::TABLE_NAME;
		
		$sql = "INSERT INTO $table_name (user_login, failed_login_time) VALUES ('" . $wpdb->escape($username)."'," . time() . ")";
		$result = $wpdb->query($sql);
		
	}
	
	
	/**
	 * Determines the number of failed login attempts of specific user within a specific time from now to the past.
	 * 
	 * @param $username
	 * @param $seconds number of seconds
	 * @return number of failed login attempts  
	 */
	protected function _get_failed_logins_within_block_time($username) {
		global $wpdb;
		$table_name = ADIntegrationPlugin::global_db_prefix() . ADIntegrationPlugin::TABLE_NAME;
		$time = time() - (int)$this->_block_time;
		
		$sql = "SELECT count(*) AS count from $table_name WHERE user_login = '".$wpdb->escape($username)."' AND failed_login_time >= $time";
		return $wpdb->get_var($sql);
	}
	
	
	/**
	 * Deletes entries from store where the time of failed logins is more than the specified block time ago.
	 * Deletes also all entries of a user, if its username is given . 
	 *  
	 * @param $username
	 * @return query result
	 */
	protected function _cleanup_failed_logins($username = NULL) {
		global $wpdb;
		
		$this->_log(ADI_LOG_NOTICE,'cleaning up failed logins for user "'.$username.'"');
		$table_name = ADIntegrationPlugin::global_db_prefix() . ADIntegrationPlugin::TABLE_NAME;
		$time = time() - $this->_block_time;
		
		$sql = "DELETE FROM $table_name WHERE failed_login_time < $time";
		if ($username != NULL) {
			$sql .= " OR user_login = '".$wpdb->escape($username)."'"; 
		}
		
		$results = $wpdb->query($sql);
	}

	
	/**
	 * Get the rest of the time an account is blocked. 
	 * 
	 * @param $username
	 * @return int seconds the account is blocked, or 0
	 */
	protected function _get_rest_of_blocking_time($username) {
		global $wpdb;
		
		$table_name = ADIntegrationPlugin::global_db_prefix() . ADIntegrationPlugin::TABLE_NAME;
		
		$sql = "SELECT max(failed_login_time) FROM $table_name WHERE user_login = '".$wpdb->escape($username)."'";
		$max_time = $wpdb->get_var($sql);
		
		if ($max_time == NULL ) {
			return 0;
		}
		return ($max_time + $this->_block_time) - time();
		
	}
	

	/**
	 * Generate a random password.
	 * 
	 * @param int $length Length of the password
	 * @return password as string
	 */
	protected function _get_password($length = 10) {
		return substr(md5(uniqid(microtime())), 0, $length);
	}

	
	/**
	 * Create a new WordPress account for the specified username.
	 * 
	 * @param string $username
	 * @param array $userinfo
	 * @param string $display_name
	 * @param string $role
	 * @param string $password
	 * @return integer user_id
	 */
	protected function _create_user($username, $userinfo, $display_name, $role = '', $password = '', $bulkimport = false)
	{
		global $wp_version;
		
		
		$info = $this->_create_info_array($userinfo);
		
		// get UPN suffix
		$parts = explode('@',$info['userprincipalname']);
		if (isset($parts[1])) {
			$account_suffix = '@'.$parts[1];
		} else {
			$account_suffix = '';
		}
		
		
		if (isset($info['mail'])) {
			$email = $info['mail'];
		} else {
			$email = '';
		}
		
		if ( $info['mail'] == '' ) 
		{
			if (trim($this->_default_email_domain) != '') {
				$email = $username . '@' . $this->_default_email_domain;
			} else {
				if (strpos($username, '@') !== false) {
					$email = $username;
				}
			}
		}
				
		// append account suffix to new users? 
		if ($this->_append_suffix_to_new_users) {
			$username .= $account_suffix;
		}
		
		$this->_log(ADI_LOG_NOTICE,"Creating user '$username' with following data:\n".
					  "- email         : ".$email."\n".
					  "- first name    : ".$info['givenname']."\n".
					  "- last name     : ".$info['sn']."\n".
					  "- display name  : $display_name\n".
					  "- account suffix: $account_suffix\n".
					  "- role          : $role");
		

		// set local password if needed or on Bulk Import
		if (!$this->_no_random_password || ($bulkimport === true)) {
			$password = $this->_get_password();
			$this->_log(ADI_LOG_DEBUG,'Setting random password.');
		} else {
			$this->_log(ADI_LOG_DEBUG,'Setting local password to the used for this login.');
		}
		
		if (version_compare($wp_version, '3.1', '<')) {
			require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'registration.php');
		}
		
		if ($this->_duplicate_email_prevention == ADI_DUPLICATE_EMAIL_ADDRESS_ALLOW) {
			if (!defined('WP_IMPORTING')) {
				define('WP_IMPORTING',true); // This is a dirty hack. See wp-includes/registration.php
			}
		}
		
		if ($this->_duplicate_email_prevention == ADI_DUPLICATE_EMAIL_ADDRESS_CREATE) {
			$new_email = $this->_create_non_duplicate_email($email);
			if ($new_email !== $email) {
				$this->_log(ADI_LOG_NOTICE, "Duplicate email address prevention: Email changed from $email to $new_email.");
			}
			$email = $new_email;
		}
		
		// Here we go!
		$return = wp_create_user($username, $password, $email);

		// log errors
		if (is_wp_error($return)) {
   			$this->_log(ADI_LOG_ERROR, $return->get_error_message());
		}
		
		$user_id = username_exists($username);
		$this->_log(ADI_LOG_NOTICE,'- user_id       : '.$user_id);
		if ( !$user_id ) {
			// do not die on bulk import
			if (!$bulkimport) {
				$this->_log(ADI_LOG_FATAL,'Error creating user.');
				die("Error creating user!");
			} else {
				$this->_log(ADI_LOG_ERROR,'Error creating user.');
				return false;
			}
		} else {
			update_user_meta($user_id, 'first_name', $info['givenname']);
			update_user_meta($user_id, 'last_name', $info['sn']);
			if ($this->_auto_update_description) {
				update_user_meta($user_id, 'description', $info['description']);
			}
			
			// set display_name
			if ($display_name != '') {
				$return = wp_update_user(array('ID' => $user_id, 'display_name' => $display_name));
			}
			
			// set role
			if ( $role != '' ) 
			{
				$roles = new WP_Roles();
				if ($roles->is_role($role)) { // Updates role only if role exists (Issue #0051)
					wp_update_user(array('ID' => $user_id, 'role' => $role));
				} else {
					$this->_log(ADI_LOG_WARN, 'Role "' . $role . '" currently does not exist in WordPress. Role of "' . $username . '" is not set.');
				}
			}
			
			// Important for SyncBack: store account suffix in user meta
			update_user_meta($user_id, 'ad_integration_account_suffix', $account_suffix);
	
			
			// Update User Meta
			if ($this->_write_usermeta === true) {
				$attributes = $this->_get_attributes_array(); // load attribute informations: type, metakey, description
				foreach($info AS $attribute => $value) {
					// conversion/formatting
					$type = $attributes[$attribute]['type'];
					$metakey = $attributes[$attribute]['metakey'];
					$value = $this->_format_attribute_value($type, $value);
					
					if ((trim($value) != '') || ($this->_usermeta_empty_overwrite == true)) {
						$this->_log(ADI_LOG_DEBUG,"$attribute = $value / type = $type / meta key = $metakey");
						
						// store it
						update_user_meta($user_id, $metakey, $value);
					} else {
						$this->_log(ADI_LOG_DEBUG,"$attribute is empty. Local value of meta key $metakey left unchanged.");
					}
				}
			}
		}

		
		return $user_id;
	}
	
	
	/**
	 * Updates a specific Wordpress user account
	 * 
	 * @param string $username
	 * @param array $userinfo
	 * @param string $display_name
	 * @param string $role
	 * @param string $password
	 * @return integer user_id
	 */
	protected function _update_user($username, $userinfo, $display_name='', $role = '', $password = '', $bulkimport = false)
	{
		global $wp_version;
		
		$info = $this->_create_info_array($userinfo);
		
		// get UPN suffix
		$parts = explode('@',$info['userprincipalname']);
		if (isset($parts[1])) {
			$account_suffix = '@'.$parts[1];
		} else {
			$account_suffix = '';
		}
		
		
		if (isset($info['mail'])) {
			$email = $info['mail'];
		} else {
			$email = '';
		}
		
		if ( $email == '' ) 
		{
			if (trim($this->_default_email_domain) != '') {
				$email = $username . '@' . $this->_default_email_domain;
			} else {
				if (strpos($username, '@') !== false) {
					$email = $username;
				}
			}
		}
		
		if ($this->_append_suffix_to_new_users) {
			$username .= $account_suffix;
		}
		
		$this->_log(ADI_LOG_NOTICE,'Updating user "'.$username."\" with following data:\n".
					  "- email         : $email\n".
					  "- first name    : ".$info['givenname']."\n".
					  "- last name     : ".$info['sn']."\n".
					  "- display name  : $display_name\n".
					  "- account suffix: $account_suffix\n".
					  "- role          : $role");
		
		if (version_compare($wp_version, '3.1', '<')) {
			require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'registration.php');
		}
		
		$user_id = username_exists($username);
		if ($user_id === false) {
			return false;
		}
		
		$this->_log(ADI_LOG_NOTICE,'- user_id       : '.$user_id);
		if ( !$user_id ) {
			$this->_log(ADI_LOG_FATAL,'Error updating user.');
			die('Error updating user!');
		} else {
			update_user_meta($user_id, 'first_name', $info['givenname']);
			update_user_meta($user_id, 'last_name', $info['sn']);
			if ($this->_auto_update_description) {
				update_user_meta($user_id, 'description', $info['description']);
			}
			
			// set display_name
			if ($display_name != '') {
				wp_update_user(array('ID' => $user_id, 'display_name' => $display_name));
			}
			
			// set role
			if ( $role != '' ) 
			{
				$roles = new WP_Roles();
				if ($roles->is_role($role)) { // Updates role only if role exists
					wp_update_user(array('ID' => $user_id, 'role' => $role));
				} else {
					$this->_log(ADI_LOG_WARN, 'Role "' . $role . '" currently does not exist in WordPress. Role of "' . $username . '" is not set.');
				}
			}
			
			// set email if not empty
			if ( $email != '' ) 
			{
				// if we allow duplicate email addresses just set it
				if ($this->_duplicate_email_prevention == ADI_DUPLICATE_EMAIL_ADDRESS_ALLOW) {
					$return = wp_update_user(array('ID' => $user_id, 'user_email' => $email));
				} else {
				
					// duplicate email addresses disallowed
					// if we don't have a conflict, just set it
					if (!email_exists($email)) {
						$return = wp_update_user(array('ID' => $user_id, 'user_email' => $email));
					} else {

						// we have a conflict, so only update when the "create" option is set
						if ($this->_duplicate_email_prevention == ADI_DUPLICATE_EMAIL_ADDRESS_CREATE) { 
							$userdata = get_userdata($user_id);

							// only update if the email is not already set
							if ($userdata->user_email == '') {  
								$new_email = $this->_create_non_duplicate_email($email);
								$this->_log(ADI_LOG_NOTICE, "Duplicate email address prevention: Email changed from $email to $new_email.");
								$return = wp_update_user(array('ID' => $user_id, 'user_email' => $new_email));
							} else { 
								$this->_log(ADI_LOG_NOTICE, "Duplicate email address prevention: Existing email " . $userdata->user_email . " left unchanged.");
							}
						}
					}
				}
			}
		}
		
		
		// Update password if needed (NOT on Bulk Import)
		if (($this->_auto_update_password === true) && ($bulkimport === false)) {
			$this->_log(ADI_LOG_NOTICE,'Setting local password to the one used for this login.');
			@wp_update_user(array('ID' => $user_id, 'user_pass' => $password)); // can lead to notices so we use @
		}
		
		
		// Important for SyncBack: store account suffix in user meta
		update_user_meta($user_id, 'ad_integration_account_suffix', $account_suffix);
		
		// Update User Meta
		if ($this->_write_usermeta === true) {
			$attributes = $this->_get_attributes_array(); // load attribute informations: type, metakey, description
			foreach($info AS $attribute => $value) {
				// conversion/formatting
				$type = $attributes[$attribute]['type'];
				$metakey = $attributes[$attribute]['metakey'];
				$value = $this->_format_attribute_value($type, $value);
				
				if ((trim($value) != '') || ($this->_usermeta_empty_overwrite == true)) {
					$this->_log(ADI_LOG_DEBUG,"$attribute = $value / type = $type / meta key = $metakey");
					
					// store it
					update_user_meta($user_id, $metakey, $value);
					
				} else {
					$this->_log(ADI_LOG_DEBUG,"$attribute is empty. Local value of meta key $metakey left unchanged.");
				}
			}
		}
		
		
		// log errors
		if (isset($return)) {
			if (is_wp_error($return)) {
	   			$this->_log(ADI_LOG_ERROR, $return->get_error_message());
			}
		}
		
		return $user_id;
	}
	
	
	/**
	 * Disable a user by setting adi_user_disabled to true in usermeta and changing the email
	 * 
	 * @param int $user_id User ID 
	 * @param string $reason Reason for disabling the user
	 */
	protected function _disable_user($user_id, $reason)
	{
		$userdata = get_userdata($user_id);
		if (strpos($userdata->user_email,'DISABLED-USER-') !== 0) {
			$new_email = 'DISABLED-USER-' . $userdata->user_email;
		} else {
			$new_email = $userdata->user_email;
		}
		
		update_user_meta($user_id, 'adi_user_disabled', true); // set disabled flag
		update_user_meta($user_id, 'adi_user_disabled_reason', $reason); // store reason
		
		// Do not overwrite previously stored email
		if (get_user_meta($user_id, 'adi_user_disabled_email', true) == '') {
			update_user_meta($user_id, 'adi_user_disabled_email', $userdata->user_email); // store email in meta
		}
		
		wp_update_user( array ('ID' => $user_id, 'user_email' => $new_email) ) ; // change email of user
		
		// DIRTY: if we come from profile page, we have to change to POST data.
		if (isset($_POST['email'])) {
			$_POST['email'] = $new_email;
		}
		
	}

	
	/**
	 * Enables a user by setting adi_user_disabled to false in usermeta and restoring the email
	 * 
	 * @param int $user_id User ID
	 */
	protected function _enable_user($user_id)
	{
		update_user_meta($user_id, 'adi_user_disabled', false);  // remove disabled flag
		update_user_meta($user_id, 'adi_user_disabled_reason', '');  // remove reaon
		
		$email = get_user_meta($user_id, 'adi_user_disabled_email', true); // fetch stored email from meta

		// Only restore email if it has been previously stored
		if ($email != '') {
			wp_update_user( array ('ID' => $user_id, 'user_email' => $email) ) ; // restore email
		}
		
		delete_user_meta($user_id, 'adi_user_disabled_email'); // delete stored email from meta
		
		// DIRTY: if we come from profile page, we have to change the POST data.
		if (isset($_POST['email'])) {
			$_POST['email'] = $email;
		}		
	}

	
	/**
	 * Returns the given email address or a newly created so no 2 users
	 * can have the same email address.
	 * 
	 * @param $email original email address
	 * @return unique email address
	 */
	protected function _create_non_duplicate_email($email)
	{

		if (!email_exists($email)) {
			return $email;
		}
		
		// Ok, lets create a new email address that does not already exists in the database
		$arrEmailParts = split('@',$email);
		$counter = 1;
		$ok = false;
		while ($ok !== true) {
			$email = $arrEmailParts[0].$counter.'@'.$arrEmailParts[1];
			$ok = !email_exists($email);
			$counter++;	
		}
		return $email;
	}
	
	
	/**
	 * Build an array with the values for AD attributes
	 * 
	 * @param array $userinfo
	 * @return array 
	 */
	protected function _create_info_array($userinfo)
	{
		$info = array();
		foreach($this->_all_user_attributes AS $attribute) {
			$attribute = strtolower($attribute);
			if (isset($userinfo[$attribute])) {
				if (isset($userinfo[$attribute]['count'])) {
					unset($userinfo[$attribute]['count']);
					$info[$attribute] = implode("\n", $userinfo[$attribute]);
				} else {
					$info[$attribute] = $userinfo[$attribute];
				}
			} else {
				$info[$attribute] = '';
			}
		}
		return $info;
	}
		
	
	
	/**
	 * Checks if the user is member of the group(s) allowed to login
	 * 
	 * @param $username
	 * @return boolean
	 */
	protected function _check_authorization_by_group($username) {
		
		// Debugging: show all groups the user is a member of
		if (defined('WP_DEBUG')) {
			$this->_log(ADI_LOG_DEBUG,"USER GROUPS:".print_r($this->_adldap->user_groups($username),true));
		}
		
		if ($this->_authorize_by_group) {
			$authorization_groups = explode(';', $this->_authorization_group);
			foreach ($authorization_groups as $authorization_group) {
				if ($this->_adldap->user_ingroup($username, $authorization_group, true)) {
					$this->_log(ADI_LOG_NOTICE,'Authorized by membership of group "'.$authorization_group.'"');
					return true;
				}
			}
			$this->_log(ADI_LOG_WARN,'Authorization by group failed. User is not authorized.');
			return false;
		} else {
			return true;
		}
	}
	
	
	/**
	 * Get the first matching role from the list of role equivalent groups the user belongs to.
	 * 
	 * @param $ad_username 
	 * @return string matching role
	 */
	protected function _get_user_role_equiv($ad_username) {
		
		$role_equiv_groups = explode(';', $this->_role_equivalent_groups);
		
		$user_role = '';
		foreach ($role_equiv_groups as $whatever => $role_group)
		{
				$role_group = explode('=', $role_group);
				if ( count($role_group) != 2 )
				{
					continue;
				}
				$ad_group = $role_group[0];
				
				$corresponding_role = $role_group[1];
				if ( $this->_adldap->user_ingroup($ad_username, $ad_group, true ) )
				{
					$user_role = $corresponding_role;
					break;
				}
		}
		return $user_role;
	}
	
	
	/**
	 * Generate a new Auth Code of 20 characters and store it
	 */
	protected function _generate_authcode()
	{
		$length = 20;
	    $chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
	    $code = '';    
	    for ($x = 0; $x < $length; $x++) {
	        $code .= $chars[mt_rand(0, strlen($chars)-1)];
	    }
		$this->_bulkimport_authcode =  $code;
		
		// Save authcode
		if (IS_WPMU) {
			update_site_option('AD_Integration_bulkimport_authcode',$code);
		} else {
			update_option('AD_Integration_bulkimport_authcode',$code);
		}
		$this->_log(ADI_LOG_NOTICE,'New Auth Code for Bulk Import generated.');
	}
		
	
	/**
	 * Send an email to the user who's account is blocked
	 * 
	 * @param $username string
	 * @return unknown_type
	 */
	protected function _notify_user($username)
	{
		// if auto creation is enabled look for the user in AD 
		if ($this->_auto_create_user) {
			
			$userinfo = $this->_adldap->user_info($username, array("sn", "givenname", "mail"));
			if ($userinfo) {
				$userinfo = $userinfo[0];
				$email = $userinfo['mail'][0];
				$first_name = $userinfo['givenname'][0];
				$last_name = $userinfo['sn'][0];	
			} else { 
				return false;
			}
		} else {
			// auto creation is disabled, so look for the user in local database
			if (version_compare($wp_version, '3.1', '<')) {
				require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'registration.php');
			}
			
			$user_id = username_exists($username);
			if ($user_id) {
				$user_info = get_userdata($user_id);
				$last_name = $user_info->last_name;
				$first_name = $user_info->first_name;
				$email = $user_info->user_email;
			} else {
				return false;
			}
		}

		// do we have a correct email address?
		if (is_email($email)) {

			// Load up the localization file if we're using WordPress in a different language
			// Place it in this plugin's folder and name it "ad-integration-[value in wp-config].mo"
			load_plugin_textdomain( 'ad-integration', false, dirname( plugin_basename( __FILE__ ) ) );
			
			$blog_url = get_bloginfo('url');
			$blog_name = get_bloginfo('name');
			$blog_domain = preg_replace ('/^(http:\/\/)(.+)\/.*$/i','$2', $blog_url);
			

			$subject = '['.$blog_name.'] '.__('Account blocked','ad-integration');
			$body = sprintf(__('Someone tried to login to %s (%s) with your username (%s) - but in vain. For security reasons your account is now blocked for %d seconds.','ad-integration'), $blog_name, $blog_url, $username, $this->_block_time);
			$body .= "\n\r";
			$body .= __('THIS IS A SYSTEM GENERATED E-MAIL, PLEASE DO NOT RESPOND TO THE E-MAIL ADDRESS SPECIFIED ABOVE.','ad-integration');
			
			$header = 'From: "WordPress" <wordpress@'.$blog_domain.">\r\n";
			return wp_mail($email, $subject, $body, $header);
		} else {
			return false;
		}
	}

	/**
	 * Notify administrator(s) by e-mail if an account is blocked
	 * 
	 * @param $username username of the blocked account
	 * @return boolean false if no e-mail is sent, true on success
	 */
	protected function _notify_admin($username)
	{
		$arrEmail = array(); // list of recipients
		
		if ($this->_admin_notification) {
			$email = $this->_admin_email;
			
			// Should we use Blog-Administrator's e-mail
			if (trim($email) == '') {
				// Is this an e-mail address?
				if (is_email($email)) {
					$arrEmail[0] = trim(get_bloginfo('admin_email '));
				}
			} else {
				// Using own list of notification recipients
				$arrEmail = explode(";",$email);
				
				// remove wrong e-mail addresses from array
				for ($x=0; $x < count($arrEmail); $x++) {
					$arrEmail[$x] = trim($arrEmail[$x]); // remove possible whitespaces
					if (!is_email($arrEmail[$x])) {
						unset($arrEmail[$x]);
					}
				}
				
			}
			
			// Do we have valid e-mail addresses?
			if (count($arrEmail) > 0) {
				
				if ($this->_auto_create_user) {

					// auto creation is enabled, so look for the user in AD						
					$userinfo = $this->_adldap->user_info($username, array("sn", "givenname", "mail"));
					if ($userinfo) {
						$userinfo = $userinfo[0];
						$first_name = $userinfo['givenname'][0];
						$last_name = $userinfo['sn'][0];	
					} else { 
						return false;
					}
				} else {
					
					// auto creation is disabled, so look for the user in local database
					if (version_compare($wp_version, '3.1', '<')) {
						require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'registration.php');
					}
					$user_id = username_exists($username);
					if ($user_id) {
						$user_info = get_userdata($user_id);
						$last_name = $user_info->last_name;
						$first_name = $user_info->first_name;
					} else {
						return false;
					}
				}
				
				// Load up the localization file if we're using WordPress in a different language
				// Place it in this plugin's folder and name it "ad-integration-[value in wp-config].mo"
				load_plugin_textdomain( 'ad-integration', false, dirname( plugin_basename( __FILE__ ) ) );
				
				$blog_url = get_bloginfo('url');
				$blog_name = get_bloginfo('name');
				$blog_domain = preg_replace ('/^(http:\/\/)(.+)\/.*$/i','$2', $blog_url);

				$subject = '['.$blog_name.'] '.__('Account blocked','ad-integration');
				$body = sprintf(__('Someone tried to login to %s (%s) with the username "%s" (%s %s) - but in vain. For security reasons this account is now blocked for %d seconds.','ad-integration'), $blog_name, $blog_url, $username, $first_name, $last_name, $this->_block_time);
				$body .= "\n\r";
				$body .= sprintf(__('The login attempt was made from IP-Address: %s','ad-integration'), $_SERVER['REMOTE_ADDR']);
				$body .= "\n\r";
				$body .= __('THIS IS A SYSTEM GENERATED E-MAIL, PLEASE DO NOT RESPOND TO THE E-MAIL ADDRESS SPECIFIED ABOVE.','ad-integration');
				$header = 'From: "WordPress" <wordpress@'.$blog_domain.">\r\n";
				
			
				// send e-mails
				$blnSuccess = true;
				foreach($arrEmail AS $email)  {
					$blnSuccess = ($blnSuccess AND wp_mail($email, $subject, $body, $header));
				}
				return $blnSuccess;
				
				
			} else {
				return false;
			}
		} else {
			return false;
		}
		
		return true;
	} 
	

	/**
	 * Encrypt strings with AES/Rijndael 128 if mcrypt is available and base64 encode it.
	 *
	 * @param string $text data to encrypt
	 */
	protected function _encrypt($text) {
		if (function_exists('mcrypt_encrypt')) {
		    $iv = md5('Active-Directory-Integration'); // not nice
		    $key = substr(AUTH_SALT,0, mcrypt_get_key_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB));
		    $encrypted_text = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $text, MCRYPT_MODE_ECB, $iv);
		} else {
			$this->_log(ADI_LOG_WARN,'Encrypting: mcrypt not installed.');
			$encrypted_text = $text;
		}
		return base64_encode($encrypted_text);
	}

	
	/**
	 * base64_decode and decrypt strings with AES/Rijndael 128 if mcrypt is available.
	 *
	 * @param string $encrypted_text data to decrypt
	 */
	protected function _decrypt($encrypted_text) {
		$encrypted_text = base64_decode($encrypted_text);
		if (function_exists('mcrypt_decrypt')) {
		    $iv = md5('Active-Directory-Integration');
		    $key = substr(AUTH_SALT,0, mcrypt_get_key_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB));
		    $text = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $encrypted_text, MCRYPT_MODE_ECB, $iv);
		} else {
			$text = $encrypted_text; 
		}
		return $text;
	}
	
	
	/**
	 * Output debug informations
	 * 
	 * @param integer level
	 * @param string $notice
	 */
	protected function _log($level = 0, $info = '') {
		if ($level <= $this->_loglevel) {
			echo '[' .$level . '] '.$info."\n\r";
		}
		if (WP_DEBUG) {
			if ($fh = @fopen($this->_logfile,'a+')) {
				fwrite($fh,'[' .$level . '] '.$info."\n");
				fclose($fh);
			}
		}		
	}
		
		
	/**
	 * Show a blocking page for blocked accounts.
	 * 
	 * @param $username
	 */
	protected function _display_blocking_page($username) {
		$seconds = $this->_get_rest_of_blocking_time($username);
		
		// Load up the localization file if we're using WordPress in a different language
		// Place it in this plugin's folder and name it "ad-integration-[value in wp-config].mo"
		load_plugin_textdomain( 'ad-integration', false, dirname( plugin_basename( __FILE__ ) ) );
		
			
				?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" <?php language_attributes(); ?>>
<head>
	<title><?php bloginfo('name'); ?> &rsaquo; <?php echo $title; ?></title>
	<meta http-equiv="Content-Type" content="<?php bloginfo('html_type'); ?>; charset=<?php bloginfo('charset'); ?>" />
	<script type="text/javascript">
	var seconds = <?php echo $seconds;?>;
	function setTimer()	{
		var aktiv = window.setInterval("countdown()", 1000);
	}	

	function countdown() {
		seconds = seconds - 1;
		if (seconds > 0) {
			document.getElementById('secondsleft').innerHTML = seconds;
		} else {
			window.location.href = '<?php echo $_SERVER['REQUEST_URI']; ?>';
		}
	}
	</script>
	<?php
	wp_admin_css( 'login', true );
	wp_admin_css( 'colors-fresh', true );
	do_action('login_head'); ?>
</head>
<body class="login" onload="setTimer()">
	
	<div id="login"><h1><a href="<?php echo apply_filters('login_headerurl', 'http://wordpress.org/'); ?>" title="<?php echo apply_filters('login_headertitle', __('Powered by WordPress')); ?>"><?php bloginfo('name'); ?></a></h1>
		<div id="login_error">
			<?php _e('Account blocked for','ad-integration');?> <span id="secondsleft"><?php echo $seconds;?></span> <?php _e('seconds','ad-integration');?>.
		</div>
	</div>
</body>
</html>
<?php 
		die(); // IMPORTANT
	
	}

} // END OF CLASS
} // ENDIF


// create the needed tables on plugin activation
register_activation_hook(__FILE__,'ADIntegrationPlugin::activate');

// delete the tables on plugin deactivation
register_deactivation_hook(__FILE__,'ADIntegrationPlugin::deactivate');

// uninstall hook
if (function_exists('register_uninstall_hook')) {
	register_uninstall_hook(__FILE__, 'ADIntegrationPlugin::uninstall');
}

// Load the plugin hooks, etc.
$AD_Integration_plugin = new ADIntegrationPlugin();

?>