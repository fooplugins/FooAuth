<?php

function fooauth_create_settings() {

	//region LDAP Tab
	$tabs['ldap'] = __( 'LDAP', 'fooauth' );

	//region Service Account
	$sections['service_account'] = array(
		'tab'  => 'ldap',
		'name' => __( 'Service Account', 'fooauth' )
	);

	$settings[] = array(
		'id'      => 'ldap_username',
		'title'   => __( 'Username', 'fooauth' ),
		'type'    => 'text',
		'section' => 'service_account',
		'tab'     => 'ldap'
	);
	$settings[] = array(
		'id'      => 'ldap_password',
		'title'   => __( 'Password', 'fooauth' ),
		'type'    => 'password',
		'section' => 'service_account',
		'tab'     => 'ldap'
	);
	$settings[] = array(
		'id'      => 'ldap_domain',
		'title'   => __( 'Domain', 'fooauth' ),
		'desc'    => __( 'Fully qualified domain name', 'fooauth' ),
		'type'    => 'text',
		'section' => 'service_account',
		'tab'     => 'ldap'
	);
	//endregion

	//region Domain Controller
	$sections['domain_controller'] = array(
		'tab'  => 'ldap',
		'name' => __( 'Domain Controller', 'fooauth' )
	);
	$settings[] = array(
		'id'      => 'ldap_domain_controllers',
		'title'   => __( 'Domain Controllers', 'fooauth' ),
		'type'    => 'text',
		'desc'    => __( 'Comma separated list of domain controllers', 'fooauth' ),
		'section' => 'domain_controller',
		'tab'     => 'ldap'
	);
	$settings[] = array(
		'id'      => 'ldap_port',
		'title'   => __( 'Port', 'fooauth' ),
		'type'    => 'text',
		'section' => 'domain_controller',
		'tab'     => 'ldap'
	);
	$settings[] = array(
		'id'      => 'ldap_tls',
		'title'   => __( 'Use TLS', 'fooauth' ),
		'type'    => 'checkbox',
		'desc'    => __( 'Secure connection between Wordpress and AD servers. NOTE : To use TLS, the port must be set to 389', 'fooauth' ),
		'section' => 'domain_controller',
		'tab'     => 'ldap'
	);
	$settings[] = array(
		'id'      => 'ldap_organizational_unit',
		'title'   => __( 'Organizational Unit (Base DN)', 'fooauth' ),
		'type'    => 'text',
		'desc'    => __( 'eg. DC=sub,DC=domain,DC=com', 'fooauth' ),
		'section' => 'domain_controller',
		'tab'     => 'ldap'
	);
	$settings[] = array(
		'id'      => 'ldap_network_timeout',
		'title'   => __( 'Network Timeout', 'fooauth' ),
		'type'    => 'text',
		'section' => 'domain_controller',
		'tab'     => 'ldap'
	);
	$settings[] = array(
		'id'      => 'ldap_single_signon',
		'title'   => __( 'Allow Single Signon', 'fooauth' ),
		'type'    => 'checkbox',
		'section' => 'domain_controller',
		'tab'     => 'ldap'
	);
	//endregion
	//endregion

	//region User Tab
	$tabs['user'] = __( 'User', 'fooauth' );

	$sections['user_options'] = array(
		'tab'  => 'user',
		'name' => __( 'User Options', 'fooauth' )
	);
	$settings[] = array(
		'id'      => 'user_account_suffix',
		'title'   => __( 'Account Suffix', 'fooauth' ),
		'type'    => 'text',
		'section' => 'user_options',
		'tab'     => 'user'
	);
	$settings[] = array(
		'id'      => 'user_append_suffix',
		'title'   => __( 'Append Suffix to Username', 'fooauth' ),
		'type'    => 'checkbox',
		'desc'    => __( 'Append suffix to newly created usernames', 'fooauth' ),
		'section' => 'user_options',
		'tab'     => 'user'
	);
	$settings[] = array(
		'id'      => 'user_prevent_email_address_change',
		'title'   => __( 'Prevent users from changing their email address', 'fooauth' ),
		'type'    => 'checkbox',
		'section' => 'user_options',
		'tab'     => 'user'
	);
	$settings[] = array(
		'id'      => 'user_prevent_password_change',
		'title'   => __( 'Prevent users from changing their Wordpress password', 'fooauth' ),
		'type'    => 'checkbox',
		'section' => 'user_options',
		'tab'     => 'user'
	);
	$settings[] = array(
		'id'      => 'user_display_name',
		'title'   => __( 'Display Name', 'fooauth' ),
		'type'    => 'select',
		'choices' => array(
			'samaccountname' => __( 'Username', 'fooauth' ),
			'displayName'    => __( 'Display Name', 'fooauth' ),
			'description'    => __( 'Description', 'fooauth' ),
			'givenname'      => __( 'First Name', 'fooauth' ),
			'sn'             => __( 'Surname', 'fooauth' ),
			'givenname sn'   => __( 'First Name - Surname', 'fooauth' ),
			'cn'             => __( 'Fullname', 'fooauth' ),
			'mail'           => __( 'Email Address', 'fooauth' )
		),
		'section' => 'user_options',
		'tab'     => 'user'
	);
	$settings[] = array(
		'id'      => 'user_max_login_attempts',
		'title'   => __( 'Maximum Login Attempts', 'fooauth' ),
		'type'    => 'text',
		'section' => 'user_options',
		'tab'     => 'user'
	);
	//endregion

	//region Sync Tab
	$tabs['sync'] = __( 'Sync', 'fooauth' );

	$sections['sync_options'] = array(
		'tab'  => 'user',
		'name' => __( 'Sync Options', 'fooauth' )
	);

	$settings[] = array(
		'id'      => 'sync_auto_user_creation',
		'title'   => __( 'Automatically Create Users', 'fooauth' ),
		'type'    => 'checkbox',
		'section' => 'sync_options',
		'tab'     => 'sync'
	);
	$settings[] = array(
		'id'      => 'sync_auto_user_updates',
		'title'   => __( 'Automatically Update Users', 'fooauth' ),
		'type'    => 'checkbox',
		'section' => 'sync_options',
		'tab'     => 'sync'
	);
	$settings[] = array(
		'id'      => 'sync_import_groups',
		'title'   => __( 'Import Groups', 'fooauth' ),
		'type'    => 'checkbox',
		'section' => 'sync_options',
		'tab'     => 'sync'
	);
	$settings[] = array(
		'id'      => 'sync_default_role',
		'title'   => __( 'Default Role', 'fooauth' ),
		'type'    => 'select',
		'choices' => array(
			'admin'       => __( 'Admin', 'fooauth' ),
			'pending'     => __( 'Pending', 'fooauth' ),
			'subscriber'  => __( 'Subscriber', 'fooauth' ),
			'editor'      => __( 'Editor', 'fooauth' ),
			'contributor' => __( 'Contributor', 'fooauth' )
		),
		'desc'    => __( 'Default role new accounts should be assigned to', 'fooauth' ),
		'section' => 'sync_options',
		'tab'     => 'sync'
	);
	//endregion

	//region Authorization Tab
	$tabs['authorization'] = __( 'Authorization', 'fooauth' );

	$sections['authorization_options'] = array(
		'tab'  => 'authorization',
		'name' => __( 'Authorization Options', 'fooauth' )
	);
	$settings[] = array(
		'id'      => 'authorization_enable_page_auth',
		'title'   => __( 'Enable Page Authorization', 'fooauth' ),
		'type'    => 'checkbox',
		'section' => 'authorization_options',
		'tab'     => 'authorization'
	);
	$settings[] = array(
		'id'      => 'authorization_enable_post_auth',
		'title'   => __( 'Enable Post Authorization', 'fooauth' ),
		'type'    => 'checkbox',
		'section' => 'authorization_options',
		'tab'     => 'authorization'
	);
	$settings[] = array(
		'id'      => 'authorization_enable_menu_auth',
		'title'   => __( 'Enable Menu Authorization', 'fooauth' ),
		'type'    => 'checkbox',
		'section' => 'authorization_options',
		'tab'     => 'authorization'
	);
	$settings[] = array(
		'id'      => 'authorization_login_groups',
		'title'   => __( 'Authorized Login Groups', 'fooauth' ),
		'type'    => 'text',
		'desc'    => __( 'Restrict login to specific security groups', 'fooauth' ),
		'section' => 'authorization_options',
		'tab'     => 'authorization'
	);
	$settings[] = array(
		'id'      => 'authorization_role_to_ad_mapping',
		'title'   => __( 'Role to AD group mapping', 'fooauth' ),
		'type'    => 'text',
		'desc'    => __( 'Map AD groups to specific Wordpress roles', 'fooauth' ),
		'section' => 'authorization_options',
		'tab'     => 'authorization'
	);
	$settings[] = array(
		'id'      => 'authorization_mixed_auth',
		'title'   => __( 'Enable Mixed Authorization', 'fooauth' ),
		'type'    => 'text',
		'section' => 'authorization_options',
		'tab'     => 'authorization'
	);
	//endregion

	//region Import Tab
	$tabs['import'] = __( 'Import', 'fooauth' );

	$sections['import_options'] = array(
		'tab'  => 'import',
		'name' => __( 'Import Options', 'fooauth' )
	);
	$settings[] = array(
		'id'      => 'import_import_auth_code',
		'title'   => __( 'Import Authorization Code', 'fooauth' ),
		'type'    => 'text',
		'desc'    => __( 'Use this code for your cron jobs', 'fooauth' ),
		'section' => 'import_options',
		'tab'     => 'import'
	);
	$settings[] = array(
		'id'      => 'import_import_select_groups',
		'title'   => __( 'Import specific groups and members', 'fooauth' ),
		'type'    => 'text',
		'section' => 'import_options',
		'tab'     => 'import'
	);

	//endregion

	return array(
		'tabs'     => $tabs,
		'sections' => $sections,
		'settings' => $settings
	);
}