<?php

function fooauth_create_settings() {

  //region LDAP Tab
  $tabs['general'] = __('General', 'fooauth');

  //region Service Account
  $sections['service_account'] = array(
    'tab' => 'general',
    'name' => __('Service Account', 'fooauth')
  );

  $settings[] = array(
    'id' => 'ldap_username',
    'title' => __('Username', 'fooauth'),
    'type' => 'text',
    'section' => 'service_account',
    'tab' => 'general'
  );
  $settings[] = array(
    'id' => 'ldap_password',
    'title' => __('Password', 'fooauth'),
    'type' => 'password',
    'section' => 'service_account',
    'tab' => 'general'
  );
  $settings[] = array(
    'id' => 'ldap_fqdn',
    'title' => __('FQDN', 'fooauth'),
    'desc' => __('Fully qualified domain name. Eg. fooplugins.com', 'fooauth'),
    'type' => 'text',
    'section' => 'service_account',
    'tab' => 'general'
  );
  $settings[] = array(
    'id' => 'ldap_domain',
    'title' => __('Domain', 'fooauth'),
    'desc' => __('Name of your domain. Eg. fooplugins', 'fooauth'),
    'type' => 'text',
    'section' => 'service_account',
    'tab' => 'general'
  );
  //endregion

  //region Domain Controller
  $sections['domain_controller'] = array(
    'tab' => 'general',
    'name' => __('Domain Controller', 'fooauth')
  );
  $settings[] = array(
    'id' => 'ldap_domain_controllers',
    'title' => __('Domain Controllers', 'fooauth'),
    'type' => 'text',
    'desc' => __('Comma separated list of domain controllers. Eg. ADCONTROL1,ADCONTROL2,ADCONTROL5', 'fooauth'),
    'section' => 'domain_controller',
    'tab' => 'general'
  );
  $settings[] = array(
    'id' => 'ldap_port',
    'title' => __('Port', 'fooauth'),
    'type' => 'text',
    'default' => '389',
    'section' => 'domain_controller',
    'tab' => 'general'
  );
  $settings[] = array(
    'id' => 'ldap_tls',
    'title' => __('Use TLS', 'fooauth'),
    'type' => 'checkbox',
    'desc' => __('Secure connection between Wordpress and AD servers. NOTE : To use TLS, the port must be set to 389', 'fooauth'),
    'section' => 'domain_controller',
    'tab' => 'general'
  );
  $settings[] = array(
    'id' => 'ldap_organizational_unit',
    'title' => __('Organizational Unit', 'fooauth'),
    'type' => 'text',
    'desc' => __('Base DN Eg. DC=sub,DC=domain,DC=com', 'fooauth'),
    'section' => 'domain_controller',
    'tab' => 'general'
  );
  $settings[] = array(
    'id' => 'ldap_network_timeout',
    'title' => __('Network Timeout', 'fooauth'),
    'type' => 'text',
    'section' => 'domain_controller',
    'tab' => 'general'
  );

  //endregion

  //region Single Signon
  $sections['single_signon'] = array(
    'tab' => 'general',
    'name' => __('Single Sign-On', 'fooauth')
  );
  $settings[] = array(
    'id' => 'ldap_single_signon',
    'title' => __('Enable Single Sign-On', 'fooauth'),
    'type' => 'checkbox',
    'section' => 'single_signon',
    'tab' => 'general'
  );
  $settings[] = array(
    'id' => 'authentication_mixed_auth',
    'title' => __('Enable Mixed Authentication', 'fooauth'),
    'type' => 'checkbox',
    'section' => 'single_signon',
    'tab' => 'general'
  );
  //endregion

  //region User Setting
  $sections['user_setting'] = array(
    'tab' => 'general',
    'name' => __("User", "fooauth")
  );
  $settings[] = array(
    'id' => 'display_name',
    'title' => __('Display Name', 'fooauth'),
    'type' => 'select',
    'choices' => array(
      'samaccountname' => __('Username', 'fooauth'),
      'displayName' => __('Display Name', 'fooauth'),
      'description' => __('Description', 'fooauth'),
      'givenname' => __('First Name', 'fooauth'),
      'sn' => __('Surname', 'fooauth'),
      'givenname sn' => __('First Name - Surname', 'fooauth'),
      'cn' => __('Fullname', 'fooauth'),
      'mail' => __('Email Address', 'fooauth')
    ),
    'section' => 'user_setting',
    'tab' => 'general'
  );
  $settings[] = array(
    'id' => 'default_role',
    'title' => __('Default Role', 'fooauth'),
    'type' => 'select',
    'choices' => array(
      'admin' => __('Admin', 'fooauth'),
      'pending' => __('Pending', 'fooauth'),
      'subscriber' => __('Subscriber', 'fooauth'),
      'editor' => __('Editor', 'fooauth'),
      'contributor' => __('Contributor', 'fooauth')
    ),
    'default' => 'pending',
    'desc' => __('Default role new accounts should be assigned to', 'fooauth'),
    'section' => 'user_setting',
    'tab' => 'general'
  );
  //endregion

  //endregion

  //region Sync Tab
  $tabs['sync'] = __('Sync', 'fooauth');

  $sections['sync_options'] = array(
    'tab' => 'user',
    'name' => __('Sync Options', 'fooauth')
  );

  $settings[] = array(
    'id' => 'sync_auto_user_creation',
    'title' => __('Automatically Create Users', 'fooauth'),
    'type' => 'checkbox',
    'default' => 'on',
    'section' => 'sync_options',
    'tab' => 'sync'
  );
  $settings[] = array(
    'id' => 'sync_auto_user_updates',
    'title' => __('Automatically Update Users', 'fooauth'),
    'type' => 'checkbox',
    'section' => 'sync_options',
    'tab' => 'sync'
  );
  $settings[] = array(
    'id' => 'sync_import_groups',
    'title' => __('Import Groups', 'fooauth'),
    'type' => 'checkbox',
    'section' => 'sync_options',
    'tab' => 'sync'
  );

  //endregion

  //region Authorization Tab
  $tabs['authorization'] = __('Authorization', 'fooauth');

  $sections['authorization_options'] = array(
    'tab' => 'authorization',
    'name' => __('Authorization Options', 'fooauth')
  );
  $settings[] = array(
    'id' => 'authorization_enable_page_auth',
    'title' => __('Enable Page Authorization', 'fooauth'),
    'type' => 'checkbox',
    'section' => 'authorization_options',
    'tab' => 'authorization'
  );
  $settings[] = array(
    'id' => 'authorization_enable_post_auth',
    'title' => __('Enable Post Authorization', 'fooauth'),
    'type' => 'checkbox',
    'section' => 'authorization_options',
    'tab' => 'authorization'
  );
  $settings[] = array(
    'id' => 'authorization_enable_menu_auth',
    'title' => __('Enable Menu Authorization', 'fooauth'),
    'type' => 'checkbox',
    'section' => 'authorization_options',
    'tab' => 'authorization'
  );
  $settings[] = array(
    'id' => 'authorization_login_groups',
    'title' => __('Authorized Login Groups', 'fooauth'),
    'type' => 'text',
    'desc' => __('Restrict login to specific security groups', 'fooauth'),
    'section' => 'authorization_options',
    'tab' => 'authorization'
  );
  $settings[] = array(
    'id' => 'authorization_role_to_ad_mapping',
    'title' => __('Role to AD group mapping', 'fooauth'),
    'type' => 'text',
    'desc' => __('Map AD groups to specific Wordpress roles', 'fooauth'),
    'section' => 'authorization_options',
    'tab' => 'authorization'
  );
  //endregion

  return array(
    'tabs' => $tabs,
    'sections' => $sections,
    'settings' => $settings
  );
}