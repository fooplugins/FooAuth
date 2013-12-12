<?php

if (!class_exists('settings')) {
    class settings
    {
        function __construct()
        {
            add_action('fooauth-settings-init', array(&$this, 'create_settings'));
        }

        function create_settings($fooauth)
        {
            //LDAP Settings
            $fooauth->admin_settings_add_tab('ldap', __('LDAP', 'fooauth'));
            //Service Account
            $fooauth->admin_settings_add_section_to_tab('ldap', 'service_account', __('Service Account', 'fooauth'));
            $fooauth->admin_settings_add(array(
                'id' => 'ldap_username',
                'title' => __('Username', 'fooauth'),
                'type' => 'text',
                'section' => 'service_account',
                'tab' => 'ldap'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'ldap_password',
                'title' => __('Password', 'fooauth'),
                'type' => 'text',
                'section' => 'service_account',
                'tab' => 'ldap'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'ldap_domain',
                'title' => __('Domain', 'fooauth'),
                'desc' => __('Fully qualified domain name', 'fooauth'),
                'type' => 'text',
                'section' => 'service_account',
                'tab' => 'ldap'
            ));

            //Domain Controller
            $fooauth->admin_settings_add_section_to_tab('ldap', 'domain_controller', __('Domain Controller', 'fooauth'));
            $fooauth->admin_settings_add(array(
                'id' => 'ldap_domain_controllers',
                'title' => __('Domain Controllers', 'fooauth'),
                'type' => 'text',
                'desc' => __('Comma separated list of domain controllers', 'fooauth'),
                'section' => 'domain_controller',
                'tab' => 'ldap'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'ldap_port',
                'title' => __('Port', 'fooauth'),
                'type' => 'text',
                'section' => 'domain_controller',
                'tab' => 'ldap'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'ldap_tls',
                'title' => __('Use TLS', 'fooauth'),
                'type' => 'checkbox',
                'desc' => __('Secure connection between Wordpress and AD servers. NOTE : To use TLS, the port must be set to 389', 'fooauth'),
                'section' => 'domain_controller',
                'tab' => 'ldap'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'ldap_organizational_unit',
                'title' => __('Organizational Unit (Base DN)', 'fooauth'),
                'type' => 'text',
                'desc' => __('eg. DC=sub,DC=domain,dc=com', 'fooauth'),
                'section' => 'domain_controller',
                'tab' => 'ldap'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'ldap_network_timeout',
                'title' => __('Network Timeout', 'fooauth'),
                'type' => 'text',
                'section' => 'domain_controller',
                'tab' => 'ldap'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'ldap_single_signon',
                'title' => __('Allow Single Signon', 'fooauth'),
                'type' => 'checkbox',
                'section' => 'domain_controller',
                'tab' => 'ldap'
            ));

            //User Settings
            $fooauth->admin_settings_add_tab('user', __('User', 'fooauth'));
            $fooauth->admin_settings_add_section_to_tab('user', 'user_options', __('User Options', 'fooauth'));
            $fooauth->admin_settings_add(array(
                'id' => 'user_account_suffix',
                'title' => __('Account Suffix', 'fooauth'),
                'type' => 'text',
                'section' => 'user_options',
                'tab' => 'user'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'user_append_suffix',
                'title' => __('Append Suffix to Username', 'fooauth'),
                'type' => 'checkbox',
                'desc' => __('Append suffix to newly created usernames', 'fooauth'),
                'section' => 'user_options',
                'tab' => 'user'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'user_prevent_email_address_change',
                'title' => __('Prevent users from changing their email address', 'fooauth'),
                'type' => 'checkbox',
                'section' => 'user_options',
                'tab' => 'user'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'user_prevent_password_change',
                'title' => __('Prevent users from changing their Wordpress password', 'fooauth'),
                'type' => 'checkbox',
                'section' => 'user_options',
                'tab' => 'user'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'user_display_name',
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
                'section' => 'user_options',
                'tab' => 'user'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'user_max_login_attempts',
                'title' => __('Maximum Login Attempts', 'fooauth'),
                'type' => 'text',
                'section' => 'user_options',
                'tab' => 'user'
            ));

            //Sync Settings
            $fooauth->admin_settings_add_tab('sync', __('Sync', 'fooauth'));
            $fooauth->admin_settings_add_section_to_tab('sync', 'sync_options', __('Sync Options', 'fooauth'));
            $fooauth->admin_settings_add(array(
                'id' => 'sync_auto_user_creation',
                'title' => __('Automatically Create Users', 'fooauth'),
                'type' => 'checkbox',
                'section' => 'sync_options',
                'tab' => 'sync'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'sync_auto_user_updates',
                'title' => __('Automatically Update Users', 'fooauth'),
                'type' => 'checkbox',
                'section' => 'sync_options',
                'tab' => 'sync'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'sync_import_groups',
                'title' => __('Import Groups', 'fooauth'),
                'type' => 'checkbox',
                'section' => 'sync_options',
                'tab' => 'sync'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'sync_default_role',
                'title' => __('Default Role', 'fooauth'),
                'type' => 'select',
                'choices' => array(
                    'admin' => __('Admin', 'fooauth'),
                    'pending' => __('Pending', 'fooauth'),
                    'subscriber' => __('Subscriber', 'fooauth'),
                    'editor' => __('Editor', 'fooauth'),
                    'contributor' => __('Contributor', 'fooauth')
                ),
                'desc' => __('Default role new accounts should be assigned to', 'fooauth'),
                'section' => 'sync_options',
                'tab' => 'sync'
            ));

            //Authorization Settings
            $fooauth->admin_settings_add_tab('authorization', __('Authorization', 'fooauth'));
            $fooauth->admin_settings_add_section_to_tab('authorization', 'authorization_options', __('Authorization Options', 'fooauth'));
            $fooauth->admin_settings_add(array(
                'id' => 'authorization_enable_page_auth',
                'title' => __('Enable Page Authorization', 'fooauth'),
                'type' => 'checkbox',
                'section' => 'authorization_options',
                'tab' => 'authorization'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'authorization_enable_post_auth',
                'title' => __('Enable Post Authorization', 'fooauth'),
                'type' => 'checkbox',
                'section' => 'authorization_options',
                'tab' => 'authorization'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'authorization_enable_menu_auth',
                'title' => __('Enable Menu Authorization', 'fooauth'),
                'type' => 'checkbox',
                'section' => 'authorization_options',
                'tab' => 'authorization'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'authorization_login_groups',
                'title' => __('Authorized Login Groups', 'fooauth'),
                'type' => 'text',
                'desc' => __('Restrict login to specific security groups', 'fooauth'),
                'section' => 'authorization_options',
                'tab' => 'authorization'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'authorization_role_to_ad_mapping',
                'title' => __('Role to AD group mapping', 'fooauth'),
                'type' => 'text',
                'desc' => __('Map AD groups to specific Wordpress roles', 'fooauth'),
                'section' => 'authorization_options',
                'tab' => 'authorization'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'authorization_mixed_auth',
                'title' => __('Enable Mixed Authorization', 'fooauth'),
                'type' => 'text',
                'section' => 'authorization_options',
                'tab' => 'authorization'
            ));

            //Import Settings
            $fooauth->admin_settings_add_tab('import', __('Import', 'fooauth'));
            $fooauth->admin_settings_add_section_to_tab('import', 'import_options', __('Import Options', 'fooauth'));
            $fooauth->admin_settings_add(array(
                'id' => 'import_import_auth_code',
                'title' => __('Import Authorization Code', 'fooauth'),
                'type' => 'text',
                'desc' => __('Use this code for your cron jobs', 'fooauth'),
                'section' => 'import_options',
                'tab' => 'import'
            ));
            $fooauth->admin_settings_add(array(
                'id' => 'import_import_select_groups',
                'title' => __('Import specific groups and members', 'fooauth'),
                'type' => 'text',
                'section' => 'import_options',
                'tab' => 'import'
            ));
        }
    }
}