<?php

if (!class_exists('FooAuth_Single_Signon')) {
    class FooAuth_Single_Signon
    {
        function __construct()
        {
            add_action('after_setup_theme', array($this, 'auto_login'));
        }

        private function get_details_from_ldap($username)
        {
            $options = FooAuth::get_instance()->options();

            $fqdn = $options->get('ldap_fqdn');
            $ou = $options->get('ldap_organizational_unit');
            $ldap_username = $options->get('ldap_username');
            $ldap_password = $options->get('ldap_password');
            $display_name_option = $options->get('user_display_name', 'displayName');

            $ldapCred = $ldap_username . '@' . $fqdn;
            try {
                $connection = ldap_connect('ldap://' . $fqdn);
                //Set some variables
                ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
                ldap_set_option($connection, LDAP_OPT_REFERRALS, 0);

                try {
                    //Bind to the ldap directory
                    ldap_bind($connection, $ldapCred, $ldap_password);

                    //Search the directory
                    $result = ldap_search($connection, $ou, '(samaccountname=' . $username . ')');
                    //Create result set
                    $entries = ldap_get_entries($connection, $result);

                    $email = (empty($entries[0]["mail"][0]) ? $username . '@' . $fqdn : $entries[0]["mail"][0]);
                    $firstname = $entries[0]["givenname"][0];
                    $surname = $entries[0]["sn"][0];
                    $display_name = $entries[0]["$display_name_option"][0];

                    return array(
                        'email' => $email,
                        'name' => $firstname,
                        'surname' => $surname,
                        'display_name' => $display_name
                    );

                } catch (Exception $e) {
                    return new WP_Error('666', 'Caught exception binding to LDAP Directory: ', $e->getMessage());
                }
            } catch (Exception $e) {
                return new WP_Error('666', 'Caught exception connecting to domain: ', $e->getMessage());
            }

        }

        private function update_user_details($username, $user_id)
        {
            $user = $this->get_details_from_ldap($username);

            $userdata = array(
                'ID' => $user_id,
                'first_name' => $user['name'],
                'last_name' => $user['surname'],
                'display_name' => $user['display_name']
            );

            wp_update_user($userdata);
        }

        private function register_new_user($username)
        {
            $user = $this->get_details_from_ldap($username);

            if (!is_wp_error($user)) {
                $options = FooAuth::get_instance()->options();
                $default_role = $options->get('sync_default_role', 'pending');

                $random_password = wp_generate_password($length = 12, $include_standard_special_chars = false);

                $userdata =
                    array(
                        'first_name' => $user['name'],
                        'last_name' => $user['surname'],
                        'display_name' => $user['display_name'],
                        'role' => $default_role,
                        'password' => $random_password,
                        'login' => $username,
                        'email' => $user['email']
                    );

                return wp_insert_user($userdata);
            }
            return $user;
        }

        private function extract_current_user_info()
        {
            if (empty($_SERVER['REMOTE_USER'])) return false;

            $current_credentials = explode('\\', $_SERVER['REMOTE_USER']);
            list($ad_domain, , $ad_username) = $current_credentials;

            return array(
                'domain' => $ad_domain,
                'username' => $ad_username
            );
        }

        private function is_on_login_page()
        {
            return 'wp-login.php' === $GLOBALS['pagenow'];
        }

        function auto_login()
        {
            if (FooAuth::get_instance()->options()->get('ldap_single_signon', false)) {
                if (!$this->is_on_login_page() && !is_user_logged_in()) {
                    $user_info = $this->extract_current_user_info();

                    if ($user_info === false) return;

                    $username = $user_info['username'];

                    $user_id = username_exists($username);

                    if ($user_id) {
                        $this->update_user_details($username, $user_id);
                    } else {
                        $user_id = $this->register_new_user($username);
                    }

                    if (!is_wp_error($user_id)) {
                        wp_set_current_user($user_id, $username);
                        wp_set_auth_cookie($user_id);
                        do_action('wp_login', $username);
                    }
                }
            }
        }
    }
}