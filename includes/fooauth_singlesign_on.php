<?php
/**
 * Created by PhpStorm.
 * User: Pigrat
 * Date: 2013/12/12
 * Time: 4:11 PM
 */

if (!class_exists('FooAuth_Single_Signon')) {
    class FooAuth_Single_Signon
    {
        function ad_sso_get_user_id( $user_login ) {
            $user = get_user_by('login', $user_login);
            return $user->ID;
        }

        function ad_sso_register_user( $domain, $userid, $isNewUser ) {

            $ad_sso_fqdn = get_option('ad_sso_fqdn');
            $ad_sso_ou = get_option('ad_sso_ou');

            $ad_sso_username = get_option('ad_sso_username');
            $ad_sso_password = get_option('ad_sso_password');
            $ad_sso_domain = get_option('ad_sso_domain');

            // if the default role hasn't been set, default to subscriber
            $ad_sso_default_role = (strlen(get_option('ad_sso_default_role')) > 0 ? get_option('ad_sso_default_role') : 'subscriber');
            // if a value isn't set or true, default to false
            $ad_sso_show_toolbar = (get_option('ad_sso_show_toolbar') == '1' ? 'true' : 'false');

            $ldapCred = $ad_sso_username . '@' . $ad_sso_fqdn;
            try {
                $connection = ldap_connect('ldap://' . $ad_sso_fqdn);
                //Set some variables
                ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
                ldap_set_option($connection, LDAP_OPT_REFERRALS, 0);

                try {
                    //Bind to the ldap directory
                    $bind = ldap_bind($connection, $ldapCred, $ad_sso_password);

                    //Search the directory
                    $result = ldap_search($connection, $ad_sso_ou, '(samaccountname=' . $userid . ')');
                    //Create result set
                    $entries = ldap_get_entries($connection, $result);

                    $email = (empty($entries[0]["mail"][0]) ? $userid . '@' . $ad_sso_fqdn : $entries[0]["mail"][0]);
                    $givenname = $entries[0]["givenname"][0];
                    $sn = $entries[0]["sn"][0];

                    if ( $isNewUser ) {
                        $random_password = wp_generate_password( $length=12, $include_standard_special_chars=false );
                        $user_id = wp_create_user( $userid, $random_password, $email );

                        wp_update_user(
                            array (
                                'ID' => ad_sso_get_user_id( $userid ),
                                'first_name' => $givenname,
                                'last_name' => $sn,
                                'show_admin_bar_front' => $ad_sso_show_toolbar,
                                'display_name' =>  $givenname . ' ' . $sn,
                                'role' => $ad_sso_default_role
                            )
                        );
                    } else {
                        wp_update_user(
                            array (
                                'ID' => ad_sso_get_user_id( $userid ),
                                'first_name' => $givenname,
                                'last_name' => $sn,
                                'display_name' =>  $givenname . ' ' . $sn,
                                'user_email' => $email
                            )
                        );
                    }
                } catch(Exception $e) {
                    echo 'Caught exception binding to LDAP Directory: ',  $e->getMessage(), "<br />";
                }
            } catch(Exception $e) {
                echo 'Caught exception connecting to domain: ',  $e->getMessage(), "<br />";
            }


        }

		function update_user_details($domain, $username) {

		}

		function register_new_user($domain, $username) {

		}

		function extract_current_user_info() {
			if ( empty( $_SERVER['REMOTE_USER'] )) return false;

			$current_credentials = explode('\\', $_SERVER['REMOTE_USER']);
			list($ad_domain,, $ad_username) = $current_credentials;

			return array(
				'domain' => $ad_domain,
				'username' => $ad_username
			);
		}

		function is_on_login_page() {
			return 'wp-login.php' === $GLOBALS['pagenow'];
		}

		function auto_login() {
			if ( !is_on_login_page() && !is_user_logged_in() ) {
				$user_info = $this->extract_current_user_info();

				if ($user_info === false) return;

				$username = $user_info['username'];
				$domain = $user_info['domain'];

				if (username_exists( $username )) {
					$this->update_user_details($domain, $username);
				} else {
					$this->register_new_user($domain, $username);
				}

				$user = get_user_by('login', $username);
				$user_id = $user->ID;
				wp_set_current_user($user_id, $username);
				wp_set_auth_cookie($user_id);
				do_action('wp_login', $username);
			}
		}
	}
}