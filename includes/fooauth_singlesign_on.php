<?php
/**
 * Created by PhpStorm.
 * User: Pigrat
 * Date: 2013/12/12
 * Time: 4:11 PM
 */

if (!class_exists('fooauth_single_signon')) {
    class fooauth_single_signon
    {
        function ad_sso_get_user_id( $userid ) {
            $user = get_userdatabylogin( $userid );
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

        /*  Get domain and username of user */
    $cred = explode('\\', $_SERVER['REMOTE_USER']);
        /*  seperate domain and user variables  */
    list($ad_sso_local_domain,, $ad_sso_local_userid) = $cred;
    if ( is_user_logged_in() ) {
    global $current_user;
    get_currentuserinfo();
    if ( !(strtolower(trim($current_user->user_login)) === strtolower(trim($ad_sso_local_userid)))) {
    wp_logout();
    }
}

    if ( !is_user_logged_in() ) {
        if (username_exists( $ad_sso_local_userid )) {
            ad_sso_register_user($ad_sso_local_domain, $ad_sso_local_userid, false); // update name and email

        } else {
            ad_sso_register_user($ad_sso_local_domain, $ad_sso_local_userid, true); // register user
        }
        $user_id = ad_sso_get_user_id( $ad_sso_local_userid );
        wp_set_current_user($user_id, $ad_sso_local_userid);
        wp_set_auth_cookie($user_id);
        do_action('wp_login', $ad_sso_local_userid);
    }
    }
}