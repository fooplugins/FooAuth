<?php

if (!class_exists('FooAuth_Single_Signon')) {
  class FooAuth_Single_Signon {
    function __construct() {
      add_action('after_setup_theme', array($this, 'auto_login'));
      add_action('wp_login', array($this, 'user_authorization_check'), 10, 2);
    }

    private function get_details_from_ldap($username) {
      $options = FooAuth::get_instance()->options();

      $fqdn = $options->get('ldap_fqdn');
      $ou = $options->get('ldap_organizational_unit');
      $ldap_username = $options->get('ldap_username');
      $ldap_password = $options->get('ldap_password');
      $display_name_option = $options->get('display_name', 'displayName');

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

          $user_groups = $entries[0]["memberof"];
          $email = (empty($entries[0]["mail"][0]) ? $username . '@' . $fqdn : $entries[0]["mail"][0]);
          $firstname = $entries[0]["givenname"][0];
          $surname = $entries[0]["sn"][0];
          $display_name = $entries[0]["$display_name_option"][0];

          return array(
            'email' => $email,
            'name' => $firstname,
            'surname' => $surname,
            'display_name' => $display_name,
            'user_groups' => $user_groups
          );

        } catch (Exception $e) {
          return new WP_Error('666', 'Caught exception binding to LDAP Directory: ', $e->getMessage());
        }
      } catch (Exception $e) {
        return new WP_Error('666', 'Caught exception connecting to domain: ', $e->getMessage());
      }
    }

    private function update_user_details($username, $user_id) {
      $auto_update_user = FooAuth::get_instance()->options()->get('auto_update_user', false);

      if ('on' === $auto_update_user) {
        $user = $this->get_details_from_ldap($username);

        $userdata = array(
          'ID' => $user_id,
          'first_name' => $user['name'],
          'last_name' => $user['surname'],
          'display_name' => $user['display_name']
        );

        wp_update_user($userdata);
        update_user_meta($user_id, 'user_groups', $user['user_groups']);
      }
    }

    private function register_new_user($username) {
      $user = $this->get_details_from_ldap($username);

      if (!is_wp_error($user)) {
        $options = FooAuth::get_instance()->options();
        $default_role = $options->get('default_role', 'pending');

        $random_password = wp_generate_password(12, false);

        $userdata = array(
          'first_name' => $user['name'],
          'last_name' => $user['surname'],
          'display_name' => $user['display_name'],
          'role' => $default_role,
          'user_pass' => $random_password,
          'user_login' => $username,
          'user_email' => $user['email']
        );

        $user_id = wp_insert_user($userdata);

        add_user_meta($user_id, 'user_groups', $user['user_groups'], true);

        return $user_id;
      }
      return $user;
    }

    private function extract_current_user_info() {
      if (empty($_SERVER['REMOTE_USER'])) return false;

      $current_credentials = explode('\\', $_SERVER['REMOTE_USER']);
      list($ad_domain, , $ad_username) = $current_credentials;

      return array(
        'domain' => $ad_domain,
        'username' => $ad_username
      );
    }

    private function is_on_login_page() {
      return 'wp-login.php' === $GLOBALS['pagenow'];
    }

    private function is_user_authorized($username) {
      $authorized_groups = FooAuth::get_instance()->options()->get('authorized_groups', '');
      $user_groups = '';

      $user_id = username_exists($username);
      if (isset($user_id)) {
        $user_groups = get_user_meta($user_id, 'user_groups');
      } else {
        $user_groups = $this->get_details_from_ldap($username)['user_groups'];
      }

      if (isset($authorized_groups)) {
        if (isset($user_groups)) {
          $authorized_groups_array = explode(',', $authorized_groups);

          foreach ($user_groups as $user_group) {
            if (foo_contains($authorized_groups_array, $user_group)) {
              return true;
            }
          }
        }
        return false;
      }
      return true;
    }

    private function is_sso_enabled() {
      $do_sso = FooAuth::get_instance()->options()->get('ldap_single_signon', false);
      return ('on' === $do_sso);
    }

    function user_authorization_check($user_login, $user) {
      $username = $user_login;
      if (!$this->is_user_authorized($username)) {
        //User is not authorized to login to the site. Redirect to a selected page
        $redirect_url = FooAuth::get_instance()->options()->get('unauthorized_redirect_page', get_home_url());
        wp_redirect($redirect_url);
        exit;
      }
    }

    function auto_login() {
      if ($this->is_sso_enabled()) {
        if (!$this->is_on_login_page() && !is_user_logged_in()) {
          $user_info = $this->extract_current_user_info();

          if ($user_info === false) return;

          $username = $user_info['username'];

          //check if the user has access to log in to the site
          $this->user_authorization_check($username, null);

          $user_id = username_exists($username);

          if (isset($user_id)) {
            $this->update_user_details($username, $user_id);
          } else {
            $user_id = $this->register_new_user($username);
          }

          if (!isset($user_id) && !is_wp_error($user_id)) {
            wp_set_current_user($user_id, $username);
            wp_set_auth_cookie($user_id);
            do_action('wp_login', $username);
          }
        }
      }
    }
  }
}