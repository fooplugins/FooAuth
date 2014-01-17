<?php

if (!class_exists('FooAuth_Single_Signon')) {
  class FooAuth_Single_Signon {

    function __construct() {
      add_action('after_setup_theme', array($this, 'auto_login'));
      add_action('wp_login', array($this, 'user_authorization_check'), 10, 2);
      add_action('load-post.php', array($this, 'auth_metabox_setup'));
      add_action('load-post-new.php', array($this, 'auth_metabox_setup'));
      if (!is_admin()) {
        add_action('pre_get_posts', array($this, 'filter_allowed_posts'));
      }
      if (!is_admin()) {
        add_action('wp', array($this, 'check_user_authorization'));
      }
    }

    function auto_login() {
      if ($this->is_sso_enabled()) {
        if (!$this->is_on_login_page() && !is_user_logged_in()) {
          $user_info = $this->get_current_user_info();

          if ($user_info === false) return;

          $username = $this->get_actual_username($user_info);

          //check if the user has access to log in to the site
          $this->user_authorization_check($username, null);

          if (!$this->can_user_be_created()) return;

          $user_id = username_exists($username);

          if (isset($user_id)) {
            $this->update_user_details($username, $user_id);
          } else {
            $user_id = $this->register_new_user($username);
          }

          if (isset($user_id) && !is_wp_error($user_id)) {
            wp_set_current_user($user_id, $username);
            wp_set_auth_cookie($user_id);
            do_action('wp_login', $username);
          }
        }
      }
    }

    function user_authorization_check($user_login, $user) {
      //if the user is not on the redirect page, check if they are authorized to login to the site
      if (!$this->is_on_redirect_page() && !$this->is_user_authorized($user_login)) {
        //User is not authorized to login to the site. Redirect to a selected page
        $this->redirect_unauthorized_users();
      }
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

          $user_groups_dn = $entries[0]["memberof"];
          $user_groups_array = array();

          //get just the group name out of the DN details
          foreach ($user_groups_dn as $user_group) {
            $group_details = $this->explode_dn($user_group);
            $user_groups_array[] = str_replace('CN=', '', $group_details[0]);
          }

          $user_groups = implode(',', $user_groups_array);

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

    private function get_current_user_info() {
      if (empty($_SERVER['REMOTE_USER'])) return false;

      $current_credentials = explode('\\', $_SERVER['REMOTE_USER']);
      list($ad_domain, , $ad_username) = $current_credentials;

      return array(
        'domain' => $ad_domain,
        'username' => $ad_username
      );
    }

    private function get_current_page_url() {
      $page_URL = 'http';
      if ($_SERVER["HTTPS"] == "on") {
        $page_URL .= "s";
      }
      $page_URL .= "://";
      if ($_SERVER["SERVER_PORT"] != "80") {
        $page_URL .= $_SERVER["SERVER_NAME"] . ":" . $_SERVER["SERVER_PORT"] . $_SERVER["REQUEST_URI"];
      } else {
        $page_URL .= $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"];
      }
      return $page_URL;
    }

    private function can_user_be_created() {
      //check if the user has been redirected to the redirect page and aren't logged in
      if ($this->is_on_redirect_page() && !is_user_logged_in()) {
        return false;
      }
      return true;
    }

    private function is_on_login_page() {
      return 'wp-login.php' === $GLOBALS['pagenow'];
    }

    private function is_on_redirect_page() {
      $redirect_page = FooAuth::get_instance()->options()->get('unauthorized_redirect_page', '');

      if (!empty($redirect_page)) {
        $current_page = $this->get_current_page_url();

        if (!empty($current_page)) {
          return ($current_page === $redirect_page);
        }
      }
      return false;
    }

    private function is_sso_enabled() {
      $do_sso = FooAuth::get_instance()->options()->get('ldap_single_signon', false);
      return ('on' === $do_sso);
    }

    private function is_admin_user($user_id) {
      if (!empty($user_id)) {
        $user = new WP_User($user_id);

        if (!empty($user)) {
          foreach ($user->roles as $user_role) {
            if (strtolower(__('administrator', 'fooauth')) === strtolower($user_role)) {
              return true;
            }
          }
        }
      }
      return false;
    }

    private function is_user_authorized($username, $authorized_groups = '') {
      if (empty($authorized_groups)) {
        $authorized_groups = FooAuth::get_instance()->options()->get('authorized_groups', '');
      }

      $user_id = username_exists($username);

      if ($this->is_admin_user($user_id)) {
        return true;
      }


      if (isset($user_id)) {
        $user_groups = get_user_meta($user_id, 'user_groups');
      } else {
        $user = $this->get_details_from_ldap($username);
        $user_groups = $user['user_groups'];
      }

      if (!empty($authorized_groups)) {
        if (!empty($user_groups)) {
          $user_group_array = explode(',', $user_groups[0]);

          $authorized_groups_array = explode(',', $authorized_groups);

          foreach ($user_group_array as $user_group) {
            foreach ($authorized_groups_array as $authorized_group) {
              if (strtolower($user_group) === strtolower($authorized_group)) {
                return true;
              }
            }
          }
        }
        return false;
      }
      return true;
    }

    private function update_user_details($username, $user_id) {
      $auto_update_user = FooAuth::get_instance()->options()->get('auto_user_updates', false);

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

    private function explode_dn($dn, $with_attributes = 0) {
      $result = ldap_explode_dn($dn, $with_attributes);
      //translate hex code into ASCII again
      foreach ($result as $key => $value) {
        $result[$key] = preg_replace("/\\\([0-9A-Fa-f]{2})/e", "''.chr(hexdec('\\1')).''", $value);
      }
      return $result;
    }

    function auth_metabox_setup() {
      add_action('add_meta_boxes', array($this, 'add_auth_metaboxes'));
      add_action('save_post', array($this, 'save_post_authorized_groups'), 10, 2);
    }

    function add_auth_metaboxes() {
      add_meta_box('fooauth_authorized_groups', esc_html__('Authorized Groups', 'fooath'), array($this, 'authorized_group_metabox'), 'post', 'side', 'default');
      add_meta_box('fooauth_authorized_groups', esc_html__('Authorized Groups', 'fooath'), array($this, 'authorized_group_metabox'), 'page', 'side', 'default');
    }

    function save_post_authorized_groups($post_id, $post) {
      $foo_auth_nonce = $_POST['fooauth_authorized_groups_nonce'];

      if (!isset($foo_auth_nonce) || !wp_verify_nonce($foo_auth_nonce, basename(__FILE__))) return $post_id;

      $post_type = get_post_type_object($post->post_type);

      if (!current_user_can($post_type->cap->edit_post, $post_id)) return $post_id;

      $meta_key = 'fooauth-authorized-groups';
      $new_meta_value = $_POST[$meta_key];
      $meta_value = get_post_meta($post_id, $meta_key, true);

      if (!empty($new_meta_value) && empty($meta_value)) {
        add_post_meta($post_id, $meta_key, $new_meta_value, true);
      } else if (!empty($new_meta_value) && $new_meta_value != $meta_value) {
        update_post_meta($post_id, $meta_key, $new_meta_value);
      } else if (empty($new_meta_value) && !empty($meta_value)) {
        delete_post_meta($post_id, $meta_key, $meta_value);
      }
    }

    function authorized_group_metabox($object, $box) {
      ?>
      <?php wp_nonce_field(basename(__FILE__), 'fooauth_authorized_groups_nonce'); ?>
      <p>
        <label for="fooauth-authorized-groups"><?php _e('AD Groups', 'fooauth'); ?></label>
        <br/>
        <input class="widefat" type="text" name="fooauth-authorized-groups" id="fooauth-authorized-groups"
               value="<?php echo get_post_meta($object->ID, 'fooauth-authorized-groups', true); ?>"
               size="30"/>
        <br/>
        <small><?php _e('Comma separated list of AD groups', 'fooauth'); ?></small>
      </p>
    <?php
    }

    private function redirect_unauthorized_users() {
      $redirect_url = FooAuth::get_instance()->options()->get('unauthorized_redirect_page', '');
      wp_redirect($redirect_url);
      exit;
    }

    private function get_actual_username($remote_user) {
      $username = $remote_user['username'];

      if (is_user_logged_in()) {

        $logged_in_user = wp_get_current_user();

        if ($username !== $logged_in_user->user_login) {
          $username = $logged_in_user->user_login;
        }
      }
      return $username;
    }

    function check_user_authorization() {
      $current_post = get_post();
      $meta_key = 'fooauth-authorized-groups';

      $authorized_groups = get_post_meta($current_post->ID, $meta_key, true);

      if (!empty($authorized_groups)) {
        $user = $this->get_current_user_info();

        if (!$user) return;

        if ('post' === $current_post->post_type && !$this->is_user_authorized($this->get_actual_username($user), $authorized_groups)) {
          $this->redirect_unauthorized_users();
        }
        if ('page' === $current_post->post_type && !$this->is_user_authorized($this->get_actual_username($user), $authorized_groups)) {
          $this->redirect_unauthorized_users();
        }
      }
    }

    private $excluded_posts = false;
    private $filter_loop = true;

    function get_excluded_posts() {
      if ($this->excluded_posts === false) {
        $excluded_posts = array();

        $this->filter_loop = false;

        //get all the posts for the site
        $query = new WP_Query(array('post_type' => 'post'));

        $site_posts = $query->get_posts();

        $this->filter_loop = true;

        $user = $this->get_current_user_info();

        foreach ($site_posts as $site_post) {
          $authorized_groups = get_post_meta($site_post->ID, 'fooauth-authorized-groups', true);

          if (!empty($authorized_groups)) {
            if (!$this->is_user_authorized($this->get_actual_username($user), $authorized_groups)) {
              $excluded_posts[] = $site_post->ID;
            }
          }
        }
        $this - $excluded_posts = $excluded_posts;
      }
      return $this->excluded_posts;
    }

    function filter_allowed_posts($query) {

      if ($this->filter_loop === false) return;

      //exclude all posts from the main query that the user is not authorized to view
      $excluded_posts = $this->get_excluded_posts();

      if (!empty($excluded_posts)) {
        $query->set('post__not_in', $excluded_posts);
      }
    }
  }
}