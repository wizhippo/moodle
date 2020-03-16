<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Authentication Plugin: JWT Authentication
 *
 * @package auth_jwt
 * @author Douglas Hammond
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir.'/authlib.php');
require_once($CFG->dirroot.'/auth/jwt/vendor/autoload.php');
require_once($CFG->dirroot.'/cohort/locallib.php');

/**
 * Plugin for jwt authentication.
 */
class auth_plugin_jwt extends auth_plugin_base {

    public function __construct() {
        $this->authtype = 'jwt';
        $this->config = get_config('auth_jwt');
    }

    function prevent_local_passwords() {
        return true;
    }

    function user_login($username, $password) {
        global $DB, $CFG;

        if ($user = $DB->get_record('user', array('username'=>$username, 'mnethostid'=>$CFG->mnet_localhost_id, 'auth'=>$this->authtype))) {
            if (optional_param('jwt', false, PARAM_TEXT)) {
                return true;
            }
        }

        return false;
    }

    function is_internal() {
        return false;
    }

    function can_change_password() {
        return false;
    }

    function pre_loginpage_hook()
    {
        $jwt = optional_param('jwt', false, PARAM_TEXT);

        if (!$jwt) {
            redirect($this->config->url);
        }
    }

    function loginpage_hook()
    {
        global $DB, $CFG, $SESSION, $USER;

        $jwt = optional_param('jwt', false, PARAM_TEXT);

        if (!$jwt) {
            return;
        }

        if (empty($this->config->url)) {
            return;
        }

        if (empty($this->config->key)) {
            return;
        }

        if (!empty($jwt)) {
            try {
                $decoded = JWT::decode($jwt, $this->config->key, array('HS256'));
            } catch (UnexpectedValueException $e) {
                throw new moodle_exception('faileduserdetails', 'auth_jwt');
            }

            $username = $decoded->username;

            // Prohibit login if email belongs to the prohibited domain.
            if ($err = email_is_not_allowed($decoded->email)) {
                throw new moodle_exception($err, 'auth_jwt');
            }

            // Retrieve the user matching username.
            $user = $DB->get_record('user', array('username' => $username,
                                                  'mnethostid' => $CFG->mnet_localhost_id));

            $newuser = new stdClass();
            $newuser->email = $decoded->email;
            $newuser->firstname = $decoded->firstname;
            $newuser->lastname = $decoded->lastname;
            $newuser->idnumber = $decoded->external_id;

            if (!$user) {
                if ($CFG->authpreventaccountcreation) {
                    throw new moodle_exception("noaccountyet", "auth_jwt");
                }
                create_user_record($username, '', $this->authtype);
            } else {
                $username = $user->username;
            }

            $user = authenticate_user_login($username, null);
            if ($user)
            {
                // Prefill more user information if new user.
                if ( !empty( $newuser ) )
                {
                    $newuser->id = $user->id;
                    $DB->update_record( 'user', $newuser );
                    $user = (object)array_merge( (array)$user, (array)$newuser );

                    if (property_exists($decoded, 'cohort')) {
                        foreach((array)$decoded->cohort as $cohortId) {
                            cohort_add_member($cohortId, $user->id);
                        }
                    }
                }
                complete_user_login( $user );
            }

            if (user_not_fully_set_up($USER)) {
                $urltogo = $CFG->wwwroot.'/user/edit.php';
                // We don't delete $SESSION->wantsurl yet, so we get there later.
            } else if (isset($SESSION->wantsurl) and (strpos($SESSION->wantsurl, $CFG->wwwroot) === 0)) {
                $urltogo = $SESSION->wantsurl;    // Because it's an address in this site.
                unset($SESSION->wantsurl);
            } else {
                // No wantsurl stored or external - go to homepage.
                $urltogo = $CFG->wwwroot.'/';
                unset($SESSION->wantsurl);
            }
            redirect($urltogo);
        }
    }
}
