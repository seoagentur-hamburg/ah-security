<?php
/*
* Plugin Name: AH Security
* Description: Sicherheitseinstellungen für diese Website - NICHT DEAKTIVIEREN!
* Version: 1.1.0
* Author: Andreas Hecht
* Author URI: https://andreas-hecht.com
*/


/**
 * Sicherheit: Anmeldung nur noch mit E-Mail-Adresse, anstatt Benutzernamen
 * 
 * @author Andreas Hecht
 */

//WordPress Authentifikation löschen
remove_filter('authenticate', 'wp_authenticate_username_password', 20);

// Neue Authentifikation setzen - Anmelden nur mit E-Mail und Passwort
add_filter('authenticate', function($user, $email, $password){
 
    //Check for empty fields
        if(empty($email) || empty ($password)){        
            //create new error object and add errors to it.
            $error = new WP_Error();
 
            if(empty($email)){ //No email
                $error->add('empty_username', __('<strong>FEHLER</strong>: Das E-Mail Feld ist leer.'));
            }
            else if(!filter_var($email, FILTER_VALIDATE_EMAIL)){ //Invalid Email
                $error->add('invalid_username', __('<strong>FEHLER</strong>: Die E-Mail-Adresse ist ungültig'));
            }
 
            if(empty($password)){ //No password
                $error->add('empty_password', __('<strong>FEHLER</strong>: Das Passwort-Feld ist leer.'));
            }
 
            return $error;
        }
 
        //Check if user exists in WordPress database
        $user = get_user_by('email', $email);
 
        //bad email
        if(!$user){
            $error = new WP_Error();
            $error->add('invalid', __('<strong>FEHLER</strong>: Deine Eingaben sind ungültig.'));
            return $error;
        }
        else{ //check password
            if(!wp_check_password($password, $user->user_pass, $user->ID)){ //bad password
                $error = new WP_Error();
                $error->add('invalid', __('<strong>FEHLER</strong>: Deine Eingaben sind ungültig.'));
                return $error;
            }else{
                return $user; //passed
            }
        }
}, 20, 3);




if ( ! function_exists( 'ah_remove_comment_author_class' ) ) :
/**
 * Security: Keine Benutzernamen in den Kommentar-Klassen im HTML-Quellcode
 * 
 * @author Andreas Hecht
 */
function ah_remove_comment_author_class( $classes ) {
	foreach( $classes as $key => $class ) {
		if(strstr($class, "comment-author-")) {
			unset( $classes[$key] );
		}
	}
	return $classes;
}

add_filter( 'comment_class' , 'ah_remove_comment_author_class' );
endif;



/**
 * Sicherheit: User davon abhalten, ihre Passwörter zu ändern
 * 
 * @author Andreas Hecht
 */ 
class Password_Reset_Removed
{

  function __construct() 
  {
    add_filter( 'show_password_fields', array( $this, 'disable' ) );
    add_filter( 'allow_password_reset', array( $this, 'disable' ) );
  }

  function disable() 
  {
    if ( is_admin() ) {
      $userdata = wp_get_current_user();
      $user = new WP_User($userdata->ID);
      if ( !empty( $user->roles ) && is_array( $user->roles ) && $user->roles[0] == 'administrator' )
        return true;
    }
    return false;
  }

}

$pass_reset_removed = new Password_Reset_Removed();





if ( ! function_exists( 'ah_redirect_after_login_errors' ) ) :
/**
 * Redirect auf Google nach falscher Eingabe der WP-Zugangsdaten
 */
function ah_redirect_after_login_errors() {
    
  wp_redirect( 'https://www.google.de' );
  exit;
}
add_filter( 'login_errors', 'ah_redirect_after_login_errors' );
endif;