<?php
/*
* Plugin Name: AH Security
* Description: Sicherheitseinstellungen für diese Website - NICHT DEAKTIVIEREN!
* Version: 1.2.0
* Author: SEO Agentur Hamburg
* Author URI: https://seoagentur-hamburg.com/wordpress-sicherheit-service/
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




/*
	Secure POST Requests
	@ https://m0n.co/wp-requests
    @ Anfragen an Formulare nur vom eigenen Server zulassen
*/
function shapeSpace_secure_post_requests() {
	
	if (isset($_SERVER['REQUEST_METHOD'])) {
		
		$method = $_SERVER['REQUEST_METHOD'];
		
		if (strtoupper($method) === 'POST') {
			
			$host = @gethostbyaddr($address);
			
			if ($host !== 'seychellen.com') {
				
				status_header(403);
				exit;
				
			}
			
		}
		
	}
	
}
add_action('parse_request', 'shapeSpace_secure_post_requests', 1);




if ( ! function_exists( 'AH_remove_x_pingback' ) ) :
/**
 * Entfernen der XML-RPC Schnittstelle aus dem HTML-Header der Website
 */

 function AH_remove_x_pingback( $headers )
 {
 unset( $headers['X-Pingback'] );
 return $headers;
 }
add_filter( 'wp_headers', 'AH_remove_x_pingback' );
endif;