<?php
namespace AuthTools\AuthMethods;

class HTPasswd implements AuthMethodInterface
{
  private $pass_array = array();
  
  public function __construct($passwdfile)
  {
    if ( ! file_exists($passwdfile) )
      throw new \Exception(sprintf('htpasswd file "%s" is not found.', $passwdfile));
    
    foreach( file($passwdfile) as $l )
    {
      $array = explode(':',$l);
      $user = $array[0];
      $pass = chop($array[1]);
      $this->pass_array[$user] = $pass;
    }
  }
  
  /**
   * Dummy function for compatibility with LDAP Auth Method
   *
   * @param   string    $username
   * @return  string    $username
   */
  public function formatUsername($username)
  {
    return $username;
  }
  
  /**
   * Runs authentication against htpasswd and authorization via authlist.
   *
   * @param   string  username
   * @param   string  password
   * @return  boolean
   */
  public function checkCredentials($username, $password)
  {
    if ( self::chkpwd_htpasswd($this->pass_array, $username, $password) ) {
        trigger_error('User ' . $username . ' is granted access');
        return true;
    }
    else {
        trigger_error('User ' . $username . ' is denied access', E_USER_WARNING);
        return false;
    }
  }
  
   /**
   * Returns true if the user exists and the password matches, false otherwise
   *
   * @param  array   content of the loaded htpasswd file
   * @param  string  username
   * @param  string  cleartext user's password
   * @return boolean
   */
  private function chkpwd_htpasswd($pass_array, $username, $password)
  {
    if ( ! isset($pass_array[$username]) )
    {
      trigger_error('User '. $username . ' is not is htpasswd file', E_USER_WARNING);
      return false;
    }

    $crypted = $pass_array[$username];
  
    // Determine the password type (NB: no support for MD5 passwords)
    if ( substr($crypted, 0, 6) == "{SSHA}" ) {         // Salted SHA
      $ohash   = base64_decode(substr($crypted, 6));
      $crypted = substr($ohash, 0, 20);
      $generated = pack("H*", sha1($password . substr($ohash, 20)));
    }
    else if ( substr($crypted, 0, 5) == "{SHA}" ) {     // Non salted SHA
      $generated =  self:: make_htpasswd_non_salted_sha1($password);
    }
    else if ( substr($crypted, 0, 1) == "$" ) {     // MD5 password
      trigger_error('Detected MD5 password, which is not supported. Aborted!', E_USER_WARNING);
      return false;
    }
    else {                                              // UNIX CRYPT
      $generated = crypt( $password, substr($crypted,0,CRYPT_SALT_LENGTH) );
    }
    return ( $crypted == $generated );
  }
  
  /**
   * This function generates the salted crypt hash compatible with what normally
   * `htpasswd` command produces.
   * Algorithm: CRYPT
   *
   * @param  string password to be encrypted for a .htpasswd file
   * @return string password hash
   */
  private function make_htpasswd_salt_crypt($plaintext_password)
  {
    $salt = "";
    mt_srand((double)microtime()*1000000);

    for ($i=0; $i<CRYPT_SALT_LENGTH; $i++) {
      $salt .= substr("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./", mt_rand() & 63, 1);
    }
    return crypt($plaintext_password, $salt);
  }

  /**
   * Makes a hash of the given password as it htpasswd command would do.
   * Algorithm: SHA1 *with* salt
   *
   * @param  string password to be encrypted for a .htpasswd file
   * @return string password hash
   */
  private function make_htpasswd_salted_sha1($plaintext_password)
  {
    mt_srand((double)microtime()*1000000);
    $salt = pack("CCCC", mt_rand(), mt_rand(), mt_rand(), mt_rand());
    return "{SSHA}" . base64_encode(pack("H*", sha1($plaintext_password . $salt)) . $salt);
  }
  
  /**
   * Makes a hash of the given password as it htpasswd command would do.
   * Algorithm: SHA1 *without* salt
   *
   * @param  string password to be encrypted for a .htpasswd file
   * @return string password hash
   */
  private function make_htpasswd_non_salted_sha1($plaintext_password)
  {
    return "{SHA}" . base64_encode(pack("H*", sha1($plaintext_password)));
  }
}
?>
