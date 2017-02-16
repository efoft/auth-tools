<?php
namespace AuthTools;

use AuthTools\AuthMethods\AuthMethodInterface;

class Auth
{
  private $debug = true;
  private $method;
  private $authlist;
  
  public function __construct(AuthMethodInterface $method, $authlist)
  {
    if ( ! self::isAssocArray($authlist) )
      throw new \InvalidArgumentException('Argument must be an associative with username as keys and access levels as values.');
    
    $this->authlist = $authlist;
    $this->method = $method;
  }
  
  /**
   * Check if arguments are associative arrays.
   *
   * @param   array(s)	origin data to operate with
   * @return  bool			true|false = passed pre-check or not
   */
  private static function isAssocArray()
  {
    $retval = true;
    // check whether each of args is associatiave array (keys are strings)
    foreach( func_get_args() as $arg )
    {
      if ( ! is_array($arg) || count(array_filter(array_keys($arg),'is_string')) === 0 )
      {
        $retval = false;
        break;
      }
    }
    return $retval;
  }
  
   /**
   * First checks if the use is already authenticated and secondly
   * tries to authenticate the user if credentials are supplied.
   *
   * @return  boolean
   */
  public function checkAuth() 
  {
    if ( isset($_POST['authrequest']) && ! empty($_POST['username']) && ! empty($_POST['password']) )
      $this->runAuth(strtolower($_POST['username']), $_POST['password']);

    return ( isset($_SESSION['authorized']) );
  }

  /**
   * Returns username if the user is authenticated.
   *
   * @return  string
   */
  public function getAuthName()
  {
    if ( isset($_SESSION['authorized']) && isset($_SESSION['authname']) )
      return $_SESSION['authname'];
  }

  /**
   * Each user in authlist should come with a series of allowed levels (digits 0-9).
   * Some pages require specific access level for a user. This function searches 
   * requested level through the allowed levels from config. 
   *
   * @param   string (single digit 0-9)
   * @return  boolean
   */
  public function checkAuthLevel($level_to_check)
  {
    if ( $this->checkAuth() )
      $permitted_levels = isset($this->authlist[$_SESSION['authname']]) ? $this->authlist[$_SESSION['authname']] : '';

    return ( strpos($permitted_levels, $level_to_check) !== false );
  }

  /**
   * Destroys the variable set in the session.
   *
   */
  public function logout()
  {
    if ( $this->checkAuth() )
      unset($_SESSION['authorized']);
  }

  /**
   * 
   *
   * @param   string  username in the format domain\\username or username@domain.com
   * @param   string  password
   */
  public function runAuth($username, $password)
  {
    if ( $this->method->checkCredentials($username, $password) && $this->authorize($username) )
    {
      if( session_id() == '' )
        session_start();

      $_SESSION['authorized'] = 1;
      $_SESSION['authname']   = $this->method->formatUsername($username);
    }
  }
  
  /**
   * Check the user against authlist
   *
   * @param   string    $username
   */
  private function authorize($username)
  { 
    $username = $this->method->formatUsername($username);
    
    if ( array_key_exists($username, $this->authlist) )
    {
      $this->debug && trigger_error('User ' . $username . ' is granted access');
      return true;
    }
    else
    {
      $this->debug && trigger_error('User ' . $username . ' is denied access - not in list of permitted users', E_USER_WARNING);
      return false;
    }
  }
}
?>
