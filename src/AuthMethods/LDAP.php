<?php
namespace AuthTools\AuthMethods;

class LDAP implements AuthMethodInterface
{
  private $server;
  private $full_domain;
  private $short_domain;
  
  public function __construct($server, $full_domain, $short_domain)
  {
    $this->server = $server;
    $this->full_domain = $full_domain;
    $this->short_domain = $short_domain;
  }
  
  /**
   * Aux function to extract shortname from username. Shortname is used in
   * config's authlist.
   *
   * @param   string  username in the format domain\\username or username@domain.com
   * @return  string  username without domain parts
   */
  public function formatUsername($username)
  {
    // remove domain part from username to search through autlist
    $domain_short = $this->short_domain . '\\';
    $domain_full  = '@' . $this->full_domain;

    $shortname = str_replace($domain_short, '' ,$username);
    $shortname = str_replace($domain_full,  '' ,$shortname);

    return $shortname;
  }

  /**
   * Checks user's credentials trying to bind to LDAP server.
   *
   * @param   string  username in the format domain\\username or username@domain.com
   * @param   string  password
   * @return  boolean
   */
  public function checkCredentials($username, $password)
  {
    if ( ! $connect = ldap_connect($this->server) )
      throw new \Exception(sprintf('Could not connect to LDAP server %s.', $this->server));

    ldap_set_option($connect, LDAP_OPT_PROTOCOL_VERSION, 3);

    if ( $bind = ldap_bind($connect, $username, $password) ) {
      return true;
    }
    else {
      if ( ldap_get_option($connect, LDAP_OPT_ERROR_STRING, $extended_error) ) {
        trigger_error("Error Binding to LDAP: $extended_error", E_USER_WARNING);
      } else {
        trigger_error("Error Binding to LDAP: No additional information is available.", E_USER_WARNING);
      }
      return false;
    }
  }
}
?>