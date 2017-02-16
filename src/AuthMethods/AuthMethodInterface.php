<?php
namespace AuthTools\AuthMethods;

interface AuthMethodInterface
{
  public function formatUsername($username);
  public function checkCredentials($username, $password);
}
?>