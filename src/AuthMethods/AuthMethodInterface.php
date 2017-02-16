<?php
namespace AuthTools\AuthMethods;

interface AuthMethodInterface
{
  public function setDebug($debug);
  public function formatUsername($username);
  public function checkCredentials($username, $password);
}
?>