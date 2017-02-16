# AuthTools
===

The package provides unified interface to authenticate and authorize users against various auth systems.

Currently implemented auth systems are:
* Active Directory LDAP
* apache htpasswd file

Users are authenticated against a chosed method using supplied credentials. And afterwards they're being authorized via special ACL.

### Installation
------
The package is intended to be used via Composer. It currently is not on Packagist, so add this repository description to you composer.json:
```
    "repositories": [
        {
            "type": "vcs",
            "url": "https://github.com/efoft/auth-tools"
        },
    ]
```
and require it:
```
    "require": {
        "efoft/auth-tools" : "dev-master"
    }
```
### Initialization
------
The package consists of the main class Auth and some auth systems Methods. When initialize the class instance you need to specify one of the Method. 
$auth = new Auth(<Method>, <ACL>);

Each type of Methods in turn requires some parameters for an auth system connection.

* LDAP
```
use AuthTools\Auth;
use AuthTools\AuthMethods\LDAP;

$auth = new Auth(new LDAP('dc.example.com','example.com','EXAMPLE'), $acl);
```
Arguments of LDAP Method:
  1st = resolvable name or IP of LDAP server;
  2nd = FQDN of domain name;
  3rd = short name of domain.

* htpasswd
```
use AuthTools\Auth;
use AuthTools\AuthMethods\HTPasswd;

$auth = new Auth(new HTPasswd('/etc/httpd/htusers'), $acl);
```
Arguments of HTPasswd Method:
  1st = full path to the credentials file created with htpasswd command.

#### ACL
This must be an associative array with usernames as keys and series of digits as permitted levels of access. E.g.:
```
$acl = array(
  'user1' => '0123',
  'user3' => '0124'
);
```
The above means that user1 (if the credentials was successfully verified) is
1) in the access list so that allowed to access the project
2) has access levels 0,1,2 and 3 - this levels can be later used in the project code to limit access to different parts of application. See below the usage examples.

### Usage

Check if the user is already authed. The procedure also checks for $_POST if auth request is supplied and in such case verifies credentianls:
```
if ( ! $auth->checkAuth() ) {
  header('Location: login.php');
  exit;
}
```
To perform auth there must be supplied parameters in the $_POST:
* $_POST['authrequest'] must be set
* $_POST['username'] must be set and not empty
* $_POST['password'] must be set and not empty

Important! Usernames are formatted to lowercase for validation, so they must be always specified lowercased in ACL.

Once authed the auth info is stored in the $_SESSION.

#### Logout
Auth information in the $_SESSION is destroyed.
```
$auth->logout()
```

#### Check authorization for a level
Check if currently authenticated user has access to a certain access level. Put in the beginning of the code to protect:
```
if ( ! $auth->checkAuthLevel('2') ) {
  echo 'access denied';
  return;
}
```

#### Get info
Currently authorized user:
```
$authname = $auth->getAuthName();
```
