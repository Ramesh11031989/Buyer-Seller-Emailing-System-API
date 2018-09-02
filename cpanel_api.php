<?php
$config_vars = array();    //Associative array for saving config vars (key => value;)

// domain name for email id(used for buyer, seller and admin emails)
$config_vars['email_domain']	= "example.com";   //without www or htttp

// email quota in MB
// cPanel info
$config_vars['cpuser'] = 'lwo1z1f58y8p'; // cPanel username
$config_vars['cppass'] = '#73^Do@it)noW'; // cPanel password
$config_vars['cpdomain'] = 'rameshkumar.xyz'; // cPanel domain or IP
$config_vars['cpskin'] = 'gl_paper_lantern'; // cPanel skin. Mostly x or x2 

// Default email info for new email accounts
$config_vars['epass'] = 'Default@123'; // default email password for all created  emails
$config_vars['edomain'] = 'rameshkumar.xyz'; // email domain (usually same as cPanel domain above)
$config_vars['quota'] = 10; // amount of space in megabytes
/**
include 'vendor/xmlapi.php';
$ip = "166.62.28.112";
$root_pass = $config_vars['cppass'];
$account = $config_vars['cpuser'];
$email_user = "new_email";
$email_password = "Default@123";
$email_domain = "rameshkumar.xyz";
$email_query = '10';
$xmlapi = new xmlapi($ip);
$xmlapi->set_port(2083); //2082 if not using secure connection
$xmlapi->password_auth("root",$root_pass);
$xmlapi->set_output('json');
$xmlapi->set_debug(1);

print $xmlapi->api1_query($account, "Email", "addpop", array($email_user, $email_password, $config_vars['quota'], $email_domain) );
**/
include 'vendor/xmlapi.php';
$ip = "166.62.28.112";
$root_pass = $config_vars['cppass'];
$account = $config_vars['cpuser'];
$xmlapi = new xmlapi($ip);
$xmlapi->password_auth("root",$root_pass);
$xmlapi->set_output("json");
$xmlapi->set_debug(1);
print $xmlapi->api2_query($account, "Email", "listpopswithdisk" );


?>