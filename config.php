<?php
// place this file at any place except web root and change require path api files
//passwords seting and variables

$config_vars = array();    //Associative array for saving config vars (key => value;)

// domain name for email id(used for buyer, seller and admin emails)
$config_vars['email_domain']	= "example.com";   //without www or htttp

// email quota in MB
// cPanel info
$config_vars['cpuser'] = 'lwo1z1f58y8p'; // cPanel username
$config_vars['cppass'] = '#73^Do@it)noW'; // cPanel password
$config_vars['cpdomain'] = 'rameshkumar.xyz'; // cPanel domain or IP
$config_vars['cpskin'] = 'gl_paper_lantern';  // cPanel skin. Mostly x or x2
$config_vars['ip'] = '166.62.28.112'; //cPanel IP address

// See following URL to know how to determine your cPanel skin
// http://www.zubrag.com/articles/determine-cpanel-skin.php

// Default email info for new email accounts
$config_vars['epass'] = 'Default@123'; // default email password for all created  emails
$config_vars['edomain'] = 'rameshkumar.xyz'; // email domain (usually same as cPanel domain above)
$config_vars['quota'] = 10; // amount of space in megabytes

// OTP expire time (in seconds)
$config_vars['otp_expire_time']	= 300;

//Connection settings
$config_vars['db_host_name']	= "localhost";
$config_vars['db_name']			= "bses";
$config_vars['db_user_name']	= "root";
$config_vars['db_password']		= "";
$config_vars['db_charset']		= "utf8mb4";
$config_vars['db_dsn'] 			= "mysql:host = db_host_name;dbname = db_name;charset = db_charset";
$config_vars['db_opt']			= [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false
];


//PHPMailer Server settings
$config_vars['SMTPDebug']		= 0;							// Enable verbose debug output, $mail->SMTPDebug = SMTP::DEBUG_SERVER, $mail->SMTPDebug = 2; //Alternative to first constant(SMTP::DEBUG_SERVER)
$config_vars['isSMTP']			= true;							// Set mailer to use SMTP
$config_vars['Host']			= 'smtp.gmail.com';				// Specify main and backup SMTP servers
$config_vars['SMTPAuth']		= true;							// Enable SMTP authentication
$config_vars['Username']		= 'ee08249@gmail.com';			// SMTP username
$config_vars['Password']		= 'izireqfrgigxummt';			// SMTP password
$config_vars['SMTPSecure']		= 'tls';						// Enable TLS encryption, `ssl` also accepted
$config_vars['Port']			= 587;							// TCP port to connect to
$config_vars['setFrom']			= 'RameshKumar@example.com';	//'RameshKumar@example.com', '-Ramesh Kumar'
$config_vars['addReplyTo']		= 'RameshKumar@example.com';	//'info@example.com', 'Information'
?>