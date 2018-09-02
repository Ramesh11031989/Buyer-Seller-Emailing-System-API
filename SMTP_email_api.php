<?php
// Include config file
require_once 'pdo_config.php';
require_once 'vendor/autoload.php';


$action = $_GET['action'];
$id = $_GET['id'];
$name = $_GET['name'];

$name = str_replace('%20', ' ', $name);

switch ($action) {
    case 'verifyEmail':
        insert_user($conn, $id, $name);
        break;
    case 'email_delete':
        delete_email($conn, $id);
        break;
    default:
        echo 'Action not recognized';
        break;
}

 
// Define variables and initialize with empty values
$username = $password = "";
$username_err = $password_err = "";
$passwordAttempt = 0;   // for counting login attampt

 
// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){
 
	//senetise the username and password
	
	$username = stripslashes($_POST["username"]); 

	$password = stripslashes ($_POST["password"]); 
	
  //Retrieve the user account information for the given username.
    $sql = "SELECT id, username, password FROM users WHERE username = :username";
    $stmt = $pdo->prepare($sql);
    
    //Bind value.
    $stmt->bindValue(':username', $username);
    
    //Execute.
    $stmt->execute();
    
    //Fetch row.
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
	




/**
This class can be used to check if an e-mail is valid using the SMTP protocol.

It can connect to an SMTP server defined by the MX records of the domain of the address to validate.

The class simulates the delivery of a message to see if the given recipient address is accepted as valid.

        <?php
        include_once 'class.verifyEmail.php';
        $email = 'noreplybbbbbbb@gmail.com';
        $vmail = new verifyEmail();
        if ($vmail->check($email)) {
            echo 'email &lt;' . $email . '&gt; exist!';
        } elseif ($vmail->isValid($email)) {
            echo 'email &lt;' . $email . '&gt; valid, but not exist!';
        } else {
            echo 'email &lt;' . $email . '&gt; not valid and not exist!';
        }
        ?>
		
You should check with SMTP.

That means you have to connect to that email's SMTP server.

After connecting to the SMTP server you should send these commands:

HELO somehostname.com
MAIL FROM: <no-reply@gmail.com>
RCPT TO: <emailtovalidate@domain.com>
If you get "<emailtovalidate@domain.com>: Relay access denied" that means this email in invalid.

Spammers do the connection trick too so don't assume that all servers will respond the same way. One of the other answers links to this library which has this caveat

Some mail servers will silently reject the test message, to prevent spammers from checking against their users' emails and filter the valid emails, so this function might not work properly with all mail servers.

So if there's an invalid address you might not get an invalid address response. The top upvoted answer doesn't mention this.

Spam lists. Yes, you can get blacklisted trying to do this (remember I said spammers know these tricks too). They blacklist by IP address and if your server is constantly doing verification connections you run the risk of winding up on Spamhaus or another block list. If you get blacklisted, what good does it do you to validate the email address?

If it's really that important to verify an email address the accepted way is to force the user to respond to an email. Send them a full email with a link they have to click to be verified. It's not spammy, and you still get to verify if it's valid.







How to Check if cPanel User Exists using cpanel API2 in PHP



cPanel is a cool software and allows you to automate many things.

If you want to check if a username exists you can use accountsummary API call.

 

$ip = "127.0.0.1"; // should be server IP address or 127.0.0.1 if local server
$port = 2087; // cpanel secure authentication port unsecure port# 2082
$cp_username = 'user';
$cp_passwd = 'pass';

$username = 'some_cpanel_user';

$xmlapi = new xmlapi($ip);
$xmlapi->set_port($port);  //set port number. cpanel client class allow you to access WHM as well using WHM port.
$xmlapi->password_auth($cp_username, $cp_passwd);   // authorization with password. not as secure as hash.
$xmlapi->set_debug(1);      //output to error file  set to 1 to see error_log.

$xml_res = $xmlapi->accountsummary( $username );

$yes = ! empty( $xml_res->status );
Response

object(SimpleXMLElement)#3 (3) {
  ["acct"]=>
  object(SimpleXMLElement)#4 (31) {
    ["backup"]=>
    string(1) "0"
    ["disklimit"]=>
    string(9) "unlimited"
    ["diskused"]=>
    string(2) "0M"
    ["domain"]=>
    string(26) "orbisius.com"
    ["email"]=>
    string(9) "*unknown*"
    ["ip"]=>
    string(13) "1.2.3.4"
    ["is_locked"]=>
    string(1) "0"
    ["legacy_backup"]=>
    string(1) "0"
    ["max_defer_fail_percentage"]=>
    string(9) "unlimited"
    ["max_email_per_hour"]=>
    string(9) "unlimited"
    ["maxaddons"]=>
    string(9) "*unknown*"
    ["maxftp"]=>
    string(9) "*unknown*"
    ["maxlst"]=>
    string(9) "unlimited"
    ["maxparked"]=>
    string(9) "*unknown*"
    ["maxpop"]=>
    string(9) "unlimited"
    ["maxsql"]=>
    string(9) "unlimited"
    ["maxsub"]=>
    string(9) "unlimited"
    ["min_defer_fail_to_trigger_protection"]=>
    string(1) "5"
    ["outgoing_mail_hold"]=>
    string(1) "0"
    ["outgoing_mail_suspended"]=>
    string(1) "0"
    ["owner"]=>
    string(5) "weeuu"
    ["partition"]=>
    string(4) "home"
    ["plan"]=>
    string(11) "weeuu_plan1"
    ["shell"]=>
    string(29) "/usr/local/cpanel/bin/noshell"
    ["startdate"]=>
    string(15) "16 Apr 29 17:40"
    ["suspended"]=>
    string(1) "0"
    ["suspendreason"]=>
    string(13) "not suspended"
    ["suspendtime"]=>
    string(1) "0"
    ["theme"]=>
    string(13) "paper_lantern"
    ["unix_startdate"]=>
    string(10) "1461966001"
    ["user"]=>
    string(2) "w1"
  }
  ["status"]=>
  string(1) "1"
  ["statusmsg"]=>
  string(2) "Ok"
}
















<?php
//exampledot.com for domain

$cpuser = 'exampled';////////////e.g. exampled, your cPanel main domain usually
$cppass = 'CPANEL-PASSWORD';/////Your cPanel password.
$cpdomain = 'exampledot.com';////The cPanel domain
$cpskin = 'justhost';////////////listed on cPanel as 'theme'
$emailname = 'john1';/////////////The username, e.g. john1@exampledot.com
$emaildomain = 'exampledot.com';////The domain name in email, @exampledot.com
$emailpass = 'EMAIL_PASSWORD';////The password for the email account
$quota = '25';///////////////////Megabytes of space, 0 for unlimited


$homepage = file_get_contents("https://$cpuser:$cppass@$cpdomain:2083/frontend/$cpskin/mail/doaddpop.html?email=$emailname&domain=$emaildomain&password=$emailpass&quota=$quota");
echo $homepage;
?>














if($epass==$epass1)
{

  // Create email account process starts
  //open the cpanel url
  $url = fopen ("http://$cp_user:$cp_pass@$cp_domain:2082/frontend/$cp_skin/mail/doaddpop.html?email=$user&domain=$e_domain&password=$e_pass&quota=$e_quota", "r");
  if (!$url) {
    $message = 'Unable to create email account. Possible reasons: "fopen" function allowed on your server, PHP is running in SAFE mode';
    break;
  }

  $message = "Email account {$user}@{$e_domain} created.";

  // Check result
  while (!feof ($url)) {
    $line = fgets ($url, 1024);
    if (ereg ("already exists", $line, $out)) {
      $message = "Email ID {$user}@{$e_domain} already exists.";
      break;
    }
  }
  @fclose($url);
  break;
}
else
{
$error="Password Mismatch";	//echo $error;
break;
}
}
**/	










	
	

/**
 * Class to check up e-mail
 *
 * @author Konstantin Granin <kostya@granin.me>
 * @copyright Copyright (c) 2010, Konstantin Granin
 */
class verifyEmail {
    /**
     * User name
     * @var string
     */
    private $_fromName;
    /**
     * Domain name
     * @var string
     */
    private $_fromDomain;
    /**
     * SMTP port number
     * @var int
     */
    private $_port;
    /**
     * The connection timeout, in seconds.
     * @var int
     */
    private $_maxConnectionTimeout;
    /**
     * The timeout on socket connection
     * @var int
     */
    private $_maxStreamTimeout;
    public function __construct() {
        $this->_fromName = 'noreply';
        $this->_fromDomain = 'localhost';
        $this->_port = 25;
        $this->_maxConnectionTimeout = 30;
        $this->_maxStreamTimeout = 5;
    }
    /**
     * Set email address for SMTP request
     * @param string $email Email address
     */
    public function setEmailFrom($email) {
        list($this->_fromName, $this->_fromDomain) = $this->_parseEmail($email);
    }
    /**
     * Set connection timeout, in seconds.
     * @param int $seconds
     */
    public function setConnectionTimeout($seconds) {
        $this->_maxConnectionTimeout = $seconds;
    }
    /**
     * Set the timeout on socket connection
     * @param int $seconds
     */
    public function setStreamTimeout($seconds) {
        $this->_maxStreamTimeout = $seconds;
    }
    /**
     * Validate email address.
     * @param string $email
     * @return boolean  True if valid.
     */
    public function isValid($email) {
        return (false !== filter_var($email, FILTER_VALIDATE_EMAIL));
    }
    /**
     * Get array of MX records for host. Sort by weight information.
     * @param string $hostname The Internet host name.
     * @return array Array of the MX records found.
     */
    public function getMXrecords($hostname) {
        $mxhosts = array();
        $mxweights = array();
        if (getmxrr($hostname, $mxhosts, $mxweights)) {
            array_multisort($mxweights, $mxhosts);
        }
        /**
         * Add A-record as last chance (e.g. if no MX record is there).
         * Thanks Nicht Lieb.
         */
        $mxhosts[] = $hostname;
        return $mxhosts;
    }
    /**
     * check up e-mail
     * @param string $email Email address
     * @return boolean True if the valid email also exist
     */
    public function check($email) {
        $result = false;
        if ($this->isValid($email)) {
            list($user, $domain) = $this->_parseEmail($email);
            $mxs = $this->getMXrecords($domain);
            $fp = false;
            $timeout = ceil($this->_maxConnectionTimeout / count($mxs));
            foreach ($mxs as $host) {
//                if ($fp = @fsockopen($host, $this->_port, $errno, $errstr, $timeout)) {
                if ($fp = @stream_socket_client("tcp://" . $host . ":" . $this->_port, $errno, $errstr, $timeout)) {
                    stream_set_timeout($fp, $this->_maxStreamTimeout);
                    stream_set_blocking($fp, 1);
//                    stream_set_blocking($fp, 0);
                    $code = $this->_fsockGetResponseCode($fp);
                    if ($code == '220') {
                        break;
                    } else {
                        fclose($fp);
                        $fp = false;
                    }
                }
            }
            if ($fp) {
                $this->_fsockquery($fp, "HELO " . $this->_fromDomain);
                //$this->_fsockquery($fp, "VRFY " . $email);
                $this->_fsockquery($fp, "MAIL FROM: <" . $this->_fromName . '@' . $this->_fromDomain . ">");
                $code = $this->_fsockquery($fp, "RCPT TO: <" . $user . '@' . $domain . ">");
                $this->_fsockquery($fp, "RSET");
                $this->_fsockquery($fp, "QUIT");
                fclose($fp);
                if ($code == '250') {
                    /**
                     * http://www.ietf.org/rfc/rfc0821.txt
                     * 250 Requested mail action okay, completed
                     * email address was accepted
                     */
                    $result = true;
                } elseif ($code == '450' || $code == '451' || $code == '452') {
                    /**
                     * http://www.ietf.org/rfc/rfc0821.txt
                     * 450 Requested action not taken: the remote mail server
                     *     does not want to accept mail from your server for
                     *     some reason (IP address, blacklisting, etc..)
                     *     Thanks Nicht Lieb.
                     * 451 Requested action aborted: local error in processing
                     * 452 Requested action not taken: insufficient system storage
                     * email address was greylisted (or some temporary error occured on the MTA)
                     * i believe that e-mail exists
                     */
                    $result = true;
                }
            }
        }
        return $result;
    }
    /**
     * Parses input string to array(0=>user, 1=>domain)
     * @param string $email
     * @return array
     * @access private
     */
    private function _parseEmail(&$email) {
        return sscanf($email, "%[^@]@%s");
    }
    /**
     * writes the contents of string to the file stream pointed to by handle $fp
     * @access private
     * @param resource $fp
     * @param string $string The string that is to be written
     * @return string Returns a string of up to length - 1 bytes read from the file pointed to by handle.
     * If an error occurs, returns FALSE.
     */
    private function _fsockquery(&$fp, $query) {
        stream_socket_sendto($fp, $query . "\r\n");
        return $this->_fsockGetResponseCode($fp);
    }
    /**
     * Reads all the line long the answer and analyze it.
     * @access private
     * @param resource $fp
     * @return string Response code
     * If an error occurs, returns FALSE
     */
    private function _fsockGetResponseCode(&$fp) {
	$reply = stream_get_line($fp, 1);
	$status = stream_get_meta_data($fp);
	if ($status['unread_bytes']>0)
	{
		$reply .= stream_get_line($fp, $status['unread_bytes'],"\r\n");
	}
        preg_match('/^(?<code>[0-9]{3}) (.*)$/ims', $reply, $matches);
        $code = isset($matches['code']) ? $matches['code'] : false;
        return $code;
    }
}
	
	
	


class email_read(){
	
	
}

class email_write(){
	
	
	
}

class email_set_as_read(){
	
	
}


class email_set_as_unread(){
	
	
}
?>