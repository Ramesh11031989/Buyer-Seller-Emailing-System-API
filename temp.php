<?php
PHP header() Function
Definition and Usage
The header() function sends a raw HTTP header to a client.

It is important to notice that header() must be called before any actual output is sent (In PHP 4 and later, you can use output buffering to solve this problem):


<?php
// This results in an error.
// The output above is before the header() call
header('Location: http://www.example.com/');
?>

Syntax
header(string,replace,http_response_code)

Parameter	Description
string	Required. Specifies the header string to send
replace	Optional. Indicates whether the header should replace previous or add a second header. Default is TRUE (will replace). FALSE (allows multiple headers of the same type)
http_response_code	Optional. Forces the HTTP response code to the specified value (available in PHP 4.3 and higher)

Prevent page caching:

<?php
// Date in the past
header("Expires: Mon, 26 Jul 1997 05:00:00 GMT");
header("Cache-Control: no-cache");
header("Pragma: no-cache");
?>





/**

//response must be in formated
// $status = success or error

{
    
	"status" : "$status",
    
    "error": {
		"code": "$error_code",
		"message": "$error_messages",
    }
  }
}

**/

// Include config file
require_once '../pdo_config.php';
require_once '../vendor/autoload.php';

// define varables
$email_output =  "";
$email = "";
$password = "";
$quota = "";



//No filtering in Password, password should be checked for "Strong password" at the clint side
	//return 422 Unprocessable Entity response if Password or email id is blank or not submitted
		//return 422 Unprocessable Entity response if email is not valid

if(isset($_GET['password'])){
	$password = strip_tags('$_POST['password'])');
	$password = trim ($password)
}else{
	
	//return 422 Unprocessable Entity response
}



if(isset($_POST['$email'])){
	$email_output = strip_tags('$_POST['email'])');
	$email = filter_var($email_output, FILTER_SANITIZE_EMAIL);
	$email = trim ($email)
}else{
	
	//return 422 Unprocessable Entity response
}


if(empty($email) || empty($password)){
		//return 422 Unprocessable Entity response
}








function service_response($api_response){

   $http_response_code = array(
        200 => 'OK',
        400 => 'Bad Request',
        401 => 'Unauthorized',
        403 => 'Forbidden',
        404 => 'Not Found'
    );

    header('HTTP/1.1 '.$api_response['status'].' '.$http_response_code[ $api_response['status'] ]);
    header('Content-Type: application/json; charset=utf-8');
    $json_response = json_encode($api_response);
    echo $json_response;
    exit;
}

$api_response_code = array(
    0 => array('HTTP Response' => 400, 'Message' => 'Unknown Error'),
    1 => array('HTTP Response' => 200, 'Message' => 'Success'),
    2 => array('HTTP Response' => 403, 'Message' => 'HTTPS Required'),
    3 => array('HTTP Response' => 401, 'Message' => 'Authentication Required'),
    4 => array('HTTP Response' => 401, 'Message' => 'Authentication Failed'),
    5 => array('HTTP Response' => 404, 'Message' => 'Invalid Request'),
    6 => array('HTTP Response' => 400, 'Message' => 'Invalid Response Format')
);


if( isset($_GET['actionid']) && $_GET['actionid'] == 'login_user'){
    $email    = $_GET['email'];
    $password = $_GET['password'];
    $query    = mysql_query("SELECT user_id FROM user WHERE email = '".$email."' AND password = '".md5($password)."'");
    $data     = array();
        if(mysql_num_rows($query)>0) { 
            while($row = mysql_fetch_assoc($query)) {
                $data[] = $row;
            }
    $response['code']               = 1;
    $response['status']             = $api_response_code[$response['code']]['HTTP Response'];
    $response['response_message']   = $api_response_code[$response['code']]['Message'];
    $response['message']            = 'You are logged In successfully';
    $response['data']               = $data;
    service_response($response);    

        }else{

    $response['code']               = 3;
    $response['status']             = $api_response_code[$response['code']]['HTTP Response'];
    $response['response_message']   = $api_response_code[$response['code']]['Message'];
    $response['message']            = 'Please enter correct email address and password';
    $response['data']               = $data;
    service_response($response);
    }
}










$name = str_replace('%20', ' ', $name);

switch ($action) {
    case 'list_cpanel_api':
        insert_user($conn, $id, $name);
        break;
    case 'delete_cpanel_email':
        delete_email($conn, $id);
        break;
    default:
        echo 'Action not recognized';
        break;
    case 'create_cpanel_email':
        delete_email($conn, $id);
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
	
class create_cpanel_email(){



	<?php

// cPanel info
$cpuser = 'someusername'; // cPanel username
$cppass = 'somepassword'; // cPanel password
$cpdomain = 'somesite.com'; // cPanel domain or IP
$cpskin = 'someskin';  // cPanel skin. Mostly x or x2. 
// See following URL to know how to determine your cPanel skin
// http://www.zubrag.com/articles/determine-cpanel-skin.php

// Default email info for new email accounts
// These will only be used if not passed via URL
$epass = 'hispassword'; // email password
$edomain = 'somesite.com'; // email domain (usually same as cPanel domain above)
$equota = 20; // amount of space in megabytes


function getVar($name, $def = '') {
  if (isset($_REQUEST[$name]))
    return $_REQUEST[$name];
  else 
    return $def;
}

// check if overrides passed
$euser = getVar('user', '');
$epass = getVar('pass', $epass);
$edomain = getVar('domain', $edomain);
$equota = getVar('quota', $equota);

$msg = 'check';

if (!empty($euser))
while(true) {

  // Create email account
  $f = fopen ("http://$cpuser:$cppass@$cpdomain:2082/frontend/$cpskin/mail/doaddpop.html?email=$euser&domain=$edomain&password=$epass&quota=$equota", "r");
  if (!$f) {
    $msg = 'Cannot create email account. Possible reasons: "fopen" function allowed on your server, PHP is running in SAFE mode';
    break;
  }

  $msg = "<h2>Email account {$euser}@{$edomain} created.</h2>";

  // Check result
  while (!feof ($f)) {
    $line = fgets ($f, 1024);
    if (ereg ("already exists", $line, $out)) {
      $msg = "<h2>Email account {$euser}@{$edomain} already exists.</h2>";
      break;
    }
  }
  @fclose($f);

  break;

}
}
?>








$socket = fsockopen($cpdomain,2082);
$cuser = "YourUserName";
$cpassword = "YourPassword";
$authstr = base64_encode("".$cpuser.":".$cppass."");
$in = "GET /frontend/$cpskin/mail/doaddpop.html?email=$euser&$edomain&password=$epass&quota=$equota
HTTP/1.0\r\nAuthorization: Basic $authstr \r\n";
fputs($socket,$in);
fclose( $socket );








include("xmlapi.php");        //XMLAPI cpanel client class

$ip = "127.0.0.1";            // should be server IP address or 127.0.0.1 if local server
$account = "username";        // cpanel user account name
$passwd ="password";          // cpanel user password
$port =2083;                  // cpanel secure authentication port unsecure port# 2082
$email_domain ="example.com";
$email_user ="john";
$email_pass ="johnspassword";
$email_quota = 0;             // 0 is no quota, or set a number in mb

$xmlapi = new xmlapi($ip);
$xmlapi->set_port($port);     //set port number.
$xmlapi->password_auth($account, $passwd);
$xmlapi->set_debug(0);        //output to error file  set to 1 to see error_log.

$call = array(domain=>$email_domain, email=>$email_user, password=>$email_pass, quota=>$email_quota);

$result = $xmlapi->api2_query($account, "Email", "addpop", $call );

print_r($result);            //show the result of your query



	
}	
















class delete_cpanel_email(){
	
	Your form should POST to a page that calls this to create a new email:

Code:


include '../xmlapi.php';

$ip = ''; #IP of your cPanel/WHM server
$user = ''; #cpanel username
$pass = ''; #password of your cPanel user

$xmlapi = new xmlapi($ip);
$xmlapi->password_auth($user,$pass);
$xmlapi->set_port(2083);
$xmlapi->set_output("json");

$email = $_POST["email"];
$pass = $_POST["pass"];

$params = array(
     'domain' => '', #domain to add the email to
     'email' => $email, #part of email before @ symbol
     'password' => $pass, #hopefully a strong, randomly generated password
     'quota' => 1000 #size in MB to allow the account to use
);

$xmlapi->set_debug(1);
print $xmlapi->api2_query($user, "Email", "addpop", $params );

}



















class list_cpanel_api(){
	
	
	
	
	Here's an example of listing the emails:

Code:
<?php
include '../xmlapi.php';

$ip = ''; #IP of your cPanel/WHM server
$user = ''; #cpanel username
$pass = ''; #password of your cPanel user

$xmlapi = new xmlapi($ip);
$xmlapi->password_auth($user,$pass);
$xmlapi->set_port(2083);
$xmlapi->set_output("json");

$xmlapi->set_debug(1);
print $xmlapi->api2_query($user, "Email", "listpopswithdisk" );
?>
Then you'll want to use json_decode() to pull the JSON into a PHP object and then loop through the results and print them out for people to see. You can copy the format of the email screen in cPanel for a basis for your UI.
}
?>