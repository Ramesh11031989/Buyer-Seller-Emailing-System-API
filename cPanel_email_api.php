<?php
ob_start();

// Import PHPMailer classes into the global namespace
// These must be at the top of your script, not inside a function
use \PHPMailer\PHPMailer\PHPMailer;
use \PHPMailer\PHPMailer\Exception;
// Include config file
require_once ('../vendor/autoload.php');
require_once ('config.php');

// define varables
$email_output	= "";
$email			= "";
$password		= "";
$data			= array();

//Class for cPanel email creation
class create_cpanel_email{

	public $euser		= NULL;
	public $config_vars	= NULL;
	public $cpuser		= NULL;
	public $cppass		= NULL;
	public $cpdomain	= NULL;
	public $cpskin		= NULL;
	public $epass		= NULL;
	public $edomain		= NULL;
	public $quota		= NULL;
	public $parts		= NULL;
	public $msg			= 'check';
	
	public function __construct($email, $config_vars){
		$parts = explode("@", "$email");
		$this->euser = $parts[0];
		$this->config_vars	= $config_vars;

	// cPanel info
	$this->cpuser		= $config_vars['cpuser'];
	$this->cppass		= $config_vars['cppass'];
	$this->cpdomain		= $config_vars['cpdomain'];
	$this->cpskin		= $config_vars['cpskin'];
	$this->epass		= $config_vars['epass'];
	$this->edomain		= $config_vars['edomain'];
	$this->quota		= $config_vars['quota'];
	}
	
	public function create(){
		if (!empty($euser))
		while(true) {

		  // Create email account
		  $f = fopen ("http://$cpuser:$cppass@$cpdomain:2082/frontend/$cpskin/mail/doaddpop.html?email=$euser&domain=$edomain&password=$epass&quota=$quota", "r");
		  if (!$f) {
			return FALSE;
			break;
		  }
			return TRUE;

		  // Check result
		  while (!feof ($f)) {
			$line = fgets ($f, 1024);
			if (ereg ("already exists", $line, $out)) {
			return FALSE;
			  break;
			}
		  }
		  @fclose($f);

		  break;

		}
	}
}//end of cpanel create





//email_otp class
class email_otp extends PHPMailer{
	public $email		= NULL;
	public $first_name	= NULL;
	public $otp			= NULL;
	public $isSMTP		= NULL;
	public $SMTPDebug	= NULL;
	public $Host		= NULL;
	public $SMTPAuth	= NULL;
	public $Username	= NULL;
	public $Password	= NULL;
	public $SMTPSecure	= NULL;
	public $Port		= NULL;
	
	public function __construct($email, $otp, $first_name, $config_vars){
		$this->email		= $email;
		$this->otp			= $otp;
		$this->config_vars	= $config_vars;
		$this->first_name	= $first_name;
		parent::__construct();
	}
	public function send_email(){
	//code for sending otp email
	$mail = new PHPMailer(true);   // Passing `true` enables exceptions
		try {
			//Server settings
			if($this->config_vars['isSMTP'] == true){
				$mail->isSMTP();
			}
			$mail->SMTPDebug	= $this->config_vars['SMTPDebug'];
			$mail->Host			= $this->config_vars['Host'];
			$mail->SMTPAuth		= $this->config_vars['SMTPAuth'];
			$mail->Username		= $this->config_vars['Username'];
			$mail->Password		= $this->config_vars['Password'];
			$mail->SMTPSecure	= $this->config_vars['SMTPSecure'];
			$mail->Port			= $this->config_vars['Port'];
			$setFrom			= $this->config_vars['setFrom'];
			$addReplyTo			= $this->config_vars['addReplyTo'];
			
			//Recipients
			$mail->addAddress($this->email, $this->first_name);     // Add a recipient
			$mail->setFrom($setFrom);
			$mail->addReplyTo($addReplyTo);

			//Content
			$mail->isHTML(false);                                  //true = Set email format to HTML
			$mail->Subject = 'OTP for BSES';
			$mail->Body = "Dear $this->first_name your One Time Pass Key for changing password is [$this->otp] Plese do not share otp with anyone.";
			$err = $mail->send();
			return ($err);
			
		} catch (Exception $e) {
			//echo 'Message could not be sent. Mailer Error: ', $mail->ErrorInfo;
			return false;
		}
	}
}

//db class
class DB extends PDO{
	Public static $pdo		= NULL;

    private function __construct() 
    {

    }
    private function __clone()
    {

    }   
    public static function getInstance($db_host_name, $db_name, $db_user_name, $db_password, $db_charset, $db_opt, $db_dsn) {

        if (!self::$pdo)
        {
			try {
            self::$pdo = new PDO($db_dsn, $db_user_name, $db_password, $db_opt);
			} 
			catch (PDOException $exception) {
				$exception_message = $exception->getMessage();
				//echo("$exception_message");
			}


			// and now we're done; close the connection
			//   $pdo = null;
        }
        return self::$pdo;
    }
}//db class end

//supported method GET, POST, PUT, DELETE, OPTIONS
class REST {
        public $_allow = array();
        public $_content_type = "application/json";
        public $_request = array();
         
        private $_method = "";      
        public $_code = 200;
        protected $db_host_name	= NULL;
		protected $db_name		= NULL;
		protected $db_user_name	= NULL;
		protected $db_password	= NULL;
		protected $db_charset	= NULL;
		protected $db_dsn 		= NULL;
		protected $db_opt		= NULL;
		protected $quota		= NULL;
		protected $email_domain	= NULL;
		
        public function __construct($config_vars){
			$this->db_host_name	= $config_vars['db_host_name'];
			$this->db_name		= $config_vars['db_name'];
			$this->db_user_name	= $config_vars['db_user_name'];
			$this->db_password	= $config_vars['db_password'];
			$this->db_charset	= $config_vars['db_charset'];
			$this->db_dsn		= $config_vars['db_dsn'];
			$this->db_opt		= $config_vars['db_opt'];
			$this->quota		= $config_vars['quota'];
			$this->email_domain	= $config_vars['email_domain'];
			api::__construct($config_vars);
        }
         
        public function get_referer(){
            return $_SERVER['HTTP_REFERER'];
        }

        public function response($status){
            $this->_code = ($status)?$status:200;
            $this->set_headers();
            
        }
         
        public function get_status_message(){
            $status = array(
                        100 => 'Continue',  
                        101 => 'Switching Protocols',  
                        200 => 'OK',
                        201 => 'Created',  
                        202 => 'Accepted',  
                        203 => 'Non-Authoritative Information',  
                        204 => 'No Content',  
                        205 => 'Reset Content',  
                        206 => 'Partial Content',  
                        300 => 'Multiple Choices',  
                        301 => 'Moved Permanently',  
                        302 => 'Found',  
                        303 => 'See Other',  
                        304 => 'Not Modified',  
                        305 => 'Use Proxy',  
                        306 => '(Unused)',  
                        307 => 'Temporary Redirect',  
                        400 => 'Bad Request',  
                        401 => 'Unauthorized',  
                        402 => 'Payment Required',  
                        403 => 'Forbidden',  
                        404 => 'Not Found',  
                        405 => 'Method Not Allowed',  
                        406 => 'Not Acceptable',  
                        407 => 'Proxy Authentication Required',  
                        408 => 'Request Timeout',  
                        409 => 'Conflict',  
                        410 => 'Gone',  
                        411 => 'Length Required',  
                        412 => 'Precondition Failed',  
                        413 => 'Request Entity Too Large',  
                        414 => 'Request-URI Too Long',  
                        415 => 'Unsupported Media Type',  
                        416 => 'Requested Range Not Satisfiable',  
                        417 => 'Expectation Failed',  
						422 => 'Unprocessable Entity response',
                        500 => 'Internal Server Error',  
                        501 => 'Not Implemented',  
                        502 => 'Bad Gateway',  
                        503 => 'Service Unavailable',  
                        504 => 'Gateway Timeout',  
                        505 => 'HTTP Version Not Supported');
            return ($status[$this->_code])?$status[$this->_code]:$status[500];
        }
         
        public function get_request_method(){
            return $_SERVER['REQUEST_METHOD'];
        }

        private function set_headers(){
            header("HTTP/1.1 ".$this->_code." ".$this->get_status_message());
            header("Content-Type:".$this->_content_type);
			if($_SERVER['REQUEST_METHOD'] == "OPTIONS"){
				header('Allow: GET,POST,PUT,DELETE,OPTIONS');
			}
        }
    }  

     

     
class API extends REST {
    public $config_vars = array();
	Public function __construct($config_vars){
		$this->config_vars = $config_vars;
	}
     
    /*
     * Public method for access api.
     * This method dynmically call the method based on the query string
     *
     */
public function processApi(){
//        $func = strtolower(trim(str_replace("/","",$_REQUEST['request'])));
//		if((int)method_exists($this,$func) > 0){
//          $this->$func();
//		}
		$get_request_method = $_SERVER['REQUEST_METHOD'];
		if($get_request_method == 'POST'){
			parse_str(file_get_contents("php://input"), $post_vars);
			//get all posted values
			//user_type = 0, default value is used(uncomment to pass and use this value, 0 = buyer, 1 = seller, 2 = admin)
			$this->create_user(isset($_POST['email'])			?trim(strtolower(strip_tags($_POST['email'])))			:NULL,
								isset($_POST['password'])		?trim(strip_tags($_POST['password']))					:NULL,
								isset($_POST['user_type'])		?trim(strip_tags($_POST['user_type']))					:0,
								isset($_POST['first_name'])		?trim(strtolower(strip_tags($_POST['first_name'])))		:NULL,
								isset($_POST['last_name'])		?trim(strtolower(strip_tags($_POST['last_name'])))		:NULL,
								isset($_POST['mobile'])			?trim(strip_tags(abs($_POST['mobile'])))				:NULL)
								;
		}
		elseif($get_request_method == 'DELETE'){
			parse_str(file_get_contents("php://input"), $post_vars);
			//get all posted values
			$this->delete_email(isset($post_vars['email'])		?trim(strtolower(strip_tags($post_vars['email'])))		:NULL,
								isset($post_vars['password'])	?trim(strip_tags($post_vars['password']))				:NULL);
		}
		elseif($get_request_method == 'GET'){
//			parse_str(file_get_contents("php://input"), $post_vars);print_r($post_vars);
			$this->get_email(isset($_GET['email'])				?trim(strtolower(strip_tags($_GET['email'])))			:NULL);
		}
		elseif($get_request_method == 'PUT'){
			parse_str(file_get_contents("php://input"), $post_vars);
			//get all posted values
			//user_type = 0, default value is used(uncomment to pass and use this value, 0 = buyer, 1 = seller, 2 = admin)
			$this->put_email(isset($post_vars['email'])				?trim(strtolower(strip_tags($post_vars['email'])))			:NULL,
								isset($post_vars['password'])		?trim(strip_tags($post_vars['password']))					:NULL,
								isset($post_vars['user_type'])		?trim(strip_tags($post_vars['user_type']))					:NULL,
								isset($post_vars['first_name'])		?trim(strtolower(strip_tags($post_vars['first_name'])))		:NULL,
								isset($post_vars['last_name'])		?trim(strtolower(strip_tags($post_vars['last_name'])))		:NULL,
								isset($post_vars['mobile'])			?trim(strip_tags(abs($post_vars['mobile'])))				:NULL,
								isset($post_vars['new_password'])	?trim(strtolower(strip_tags($post_vars['new_password'])))	:NULL,
								isset($post_vars['otp'])			?trim(strtolower(strip_tags($post_vars['otp'])))			:NULL);
		}
		elseif($get_request_method == 'OPTIONS'){
//			parse_str(file_get_contents("php://input"), $post_vars);print_r($post_vars);
			$this->options();
		}
		else{
            $this->response(406);   // If the method not exist with in this class, response would be "Not Acceptable".
		}
}

//genreate hashed_email

function hash_email($user_email, $user_type, $email_domain){
	$hashed_email_id = NULL;

	//buyer email	buy+herwd4x@xdomain.com
		if($user_type == 0){  //check for buyer
		
			$hashed_email_id  = 'buy+';
			$hashed_email_id .= md5("$user_email".date("Y-m-d h:i:s"));
			$hashed_email_id .= "@";			
			$hashed_email_id .= $email_domain;
		}

	
	//seller email	sel+2qwd2f@xdomain.com
		if($user_type == 1){  //check for buyer
		
			$hashed_email_id  = 'sel+';
			$hashed_email_id .= md5("$user_email".date("Y-m-d h:i:s"));
			$hashed_email_id .= "@";			
			$hashed_email_id .= $email_domain;
		
		}

	//admin email	adm+herwd4x@xdomain.com
		if($user_type == 2){  //check for admin
		
			$hashed_email_id  = 'adm+';
			$hashed_email_id .= md5("$user_email".date("Y-m-d h:i:s"));
			$hashed_email_id .= "@";			
			$hashed_email_id .= $email_domain;
		}
		
		return $hashed_email_id;

}

function getToken($length){
     $token = NULL;
     $codeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
     $codeAlphabet.= "abcdefghijklmnopqrstuvwxyz";
     $codeAlphabet.= "0123456789";
     $max = strlen((string)$codeAlphabet); // edited

    for ($i=0; $i < $length; $i++) {
        $token .= $codeAlphabet[random_int(0, $max-1)];
    }

    return $token;
}

private function get_data($email){
	$username		= $email;
	$hashed_email	= NULL;
	//Retrieve the hashed email for the given email id.
    //Construct the SQL statement and prepare it.
	$pdo = DB::getInstance($this->db_host_name, $this->db_name, $this->db_user_name, $this->db_password, $this->db_charset, $this->db_opt, $this->db_dsn);
	if($pdo){
		$sql = "SELECT username, hashed_email, first_name, last_name, mobile FROM $this->db_name.users WHERE username = :username";
		$stmt = $pdo->prepare($sql);
		
		//Bind the provided username to our prepared statement.
		$stmt->bindValue(':username', $username);
		
		//Execute.
		$stmt->execute();
		
		//Fetch the row.
		$row = $stmt->fetch(PDO::FETCH_ASSOC);	

		$pdo = NULL;
		//If $row is TRUE.
		if($row['hashed_email']){
			//User account found.
			$this->response(200);
			return $row;

		}
		else{
			//Could not find a user with that username!
			$this->response(404);
			return NULL;
		}
	}
	else{
		$this->response(500);
		}
	$pdo = NULL;
}// end of get_data

//return supported options/ methodes
private function options(){
			$this->response(200);
			$error_code		= $this->_code;
			$status_code	= ($this->_code === 200)?"success":"error";
			$error_messages	= $this->get_status_message();

			//create array for json encode
			$data["status"]			= $status_code;
			$data["allow"] 			= array("HEAD", "GET", "PUT", "DELETE", "OPTIONS");
			$data["error"] 			= array();
					$data["error"]["code"]		= $error_code;
					$data["error"]["message"]	= $error_messages;
			$data = $this->json($data);
}

private function create_user($email, $password, $user_type = 0, $first_name, $last_name = NULL, $mobile = NULL){
	//code for action(create email)
	//get email and password
	//test email is valid or not(also not empty), test size(length) of email is less then allowed in database email field (64), if not return error
	//test email exist in database, if not return error "email already exist"
	//generate hassed email id
	//create new email id into cPanel, if unsuccessful return error "500 => 'Internal Server Error',"
	//if email created into cPanel, create new entry for user(register, name id=email hashed email etc) in database else return partialay successful error	
    // If success everythig is good send header as "OK" return param
	// Cross validation if the request method is PSOT else it will return "Not Acceptable" status
	if((isset($email))&&
			(!empty($email))&&
			(strlen($email)<64)&&
			(filter_var($email, FILTER_VALIDATE_EMAIL))&&
			(isset($password))&&
			(!empty($password))&&
			(strlen((string)$password)<256)&&
			(strlen((string)$password)>7)&&
			(($user_type==0)||($user_type==1)||($user_type==2))&&
			(isset($first_name))&&
			(!empty($first_name))&&
			(strlen((string)$first_name)<64)&&
			(((isset($last_name))&&(!empty($last_name))&&(strlen((string)$last_name)<128))||($last_name == NULL))&&
			(((!empty($mobile))&&(strlen((string)$mobile)<22)&&(strlen((string)$mobile)>4)&&(filter_var($mobile, FILTER_VALIDATE_INT)))||($mobile == NULL))
			){
		$email			= $email;
		$password		= $password;
		$user_type		= $user_type;
		$session_id		= md5($this->getToken(32));	
		$first_name		= $first_name;
		$created_at 	= date("Y-m-d h:i:s");
		$last_login 	= date("Y-m-d h:i:s");
		$hashed_email	= NULL;
		$last_name 		= $last_name;
		$mobile 		= $mobile;
		$email_status	= NULL;

		$pdo = DB::getInstance($this->config_vars['db_host_name'], $this->config_vars['db_name'], $this->config_vars['db_user_name'], $this->config_vars['db_password'], $this->config_vars['db_charset'], $this->config_vars['db_opt'], $this->config_vars['db_dsn']);
		//Now, we need to check if the supplied username already exists.
		$db_name = $this->config_vars['db_name'];
		//Construct the SQL statement and prepare it.
		$sql = "SELECT username FROM $db_name.users WHERE username = :username";
		$stmt = $pdo->prepare($sql);

		//Bind the provided username to our prepared statement.
		$stmt->bindValue(':username', $email);

		//Execute.
		$stmt->execute();

		//Fetch the row.
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
		//If the provided username already exists - display error.
		if($row['username']){$user_err = "User Name/Email Id already exist";
			$this->response(403);  //forbidden
		}
		else{
				//Hash the password as we do NOT want to store our passwords in plain text.
				$passwordHash = password_hash($password, PASSWORD_BCRYPT, array("cost" => 12));

				$hashed_email = $this->hash_email($email, $user_type, $this->email_domain);

				//Prepare our INSERT statement.
				//Remember: We are inserting a new row into our users table.
				$db_name = $this->config_vars['db_name'];
				$sql = "INSERT INTO $db_name.users (username, password, user_type, session_id, created_at, last_login, hashed_email, first_name, last_name, mobile) VALUES (:username, :password, :user_type, :session_id, :created_at, :last_login, :hashed_email, :first_name, :last_name, :mobile)";
				$stmt = $pdo->prepare($sql);

				//Bind our variables.
				$stmt->bindValue(':username', $email);
				$stmt->bindValue(':password', $passwordHash);
				$stmt->bindValue(':user_type', $user_type);    
				$stmt->bindValue(':session_id', $session_id);    
				$stmt->bindValue(':created_at', $created_at);
				$stmt->bindValue(':last_login', $last_login);	
				$stmt->bindValue(':hashed_email', $hashed_email);
				$stmt->bindValue(':first_name', $first_name);
				$stmt->bindValue(':last_name', $last_name);
				$stmt->bindValue(':mobile', $mobile);	
				//Execute the statement and insert the new account.
				try{
					$result = $stmt->execute();
					if(isset($result)){
						//If the signup process is successful.										
						//What you do here is up to you!
						//Create cPanel
						$cpanel_handler = new create_cpanel_email($hashed_email, $this->config_vars);
						$email_status = $cpanel_handler->create();
						if($email_status){
							$this->response(200);
						}else{
							$this->response(500);
						}
						
						$pdo = NULL;
					}
				}catch(Exception $e){
					$this->response(500);
				}
			}	
	
	
	
	
	
		//set variable for $data array
			$error_code		= $this->_code;
			$status_code	= ($this->_code === 200)?"success":"error";
			$error_messages	= $this->get_status_message();
			
			//create array for json encode
			$data["status"]			= $status_code;
			$data["email"]			= $email;
			$data["user_type"]		= $user_type;
			$data["hashed_email"]	= $hashed_email;
			$data["first_name"]		= $first_name;
			$data["last_name"]		= $last_name;
			$data["mobile"]			= $mobile;
			$data["error"] 			= array();
					$data["error"]["code"]		= $error_code;
					$data["error"]["message"]	= $error_messages;
			$data = $this->json($data);
			$pdo = NULL;

	}else{

			$hashed_email	= NULL;
			//return 422 Unprocessable Entity response
			$this->response(422);
			$error_code		= $this->_code;
			$status_code	= ($this->_code === 200)?"success":"error";
			$error_messages	= $this->get_status_message();

			//create array for json encode
			$data["status"]			= $status_code;
			$data["email"]			= $email;
			$data["user_type"]		= $user_type;
			$data["hashed_email"]	= $hashed_email;
			$data["first_name"]		= $first_name;
			$data["last_name"]		= $last_name;
			$data["mobile"]			= $mobile;
			$data["error"] 			= array();
					$data["error"]["code"]		= $error_code;
					$data["error"]["message"]	= $error_messages;
			$data = $this->json($data);
			
	}

} //create_user() ends
 

private function delete_email($email, $password){
// Cross validation if the request method is GET else it will return "Not Acceptable" status	
//test email is valid or not(also not empty), test size(length) of email is less then allowed in database email field (64), if not return error
//test email exist in database, if not return error
//test password is valid(not empty) or not, test size(length) of password hash is less then allowed in database email field (256), if not return error
//test password equal that exist in database and, if not return error
//get hashed email acossiated with user email
//delete hashed email id from cPanel, if unsuccessful return error "500 => 'Internal Server Error',"
//if hashed email deleted from cPanel, delete entry for user(register, name id=email hashed email etc) from database else return partialay successful error
// If success everythig is good send header as "OK" return param
if(isset($email)&&
	isset($password)&&
	(!empty($email))&&
	(!empty($password))&&
	(strlen($email)<64)&&
	(strlen((string)$password)>7)&&
	(strlen((string)$password)<256)&&
	(filter_var($email, FILTER_VALIDATE_EMAIL))
	){
		$error_code		= NULL;
		$status_code	= NULL;
		$error_messages	= NULL;
		//set variable for $data array
		$error_code		= $this->_code;
		$status_code	= ($this->_code === 200)?"success":"error";
		$error_messages	= $this->get_status_message();
		$username		= $email;
	//Retrieve the hashed email for the given email id.
    //Construct the SQL statement and prepare it.
	$pdo = DB::getInstance($this->config_vars['db_host_name'], $this->config_vars['db_name'], $this->config_vars['db_user_name'], $this->config_vars['db_password'], $this->config_vars['db_charset'], $this->config_vars['db_opt'], $this->config_vars['db_dsn']);
	if($pdo){
		$db_name = $this->config_vars['db_name'];
		$sql = "SELECT username, id FROM $db_name.users WHERE username = :username";
		$stmt = $pdo->prepare($sql);
		
		//Bind the provided username to our prepared statement.
		$stmt->bindValue(':username', $username);
		
		//Execute.
		$stmt->execute();
		
		//Fetch the row.
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
    
		//If $row is TRUE.
		if($row['username']){
			//User account found delete the row (user).
			$id = $row['id'];
			$db_name = $this->config_vars['db_name'];
			$sql = "DELETE FROM $db_name.users WHERE id = :id";
			$stmt = $pdo->prepare($sql);
			
			//Bind the provided username to our prepared statement.
			$stmt->bindValue(':id', $id);
			
			//Execute.
			$stmt->execute();
			$this->response(200);
		}
		else{
			//Could not find a user with that username!
			$this->response(404);
		}
	}
	else{
		$this->response(500);
		}
	$pdo = NULL;


		$error_code		= $this->_code;
		$status_code	= ($this->_code === 200)?"success":"error";

		//create array for json encode
		$data["status"]			 = $status_code;
		$data["email"]			 = $email;
		$data["error"]  = array();
				$data["error"]["code"]		= $error_code;
				$data["error"]["message"]	= $error_messages;

		$data = $this->json($data);

	}
else{
		//return 422 Unprocessable Entity response
		$this->response(422);
		$error_code		= $this->_code;
		$status_code	= ($this->_code === 200)?"success":"error";
		$error_messages	= $this->get_status_message();

		//create array for json encode
		$data["status"]			 = $status_code;
		$data["email"]			 = $email;
		$data["error"]  = array();
				$data["error"]["code"]		= $error_code;
				$data["error"]["message"]	= $error_messages;
		$data = $this->json($data);
		
	}


} //delete_email() ends



	//@parm input email id
	//check email id exist in database(user exist)
	//create new cPanel hashed email if database entry exist but not hashed email
	//return hassed email id
private function get_email($email){
	//call sanitation function
	//check email id exist in database
	//if email exist, get hashed email from database
	//check assocetd hashed email exist in cPanal, return "email exist" if hashed email exist
	//if Cpanel hashed email not exist, try to create hassed email id
	//if hassed email creation unsuccessful return error "500 => 'Internal Server Error'," "cPanel hashed email creation unsuccessful"
	//if email is not in database return error"email not found"
	//return hassed email id
	if(isset($email)&&
		(!empty($email))&&
		(strlen($email)<64)&&
		(filter_var($email, FILTER_VALIDATE_EMAIL))
		){
		//set variable for $data array
		$return_data	= $this->get_data($email);
		
		$error_code		= $this->_code;
		$status_code	= ($this->_code === 200)?"success":"error";
		$error_messages	= $this->get_status_message();

		//create array for json encode
		$data["status"]			= $status_code;
		$data["email"]			= $email;
		$data["hashed_email"]	= $return_data['hashed_email'];
		$data["first_name"]		= $return_data['first_name'];
		$data["last_name"]		= $return_data['last_name'];
		$data["mobile"]			= $return_data['mobile'];
		$data["error"]			= array();
				$data["error"]["code"]		= $error_code;
				$data["error"]["message"]	= $error_messages;

		$data = $this->json($data);

	}
	else{

		$hashed_email	= $this->get_data($email);
		//return 422 Unprocessable Entity response
		$this->response(422);
		$error_code		= $this->_code;
		$status_code	= ($this->_code === 200)?"success":"error";
		$error_messages	= $this->get_status_message();

		//create array for json encode
		$data["status"]			 = $status_code;
		$data["email"]			 = $email;
		$data["hashed_email"]	 = $hashed_email;
		$data["error"]  = array();
				$data["error"]["code"]		= $error_code;
				$data["error"]["message"]	= $error_messages;
		$data = $this->json($data);
			
    }
	
	

			

} //get_email() ends
	
	//   Encode array into JSON
    private function json($data){
        if(is_array($data)){	
		print_r(json_encode($data));
        }
    } //rest.json methode ends

	


	//@parm input email id
	//@parm input password encrypted
	//@parm new password optional
	//@parm first name, last name, user_type etc optional
	//check email id exist in database(user exist)
	//create new cPanel hashed email if database entry exist but not hashed email
	//update email id
	//update password
	//update other user data 
	
	private function put_email($email, $password, $user_type = NULL, $first_name = NULL, $last_name = NULL, $mobile = NULL, $new_password = NULL, $otp = NULL){

	//change/update password with otp
	//fist send (email id + old password + new password) to generate and send otp on email(or mobile if you code)
	//after reciving otp, again send (email id + old password + new password + otp)
	//if correct otp recive within otp_expire_time change the password
	if((isset($email))&&
			(!empty($email))&&
			(strlen($email)<64)&&
			(filter_var($email, FILTER_VALIDATE_EMAIL))&&
			(isset($password))&&
			(!empty($password))&&
			(strlen((string)$password)<256)&&
			(strlen((string)$password)>7)&&
			(isset($new_password))&&
			(!empty($new_password))&&
			(strlen((string)$new_password)<256)&&
			(strlen((string)$new_password)>7)&&
			(((isset($otp))&&(!empty($otp))&&(strlen((string)$otp)>5)&&(strlen((string)$otp)<13))||($otp == NULL))){
			$username		= $email;
			$password		= $password;
			$new_password	= $new_password;
			$otp			= $otp;
		$pdo = DB::getInstance($this->config_vars['db_host_name'], $this->config_vars['db_name'], $this->config_vars['db_user_name'], $this->config_vars['db_password'], $this->config_vars['db_charset'], $this->config_vars['db_opt'], $this->config_vars['db_dsn']);
		//Now, we need to check if the supplied username already exists.
		//Construct the SQL statement and prepare it.
		$db_name = $this->config_vars['db_name'];
		$sql = "SELECT id, username, password, user_type, first_name FROM $db_name.users WHERE username = :username";
		$stmt = $pdo->prepare($sql);
		$passwordHash_old = NULL;
		$passwordHash_new = NULL;
		//Bind the provided username to our prepared statement.
		$stmt->bindValue(':username',  $email);
		
		//Execute.
		$stmt->execute();
		
		//Fetch the row.
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
		$id = $row['id'];
		$passwordHash_new = password_hash($new_password, PASSWORD_BCRYPT, array("cost" => 12));

		if(password_verify($password, $row['password'])){
			// email(user) exist, password match
			
			//change password
			//Prepare our UPDATE statement.
			$sql = "UPDATE $db_name.users
					SET password = :password
					WHERE id = :id";
			$stmt = $pdo->prepare($sql);
			
			//Bind our variables.
			$stmt->bindValue(':password', $passwordHash_new);
			$stmt->bindValue(':id', $id);

			//Execute the statement and insert the new account.
			try{
				$result = $stmt->execute();
				if(isset($result)){
					//If the process is successful.										
					//What you do here is up to you!
					// write otp module

					if(isset($otp)){
						//match the otp with saved otp
						//if otp matched change the password
/**						if(){
							$this->response(200);
						}else{
							//otp did not match return error
							$this->response(422);
						}
**/
					}else{
						//send otp and save temporary for some time(define in config.class.php)
						//generate otp
						$otp = $this->getToken(8);
						//Save OTP temporary with time and email
						
						//Send OTP by E-mail
						$send_otp = new email_otp($email, $otp, $first_name, $this->config_vars);
						$send_otp->send_email();
						//message otp (add code or call api if you want send otp by message)
						$this->response(200);
					}
				}
			}catch(Exception $e){
				$this->response(500);
			}
			
		}else{
			// "User Name/Email Id or password does NOT match";
			$this->response(403);  //forbidde
			$error_code		= $this->_code;
			$status_code	= ($this->_code === 200)?"success":"error";
			$error_messages	= $this->get_status_message();

			//create array for json encode
			$data["status"]			= $status_code;
			$data["email"]			= $email;
			$data["user_type"]		= $user_type;
			$data["first_name"]		= $first_name;
			$data["last_name"]		= $last_name;
			$data["mobile"]			= $mobile;
			$data["error"] 			= array();
					$data["error"]["code"]		= $error_code;
					$data["error"]["message"]	= $error_messages;
			$data = $this->json($data);
		}

		
	}//end of change password if()

	//update first_name, last_name, user_type, mobile, user_type
	//call sanitation function, verify email and other variabe and  its length
	//check email id exist in database
	// match password, if not return error
	//if email exist password match, get hashed email from database
	//check assocetd hashed email exist in cPanal, return "email exist" if hashed email exist
	//if Cpanel hashed email not exist, try to create hassed email id
	//if hassed email creation unsuccessful return error "500 => 'Internal Server Error'," "cPanel hashed email creation unsuccessful"
	//if email is not in database return error "email not found"
	//update all user data except hashed email
	elseif((isset($email))&&
			(!empty($email))&&
			(strlen($email)<64)&&
			(filter_var($email, FILTER_VALIDATE_EMAIL))&&
			(isset($password))&&
			(!empty($password))&&
			(strlen($password)<256)&&
			(strlen($password)>7)&&
			(($user_type==0)||($user_type==1)||($user_type==2)||($user_type==NULL))&&
			(((isset($first_name))&&(!empty($first_name))&&(strlen((string)$first_name)<64))||($first_name == NULL))&&
			(((isset($last_name))&&(!empty($last_name))&&(strlen((string)$last_name)<128))||($last_name == NULL))&&
			(((isset($mobile))&&(!empty($mobile))&&(strlen((string)$mobile)<22)&&((strlen((string)$mobile))>4)&&(filter_var($mobile, FILTER_VALIDATE_INT)))||($mobile == NULL))){

			$username		= $email;
			$password		= $password;
			$hashed_email	= NULL;
			
		$pdo = DB::getInstance($this->config_vars['db_host_name'], $this->config_vars['db_name'], $this->config_vars['db_user_name'], $this->config_vars['db_password'], $this->config_vars['db_charset'], $this->config_vars['db_opt'], $this->config_vars['db_dsn']);
		//Now, we need to check if the supplied username already exists.
		
		$db_name = $this->config_vars['db_name'];
		
		//Construct the SQL statement and prepare it.
		$sql = "SELECT id, username, password, user_type, first_name, mobile, last_name, hashed_email FROM $db_name.users WHERE username = :username";
		$stmt = $pdo->prepare($sql);
		
		//Bind the provided username to our prepared statement.
		$stmt->bindValue(':username', $email);
		
		//Execute.
		$stmt->execute();
		
		//Fetch the row.
		$row = $stmt->fetch(PDO::FETCH_ASSOC);

		if(isset($row['username'])){
			//user exist
			//set other variable
			$id			= $row['id'];
			$hashed_email = $row['hashed_email'];
			if(!isset($user_type)){
				$user_type	= $row['user_type'];
				//if user_type is changed, hashed_email_id should also change
			}else{
				$hashed_email = $this->hash_email($email, $user_type, $this->email_domain);
			}
			
			$first_name	= (isset($first_name))	?$first_name	:$row['first_name'];
			$last_name	= (isset($last_name))	?$last_name		:$row['last_name'];
			$mobile		= (isset($mobile))		?$mobile		:$row['mobile'];
			$db_name = $this->config_vars['db_name'];
			
			//Prepare our UPDATE statement.
			//Remember: We are inserting a new row into our users table
			$sql = "UPDATE $db_name.users
					SET user_type = :user_type, first_name = :first_name, last_name = :last_name, mobile = :mobile, hashed_email = :hashed_email
					WHERE id = :id";
			$stmt = $pdo->prepare($sql);
			
			//Bind our variables.
			$stmt->bindValue(':user_type', $user_type);
			$stmt->bindValue(':first_name', $first_name);
			$stmt->bindValue(':last_name', $last_name);
			$stmt->bindValue(':mobile', $mobile);
			$stmt->bindValue(':id', $id);
			$stmt->bindValue(':hashed_email', $hashed_email);
			//Execute the statement and insert the new account.
			try{
				$result = $stmt->execute();
				if(isset($result)){
					//If the signup process is successful.										
					//What you do here is up to you!
					$this->response(200);
				}
			}catch(Exception $e){
				$this->response(500);
			}
		    $pdo = NULL;
		}
		else{
			// "User Name/Email Id does NOT exist";
			$this->response(403);  //forbidden
			$pdo = NULL;
			}	
	
	
	
	
	
	//set variable for $data array
			$error_code		= $this->_code;
			$status_code	= ($this->_code === 200)?"success":"error";
			$error_messages	= $this->get_status_message();
			
			//create array for json encode
			$data["status"]			= $status_code;
			$data["email"]			= $email;
			$data["user_type"]		= $user_type;
			$data["first_name"]		= $first_name;
			$data["last_name"]		= $last_name;
			$data["mobile"]			= $mobile;
			$data["error"] 			= array();
					$data["error"]["code"]		= $error_code;
					$data["error"]["message"]	= $error_messages;
			$data = $this->json($data);

	}
	else{
			//return 422 Unprocessable Entity response
			$this->response(422);
			$error_code		= $this->_code;
			$status_code	= ($this->_code === 200)?"success":"error";
			$error_messages	= $this->get_status_message();

			//create array for json encode
			$data["status"]			= $status_code;
			$data["email"]			= $email;
			$data["user_type"]		= $user_type;
			$data["first_name"]		= $first_name;
			$data["last_name"]		= $last_name;
			$data["mobile"]			= $mobile;
			$data["error"] 			= array();
					$data["error"]["code"]		= $error_code;
					$data["error"]["message"]	= $error_messages;
			$data = $this->json($data);
			
    }



} //put_email ends

 
	} //rest class ends
	$pdo = NULL;
    // Initiiate Library   
    $api = new API($config_vars);
    $api->processApi();
ob_end_flush();
?>