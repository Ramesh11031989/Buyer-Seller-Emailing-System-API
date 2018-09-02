<?php
class class DB extends PDO{

    Public static $pdo = NULL;


    private function __construct() 
    {

    }
    private function __clone()
    {

    }   
    public static function getInstance() {

        if (!self::$pdo)
        {
			try {
            self::$pdo = new PDO(config::$db_dsn, config::$db_user_name, config::$db_password, config::$db_opt);
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
}
?>