<?php
    class sanitizationProcess{
        # BLacklisted IP's of errors
        private $blacklist = array();

        function handle_xss($user_input){
            $user_input = htmlspecialchars(stripslashes(trim($user_input)));
            return $user_input; 
        }
        function detect_xss($user_input){
            if(preg_match("/(\b)(on\S+)(\s*)=|javascript|(<\s*)(\/*)script/",$user_input)){
                # Hacker Detected, Block him !!!!
                $this->handle_xss($user_input);
                $this->blockHacker();
            }
            else{
                # Sanitize everything :)
                $this->handle_xss($user_input);
                return $user_input;
            }
        }
        function blockHacker(){
            if($this->get_hackers_ip_method1() == $this->get_hackers_ip_method2()){
                array_push($blacklist,$this->get_hackers_ip_method1());
                header("Location: blocked.php");
                die();
            }
            else{
                array_push($blacklist,$this->get_hackers_ip_method1(),$this->get_hackers_ip_method2());
                header("Location: blocked.php");
                die();
            }
        }

        function get_hackers_ip_method1(){
            $ipaddress = '';
            if (getenv('HTTP_CLIENT_IP'))
                $ipaddress = getenv('HTTP_CLIENT_IP');
            else if(getenv('HTTP_X_FORWARDED_FOR'))
                $ipaddress = getenv('HTTP_X_FORWARDED_FOR');
            else if(getenv('HTTP_X_FORWARDED'))
                $ipaddress = getenv('HTTP_X_FORWARDED');
            else if(getenv('HTTP_FORWARDED_FOR'))
                $ipaddress = getenv('HTTP_FORWARDED_FOR');
            else if(getenv('HTTP_FORWARDED'))
               $ipaddress = getenv('HTTP_FORWARDED');
            else if(getenv('REMOTE_ADDR'))
                $ipaddress = getenv('REMOTE_ADDR');
            else
                $ipaddress = 'UNKNOWN';
            
            $ipaddress1 = $ipaddress;
            return $ipaddress1;
        }
        function get_hackers_ip_method2(){
            $ipaddress = '';
            if (isset($_SERVER['HTTP_CLIENT_IP']))
                $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
            else if(isset($_SERVER['HTTP_X_FORWARDED_FOR']))
                $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
            else if(isset($_SERVER['HTTP_X_FORWARDED']))
                $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
            else if(isset($_SERVER['HTTP_FORWARDED_FOR']))
                $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
            else if(isset($_SERVER['HTTP_FORWARDED']))
                $ipaddress = $_SERVER['HTTP_FORWARDED'];
            else if(isset($_SERVER['REMOTE_ADDR']))
                $ipaddress = $_SERVER['REMOTE_ADDR'];
            else
                $ipaddress = 'UNKNOWN';
            $ipaddress2 = $ipaddress;
            return $ipaddress2;

        }




    } // class SanitizationProcess Ends 


    # Main Function below
    if (isset($_GET['submit'])){
        $sanitization = new sanitizationProcess;
        $user_input = $sanitization->detect_xss($_GET['input1']);
        $sql = $sanitization->detect_xss($_GET['sql']);
        
        # $sanitization->detect_xss($user_input);
        # $sanitization->detect_xss($sql);
        echo "First Input is ".$user_input."<br> Second Input is ".$sql."<br> Both are sanitized.";
    }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Document</title>
</head>
<body>
    <form action = "" method="GET"> 
        <input type="text" name="input1">
        <input type="text" name="sql">
        <input type="submit" name="submit">
    </form>
</body>
</html>