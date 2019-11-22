# secured_php

This is an simple script which can detect possible injection attacks like XSS, SQli through your text input tags,
It handles the malicious XSS Payloads, if html tags are passed they are converted into string and displayed.
The main goal of this script is to easily sanitize every input, which would result in a secured webapp. 


## Usage :- 
```php
      
    if (isset($_GET['submit'])){
        $sanitization = new sanitizationProcess; # Initialize the class
        $user_input = $sanitization->sanity_check($_GET['<  NAME OF THE INPUT TAG USED IN FORM >']); # call the function
        $user_input2 = $sanitization->sanity_check($_GET['<  NAME OF THE INPUT TAG USED IN FORM >']);
        # $user_input and $user_input2 would now be safe for further use..
    }
```
### Its that easy :)

### TODO :-
1) Performs checks for serialization attack payloads.
2) Checks for Template injections.
3) Checks for command injection and php object injections.

And lot of other things `\_(^^)_/`
