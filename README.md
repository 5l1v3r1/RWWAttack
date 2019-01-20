=======================================================================================================
				Remote Web Workplace Attack - 0.9.2
=======================================================================================================

-----------------------------------------------------------------------------
Disclaimer:
This program is to be used only with the permission of the owner of the target host and is for use in 
penetration testing only. If this is not the case you must not use this program.
-----------------------------------------------------------------------------


-----------------------------------------------------------------------------
Info:
This program will perform a dictionary attack against a live Microsoft Windows Small Business Server's 
"Remote Web Workplace" portal. Currently supports both SBS 2003 and SBS 2008.

5 active login threads run simoultanously against the target offering fairly nice speed, however running
against SBS 2008 is significantly slower than SBS 2003. - Due to the simoultanous threading, you should 
supply at least 5 passwords in your passwords file. If not, the program will pad the list with blanks to 
make it work with the hardcoded 5 threads.

For more info on RWW check http://en.wikipedia.org/wiki/Remote_Web_Workplace
------------------------------------------------------------------------------


------------------------------------------------------------------------------
Important:
Take care when specifying lockout threshold & duration. Violating account lockout policy through invalid
login attempts through RWW WILL lock users out, just the same as if these invalid login attempts were
performed at a client machine.

The default SBS 2003 lockout threshold/duration values are:
invalid login attempts = 50
lockout duration/counter reset = 10 minutes.

RWW-Attack uses these default values in order to avoid locking users out, however if you happen to know 
the lockout policy settings, you can specify your own values (see usage). 
------------------------------------------------------------------------------


------------------------------------------------------------------------------
Usage:

-t specifies host. use hostname/IP only, not full RWW URL.
-u <user list> E.G users.txt
-p <passwd list> E.G passwds.txt
-l specifies lockout threshold (for invalid login attempts). Use this value to specify the number of 
passwords to try against each user until sleeping to avoid locking out users. Default SBS 2003 lockout 
values are set if not specified (lockout threshold - 45 invalid attempts, lockout duration/reset counter - 10 mins.)
-d specifies lockout duration/reset counter in MINUTES. Default SBS 2003 lockout duration value is set if not specified (10 mins).
-c specifies if targetting a SBS 2008 (aka cougar) host.
-o <output file> specifies whether to save succesful results to file.

It is advisable to run the attack twice for accuracy.
Note: "administrator" account is disabled by default on SBS 2008.
-------------------------------------------------------------------------------


bugs/comments to mikey27 ..:<-at->:.. hotmail.com 
