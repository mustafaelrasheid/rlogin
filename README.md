# rlogin
this is a simple login program that uses rust. it uses yescript (and only
yescript), and it uses `/etc/passwd` and `/etc/shadow` to process login info.
if no argument is provided, login would run the shell specified, if a path is
provided as argument, it would be run instead of the shell. the privilage
droped to the UID and GID specified in passwd.
