# act-broadband
Linux scripts to work with ACT Broadband

** Update 2022-11-07 **
ACT has changed their portal and login mechanism. The old scripts no longer work with the new design.
act-connect.py is designed to do the work of both act_login.sh and get_act_info.py

act-connect.py --login will silently log in to ACT and can be run from cron.
The script looks up /etc/actbroadband/act.conf for credentials, just like the old act_login.sh
There are a number of Python module dependencies. Please look at the import section in the script and install them.
