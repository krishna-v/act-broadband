# act-broadband
Linux scripts to work with ACT Broadband

## Update 2022-11-07

ACT has changed their portal and login mechanism. The old scripts no longer work with the new design.

act_broadband.py is designed to do the work of both the old scripts act_login.sh and get_act_info.py

act_broadband.py --login will silently log in to ACT and can be run from cron.

act_broadband.py -v -S logins in to ACT and refreshes periodically. It can be installed as a systemd service,
using the act_broadband.service file, which expects to find an executable /usr/local/sbin/act_broadband.py

The new script looks up /etc/actbroadband/act.conf for credentials, just like the old act_login.sh

There are a number of Python module dependencies. Please look at the import section in act_broadband.py and install them.
