#!/bin/bash

#PORTALPAGE="http://portal.actcorp.in/web/blr/home"
PORTALPAGE="https://selfcare.actcorp.in/web"
PORTALFILE="/tmp/actportal.html"
OUTFILE="/tmp/act_login.html"
UID_NAME="_login_WAR_BeamPromotionalNDownloadsportlet_uname"
PWD_NAME="pword"
IP_NAME="userIP"
ACT_CONF_FILE="/etc/actbroadband/act.conf"

if [ -f ${ACT_CONF_FILE} ]; then
	source ${ACT_CONF_FILE}
fi

vprint() {
	if [ ${VERBOSE:-0} == 1 ]; then
		echo $*
	fi
}

processargs() {
	while [[ $# -gt 0 ]]
	do
		case $1 in
		-v|--verbose)
			VERBOSE=1
		;;
		-i|--interface)
			ACT_IF=$2
			shift
		;;
		-u|--user)
			USERID=$2
			shift
		;;
		-p|--password)
			PASSWORD=$2
			shift
		;;
		-l|--location)
                        LOCATION=$2
                        shift
                ;;

		esac
		shift
	done
}

processargs $*

if [[ -z ${ACT_IF} || -z ${USERID} || -z ${PASSWORD} || -z ${LOCATION} ]]; then
        echo "Please ensure ACT_IF, USERID, PASSWORD and LOCATION are set."
        exit 1
fi

#IPADDR=$(ifconfig ${ACT_IF} | grep 'inet addr' | cut -d':' -f 2 | cut -d' ' -f 1)
IPADDR=$(ifconfig ${ACT_IF} | grep 'inet ' | awk '{ print $2 }')


curl --silent -o ${PORTALFILE} "${PORTALPAGE}/${LOCATION}/home"
URL=$(egrep '?p_auth=' ${PORTALFILE} | egrep 'log(in|out)' | cut -d'"' -f2)
vprint "URL is $URL"

if [ -z "$URL" ]; then
	vprint "Could not find login URL in portal page"
	exit 1
fi

echo ${URL} | grep -q login
LOGGED_IN=$?

if [ ${LOGGED_IN} == 1 ]; then
	vprint "Already logged in"
	exit 0
fi

curl --silent --data "${IP_NAME}=${IPADDR}&${UID_NAME}=${USERID}&${PWD_NAME}=${PASSWORD}" -o ${OUTFILE} ${URL}
