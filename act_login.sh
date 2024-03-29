#!/bin/bash


ACTHOST="selfcare.actcorp.in"
PORTALFILE="/tmp/actportal.html"
OUTFILE="/tmp/act_login.html"
UID_NAME="_login_WAR_BeamPromotionalNDownloadsportlet_uname"
PWD_NAME="pword"
IP_NAME="userIP"
ACT_CONF_FILE="/etc/actbroadband/act.conf"
CHECKONLY=0

# In case we are stuck with a strange PATH due to cron invocation
export PATH=${PATH}:/sbin:/bin:/usr/bin

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
		-c|--checkonly)
			CHECKONLY=1
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

SILENTFLAG="--silent"
if [ ${VERBOSE:-0} == 1 ]; then
	SILENTFLAG=""
fi

IPADDR=$(ifconfig ${ACT_IF} | grep 'inet ' | awk '{ print $2 }')
vprint "Interface: $ACT_IF. IP: $IPADDR"

PORTALURL="https://${ACTHOST}/web/${LOCATION}/home"
vprint "Fetching $PORTALURL into $PORTALFILE" 

curl $SILENTFLAG -o ${PORTALFILE} "${PORTALURL}"

URL=$(egrep --text '?p_auth=' ${PORTALFILE} | egrep 'log(in|out)' | cut -d'"' -f2)
vprint "Login URL is $URL"

if [ -z "$URL" ]; then
	vprint "Could not find login URL in portal page"
	exit 1
fi

echo ${URL} | grep -q login
LOGGED_IN=$?

declare -a state=('False' 'True')
if [ ${CHECKONLY} == 1 ]; then
	vprint "Logged in: ${state[$LOGGED_IN]}"
	exit $LOGGED_IN
fi

if [ ${LOGGED_IN} == 1 ]; then
	vprint "Already logged in"
	exit 0
fi

vprint "Logging in"
curl $SILENTFLAG --data "${IP_NAME}=${IPADDR}&${UID_NAME}=${USERID}&${PWD_NAME}=${PASSWORD}" -o ${OUTFILE} ${URL}

grep --text -q 'You are logged in as' ${OUTFILE}
LOGIN_SUCCESS=$?

vprint "Login succeeded: ${state[$LOGIN_SUCCESS]}"
exit $LOGIN_SUCCESS

