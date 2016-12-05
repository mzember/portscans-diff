#!/bin/bash
source $LPM_PATH/packages/packages_common.sh
source $LPM_PATH/it-lpm-tools/scripts/bin/lpm_common.sh

NEW_PASS=$2

if [[ $# -eq 0 ]] ; then
	FIRST=$(< /dev/urandom tr -dc A-Za-z0-9 | head -c${1:-8})
	SECOND=$(date +%s | md5sum | base64 | tail -c 8)
	echo $FIRST$SECOND | tr -d '\n' | xsel -b
	echo -e "A new password has been placed in your clipboard."\\n\\n"Usage: Call this command with either a password, the name of a password, or the name of a server whose password has been compromised."
  exit 0
fi

#call script with name of compromised vm or password_name or password
if [ $(grep -q $1 $LPM_PATH/systems/keys/passwords_common.sh)]
then
	CURRENT_PASS=$(grep $1 $LPM_PATH/systems/keys/passwords_common.sh | sed 's/=.*//')
	CURRENT_PASS_NAME=$(grep $1 $LPM_PATH/systems/keys/passwords_common.sh | sed 's/.*=//')
	PARENT_HOSTS=$(grep -lv "^SERVER_PASSWORD=" systems/domains/*.sh | sed -e 's/systems\/domains\///' -e 's/\.sh//')
	sed -i "s/$CURRENT_PASS/$NEW_PASS/" $LPM_PATH/systems/keys/passwords_common.sh
elif [ -e systems/domains/$1.sh ]
then
	CURRENT_PASS=$(getdomainpassword $1)
	PARENT_HOSTS=$(grep -lv "^SERVER_PASSWORD=" systems/domains/*.sh | sed -e 's/systems\/domains\///' -e 's/\.sh//')
	sed -i "s/$CURRENT_PASS/$NEW_PASS/" $LPM_PATH/systems/keys/passwords_common.sh
else
	CURRENT_PASS="SERVER_PASSWORD=$1"
	PARENT_HOSTS=$(grep -l "$CURRENT_PASS" systems/domains/*.sh | sed -e 's/systems\/domains\///' -e 's/\.sh//')
	sed -i "s/^$CURRENT_PASS/$NEW_PASS/" $LPM_PATH/systems/domains/*.sh
fi

 VULNERABLE_HOSTS=()
 for host in $PARENT_HOSTS
 do
 	VULNERABLE_HOSTS=$VULNERABLE_HOSTS' '$(getinheriteddomains $host)
 done

 #echo $VULNERABLE_HOSTS | grep -o '[^ |]*'

 for host in $VULNERABLE_HOSTS
 do
	lpmlogin $host whoami
 	#lpmlogin $host 'yes $NEW_PASS | xargs passwd root'
 done
