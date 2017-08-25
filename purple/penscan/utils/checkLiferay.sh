exitValue=1

VAR="$(curl -s -I -L -k -m 10 "http://$1/c/portal/status")"

if echo "$VAR" | grep -q '^Liferay-Portal: '; then
	exitValue=0
fi

exit $exitValue