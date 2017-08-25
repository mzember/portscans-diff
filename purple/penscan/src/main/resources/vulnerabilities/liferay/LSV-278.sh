exitValue=1

VAR="$(curl -s -L -m 3 "http://$1/api//axis")"

if echo "$VAR" | grep -q 'Portal_PortalService'; then
    exitValue=0
fi

exit $exitValue