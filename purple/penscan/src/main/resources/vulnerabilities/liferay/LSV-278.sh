exitValue=1

VAR="$(curl -L -m 3 -s "http://$1/api//axis")"

if echo "$VAR" | grep -q 'Portal_PortalService'; then
    exitValue=0
fi

exit $exitValue