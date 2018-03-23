exitValue=1

VAR="$(curl -L -m 3 -s "http://$1/wsrp-portlet/proxy/a?url=http://$1/api/axis")"

if echo "$VAR" | grep -q 'Portal_PortalService'; then
    exitValue=0
else
    VAR="$(curl -L -m 3 -s "http://$1/o/wsrp-service/proxy/a?url=http://$1/api/axis")"

    if echo "$VAR" | grep -q 'Portal_PortalService'; then
        exitValue=0
    fi
fi

exit $exitValue