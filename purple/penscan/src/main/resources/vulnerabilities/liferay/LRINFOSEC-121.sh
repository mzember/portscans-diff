exitValue=1

VAR="$(curl -b blank -d "login=test@liferay.com&password=test&redirect=/default_credentials" -i -k -m 10 --post302 -s -H "Cookie: COOKIE_SUPPORT=true" -L -X POST "http://$1/c/portal/login")"

if echo "$VAR" | grep -q '/default_credentials'; then
    exitValue=0
fi

VAR="$(curl -b blank -d "login=test&password=test&redirect=/default_credentials" -i -k -m 10 --post302 -s -H "Cookie: COOKIE_SUPPORT=true" -L -X POST "http://$1/c/portal/login")"

if echo "$VAR" | grep -q '/default_credentials'; then
    exitValue=0
fi

exit $exitValue