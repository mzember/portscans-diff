exitValue=1

VAR="$(curl -s -L -k -m 3 --include "http://$1/c/portal/login" --data "login=test@liferay.com&password=test&redirect=/default_credentials" -H "Cookie: COOKIE_SUPPORT=true")"

if echo "$VAR" | grep -q '/default_credentials'; then
    exitValue=0
fi

exit $exitValue