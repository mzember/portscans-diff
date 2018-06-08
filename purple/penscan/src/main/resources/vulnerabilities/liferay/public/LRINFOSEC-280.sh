exitValue=1

VAR="$(curl -i -k -m 10 -s -H "Cookie: COOKIE_SUPPORT=true" -L "http://$1/html/common/referer_jsp.jsp?referer=http://www.google.com")"

if echo "$VAR" | grep -q 'Location: http://www.google.com'; then
    exitValue=0
fi

exit $exitValue