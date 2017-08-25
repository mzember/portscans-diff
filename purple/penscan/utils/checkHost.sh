exitValue=1

fileName=$(basename $0)

nmap -oG /tmp/$fileName.gnmap -sP liferay.com >/dev/null 2>&1;

cat /tmp/$fileName.gnmap | sed '/^#/d' | grep -q "Status: Up" && exitValue=0;

rm -rf /tmp/$fileName.gnmap

exit $exitValue