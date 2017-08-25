set -x

exitValue=1

fileName=$(basename $0)

nmap -oG /tmp/$fileName.gnmap -iL $1 -sn >/dev/null 2>&1;

cat /tmp/$fileName.gnmap | sed '/^#/d; s/Host: \(.*\) (\(.*\)).*/\1,\2/; s/\.lax\.liferay\.com//' > /tmp/$fileName.output

rm -rf /tmp/$fileName.gnmap

exit $exitValue