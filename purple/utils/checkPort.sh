exitValue=1

fileName=$(basename $0)

nmap -oG /tmp/$fileName.gnmap -sT $1 -p$2 >/dev/null 2>&1;

cat /tmp/$fileName.gnmap | sed '/^#/d' | grep -q "Ports: $2/open" && exitValue=0;

rm -rf /tmp/$fileName.gnmap

exit $exitValue