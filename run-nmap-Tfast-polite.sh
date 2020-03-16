OUTPUT=`basename $0 | sed 's/run-//;s/\.sh$//'`
test -n "$OUTPUT" || exit 1
exec nmap -A -Pn -F -iL Targets.IP -oX "$OUTPUT" --privileged -vvv -T polite
#--max-scan-delay 0.4s --host-timeout 30m

