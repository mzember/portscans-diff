OUTPUT=`basename $0 | sed 's/run-//;s/\.sh$//'`
test -n "$OUTPUT" || exit 1
exec nmap -A -Pn --top-ports 10 -iL Targets.IP -oA "$OUTPUT" --privileged -vvv -T insane
#--max-scan-delay 0.4s --host-timeout 30m

