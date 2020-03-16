DIR=scan-`date +%Y-%m-%d-%H:%M:%S`

mkdir "$DIR"
if [ -n "$TEST_IP" ]; then
    echo "$TEST_IP" > "$DIR/Targets.IP"
else 
    cp Targets.IP "$DIR"
fi
(
cd "$DIR"
sh -x ../run-nmap-Tfast-test.sh
)

sh -x ./diffscans.sh
