DIR=scan-`date +%Y-%m-%d-%H:%M:%S`

mkdir "$DIR"
cp Targets.IP "$DIR"
(
cd "$DIR"
sh -x ../run-nmap-Tfast-test.sh
)

sh -x ./diffscans.sh
