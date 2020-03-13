DIR=scan-`date +%Y-%m-%d-%H:%M:%S`

mkdir "$DIR"
cp Targets.IP "$DIR"
(
cd "$DIR"
../run-nmap-Tfast-test.sh
)

./diffscans.sh
