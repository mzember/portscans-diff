DOMAIN='liferay.com'

spfCheck=`curl -s -X POST -d "domain=$DOMAIN&serial=fred12" http://www.kitterman.com/getspf2.py > /dev/null`

spfCheckStatus=$?

echo $spfCheck | grep pass > /dev/null

spfCheckPass=$?

if [ ! -f ../auditscan/reports/spf_check/$DOMAIN.csv ]; then
	mkdir -p ../auditscan/reports/spf_check/

	echo "$(date),$spfCheckStatus,$spfCheckPass" >> ../auditscan/reports/spf_check/$DOMAIN.csv;
fi

exit 0