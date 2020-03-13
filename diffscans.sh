DIFFFILE=currentdiff.tmp
NEW=`ls -d -t scan-* | sed -n '1p'`
OLD=`ls -d -t scan-* | sed -n '2p'`

ndiff "$OLD"/nmap-*.xml "$NEW"/nmap-*.xml >$DIFFFILE

if [ `wc -l $DIFFFILE | cut -d' ' -f1` -gt 2 ]; then                # there is a difference in headers (2 lines) always
    echo "----------------------------------------------------------"
    echo "A difference between two recent scans has been identified."
    echo "----------------------------------------------------------"
    cat $DIFFFILE
    exit 1
fi

exit 0
