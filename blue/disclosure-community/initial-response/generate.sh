./BODY.sh "$(cat REPORTER_NAME)" "$(cat RESPONDER_NAME)" > BODY
cat << END_TEXT
TO: $(cat TO)
FROM: $(cat FROM)
CC: $(cat CC)
BCC: $(cat BCC)
BODY:
$(cat BODY)
END_TEXT
