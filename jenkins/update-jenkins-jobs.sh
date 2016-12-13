cd /opt/dev/projects/github/lfris-security;
git clean -dfx;
git reset --hard;
git checkout --detach;
git fetch -f upstream master:master;
git checkout -f master;
cp -Rf jenkins/jobs/* /opt/java/jenkins/jobs;