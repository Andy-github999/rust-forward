@echo off

set PASS=gukasdhgfwet
set HOST=root@192.168.2.1

echo Stopping...
sshpass -p "%PASS%" ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password -p 22 %HOST% "killall -9 forward 2>/dev/null || true"

echo Uploading...
sshpass -p "%PASS%" scp -O -o PubkeyAuthentication=no -o PreferredAuthentications=password -P 22 "D:\myprogram\rust-forward\target\aarch64-unknown-linux-musl\release\forward" %HOST%:/tmp/

echo Starting...

sshpass -p "%PASS%" ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password -p 22 %HOST% "chmod +x /tmp/forward && killall -9 forward 2>/dev/null; sleep 1 && /tmp/forward --password candy123456 > /tmp/forward.log 2>&1 &"


echo Done.
pause