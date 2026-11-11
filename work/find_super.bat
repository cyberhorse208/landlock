@echo off
wsl -e bash -c "ls -la ~/work/ 2>/dev/null && echo '---FOUND---' || echo 'no ~/work dir'; echo '===HOME==='; ls -la ~ 2>/dev/null | head -30; echo '===MNT==='; find /mnt -maxdepth 4 -name 'super_raw.img' -type f 2>/dev/null | head -10; echo '===ROOT==='; find / -maxdepth 4 -name 'super_raw.img' -type f 2>/dev/null | head -10"
