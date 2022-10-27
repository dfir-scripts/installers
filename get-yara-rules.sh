#! /bin/bash
#Git Yara Rules
echo "Download/update latest yara rules from Github"
read -s -n 1 -p " Press a key to continue . . ."
echo ""
[ "$(ls -A /usr/local/src/yara/Neo23x0/signature-base/ 2>/dev/null)" ] && \
git -C /usr/local/src/yara/Neo23x0/signature-base pull --no-rebase|| \
git clone https://github.com/Neo23x0/signature-base.git /usr/local/src/yara/Neo23x0/signature-base
[ "$(ls -A /usr/local/src/yara/reversinglabs/ 2>/dev/null)" ] && \
git -C /usr/local/src/yara/reversinglabs pull --no-rebase || \
git clone https://github.com/reversinglabs/reversinglabs-yara-rules.git /usr/local/src/yara/reversinglabs
[ "$(ls -A /usr/local/src/yara/yararules.com/ 2>/dev/null)" ] && \
git -C /usr/local/src/yara/yararules.com pull --no-rebase || \
git clone https://github.com/Yara-Rules/rules.git /usr/local/src/yara/yararules.com
[ "$(ls -A /usr/local/src/yara/bartblaze/ 2>/dev/null)" ] && \
git -C /usr/local/src/yara/bartblaze pull  --no-rebase || \
git clone  https://github.com/bartblaze/Yara-rules.git  /usr/local/src/yara/bartblaze
echo "Yara rules saved to /urs/local/src/yara/"
