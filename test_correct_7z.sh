#!/bin/bash
echo "data" > file.txt
echo "secret7z" > wordlist_correct.txt
for m in "LZMA" "LZMA2"; do
    echo "Testing method: $m"
    rm -f test_$m.7z
    7z a -psecret7z -mhe=on -m0=$m test_$m.7z file.txt > /dev/null 2>&1
    ./build/bin/crive test_$m.7z --wordlist wordlist_correct.txt --verbose --no-color 2>&1 | grep "first byte"
done
