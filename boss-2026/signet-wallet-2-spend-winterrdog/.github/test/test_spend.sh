result=$(bash ./solution/run_spend.sh)
echo $result
tx1=$(echo "$result" | tail -n 2 | head -n 1)
tx2=$(echo "$result" | tail -n 1)
test=$(bitcoin-cli -signet testmempoolaccept [\""$tx1"\",\""$tx2"\"])
echo $test
if jq -e '
    type == "array" and
    length == 2 and
    all(.[]; .allowed == true)
' <<<"$test" >/dev/null; then
    echo PASS
else
    echo FAIL
fi
