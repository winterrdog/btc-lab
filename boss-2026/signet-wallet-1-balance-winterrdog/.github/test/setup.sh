set -x
wget https://bitcoincore.org/bin/bitcoin-core-30.2/bitcoin-30.2-x86_64-linux-gnu.tar.gz
tar -xzvf bitcoin-30.2-x86_64-linux-gnu.tar.gz
ln -s $PWD/bitcoin-30.2/bin/* /usr/local/bin/
bitcoind -daemon -signet -blocksonly=1 -conf=$PWD/config/bitcoin.conf
bitcoin-cli --version
while true; do
    blockcount=$(bitcoin-cli -signet getblockcount)
    if [[ $blockcount -ge 300 ]]; then
        echo "blocks: $blockcount"
        break
    else
        sleep 1
    fi
done
hash=$(bitcoin-cli -signet getblockhash 301)
bitcoin-cli -signet invalidateblock $hash
echo invalidating block: $hash
bitcoin-cli -signet getblockcount
bitcoin-cli --version