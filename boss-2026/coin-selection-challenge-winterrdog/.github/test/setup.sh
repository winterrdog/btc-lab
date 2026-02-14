set -x
wget https://bitcoincore.org/bin/bitcoin-core-30.2/bitcoin-30.2-x86_64-linux-gnu.tar.gz
tar -xzvf bitcoin-30.2-x86_64-linux-gnu.tar.gz
ln -s $PWD/bitcoin-30.2/bin/* /usr/local/bin/
bitcoind -datadir=$PWD/datadir/node0 -daemon
while true; do
    blockcount=$(bitcoin-cli -regtest -rpcuser=student -rpcpassword=boss2026 getblockcount)
    if [[ $blockcount -ge 110 ]]; then
        break
    else
        sleep 1
    fi
done