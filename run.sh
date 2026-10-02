
source electrum/env/bin/activate
# make the easy_tx plugin visible to electrum as an internal plugin
ln -sfn ../../../easy_tx electrum/electrum/plugins/easy_tx
./electrum/electrum-env --signet

