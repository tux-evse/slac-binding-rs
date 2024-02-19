#!/bin/sh

# Small script to tap eth2/codico interface and send layer2 paquet to a development desktop
# This allow to debug from native development environement SLAC and ISO15118 protocol
# -----------------------------------------------------------------------------------
# references:
# https://gist.github.com/zOrg1331/a2a7ffb3cfe3b3b821d45d6af00cb8f6
# https://access.redhat.com/documentation/fr-fr/red_hat_enterprise_linux/9/html/configuring_and_managing_networking/configuring-a-gretap-tunnel-to-transfer-ethernet-frames-over-ipv4_configuring-ip-tunnels
#

mkdir -p $HOME/wg-tap-pki
cd $HOME/wg-tap-pki

echo "-- clean previous config"
 ip link delete wg0-tap 2> /dev/null
 ip link delete br0-tun 2> /dev/null
 ip link delete gre-tun 2> /dev/null
 ip link delete veth-private 2> /dev/null
 ip link delete veth-public 2> /dev/null
 rm -f $HOME/wg-tap-pki/*.key
