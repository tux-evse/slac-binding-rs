#!/bin/sh

# Small script to tap eth2/codico interface and send layer2 paquet to a development desktop
# This allow to debug from native development environement SLAC and ISO15118 protocol
# -----------------------------------------------------------------------------------
# references:
# https://gist.github.com/zOrg1331/a2a7ffb3cfe3b3b821d45d6af00cb8f6
# https://access.redhat.com/documentation/fr-fr/red_hat_enterprise_linux/9/html/configuring_and_managing_networking/configuring-a-gretap-tunnel-to-transfer-ethernet-frames-over-ipv4_configuring-ip-tunnels
#

export WG_PORT=51820
export SLAC_IFACE=eth2

echo "Wireguard config to tap codico/eth2 device from target to development desktop"
echo ---
if test $UID != 0; then
    echo "(hoops) this command requires admin privileges (use sudo)"
    exit 1
fi

mkdir -p $HOME/wg-tap-pki
cd $HOME/wg-tap-pki

echo -- clean previous config
 ip link delete wg0-tap 2> /dev/null
 ip link delete br0-tun 2> /dev/null
 ip link delete gre-tun 2> /dev/null

if test ! -f server-public.key; then

    echo "-- generating public/pricate keys into $HOME/wg-tap-pki"
    wg genkey | tee server-private.key | wg pubkey > server-public.key
    wg genkey | tee client-private.key | wg pubkey > client-public.key

    echo "retreive server/client keys with scp"
    echo "#scp root@target-name:$HOME/wg-tap-pki/client*.key $HOME/wg-tap-pki/server-public.key ."

    echo "-- firewall opening wg-port:$WG_PORT"
    firewall-cmd --add-port=$WG_PORT/udp --permanent && firewall-cmd --reload
else
    echo "reusing wg-pki from $HOME/wg-tap-pki"
fi


echo "-- create wireguard network interface"
  ip l a wg0-tap type wireguard
  wg set wg0-tap private-key ./server-private.key
  ip a a 12.12.12.1/24 dev wg0-tap

echo -- configure wireguard with pki keys
  ip l set dev wg0-tap up
  wg set wg0-tap listen-port 51820 peer $(cat client-public.key) allowed-ips 0.0.0.0/0

echo -- create layer2 tap device
  modprobe gre
  if test $? -ne 0; then
    echo "(hoops) kernel module 'gre' not found (need to be fixed)"
    exit 1
  fi
  ip l a gre-tun type gretap local 12.12.12.1 remote 12.12.12.2
  ip l s gre-tun up

echo -- configure bridge and add codico interface:$SLAC_IFACE
  ip l add name br0-tun type bridge
  ip l set dev br0-tun up
  ip l set gre-tun master br0-tun
  ip l set $SLAC_IFACE master br0-tun
  # ip a a 192.168.29.51/24 dev br0-tun

echo -- dispkay bridge config
  ip link show master br0-tun


