#!/bin/sh

# Small script to tap eth2/codico interface and send layer2 paquet to a development desktop
# This allow to debug from native development environement SLAC and ISO15118 protocol
# -----------------------------------------------------------------------------------
# references:
# https://gist.github.com/zOrg1331/a2a7ffb3cfe3b3b821d45d6af00cb8f6
# https://access.redhat.com/documentation/fr-fr/red_hat_enterprise_linux/9/html/configuring_and_managing_networking/configuring-a-gretap-tunnel-to-transfer-ethernet-frames-over-ipv4_configuring-ip-tunnels
#

export WG_PORT=51820
if test -z "$WG_SERVER_IP"; then
    export WG_SERVER_IP="phytec-power.tuxevse.vpn"
fi

echo "Wireguard config to tap codico/eth2 device from target:$WG_SERVER_IP to development desktop"
ping -c 1 -q -w 3 $WG_SERVER_IP
if test $? -ne 0; then
    echo "(hoops) fail to reach $WG_SERVER_IP (use WG_ENDPTS='my-target' $0) "
    exit 1
fi

echo "Wireguard config to tap codico/eth2 device from target to development desktop"
echo ---
if test $UID != 0; then
    echo "(hoops) this command requires admin privileges (use sudo)"
    exit 1
fi

mkdir -p $HOME/wg-tap-pki
cd $HOME/wg-tap-pki

echo "-- clean previous config"
 ip link delete wg0-tap 2> /dev/null

if test ! -f server-public.key; then
    echo "-- importing public/private keys into $HOME/wg-tap-pki"
    scp root@$WG_SERVER_IP:wg-tap-pki/client*.key root@$WG_SERVER_IP:wg-tap-pki/server-public.key .

    echo "-- firewall opening:wg-port:$WG_PORT"
    firewall-cmd --add-port=$WG_PORT/udp --permanent && firewall-cmd --reload
else
    echo "reusing wg-pki from $HOME/wg-tap-pki"
fi

echo "-- create wireguard network interface"
  ip l a wg0-tap type wireguard
  wg set wg0-tap private-key ./client-private.key
  ip a a 12.12.12.2/24 dev wg0-tap

echo "-- configure wireguard with pki keys"
  ip l set dev wg0-tap up
  wg set wg0-tap listen-port 51820 peer $(cat server-public.key) allowed-ips 0.0.0.0/0 endpoint $WG_SERVER_IP:51820 persistent-keepalive 15

echo "-- use 'wireshark -i wg0-tap' to monitor layer2 traffic"

