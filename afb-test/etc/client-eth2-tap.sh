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
 ip link delete br0-tun 2> /dev/null
 ip link delete gre-tun 2> /dev/null
 ip link delete veth-private 2> /dev/null
 ip link delete veth-public 2> /dev/null
 rm -f $HOME/wg-tap-pki/*.key

 echo "-- importing public/private keys into $HOME/wg-tap-pki"
 scp root@$WG_SERVER_IP:wg-tap-pki/client*.key root@$WG_SERVER_IP:wg-tap-pki/server-public.key .

echo "-- create wireguard network interface"
  ip link a wg0-tap type wireguard
  wg set wg0-tap private-key ./client-private.key
  ip a a 12.12.12.2/24 dev wg0-tap

echo "-- configure wireguard with pki keys"
  ip link set dev wg0-tap up
  wg set wg0-tap listen-port 51820 peer $(cat server-public.key) allowed-ips 0.0.0.0/0 endpoint $WG_SERVER_IP:51820 persistent-keepalive 15

echo "-- create layer2 tap device"
  modprobe gre
  if test $? -ne 0; then
    echo "(hoops) kernel module 'gre' not found (need to be fixed)"
    exit 1
  fi
  ip link a gre-tun type gretap local 12.12.12.2 remote 12.12.12.1
  ip link s gre-tun up

echo "-- configure bridge and add codico interface:$SLAC_IFACE"
  ip link add name br0-tun type bridge
  ip link set dev br0-tun up
  ip link set gre-tun master br0-tun

echo "--create a virtual interface for slac-binding-rs to listen to"
  ip link add veth-dbg type veth peer name veth-private;
  ip link set veth-private up;
  ip link set veth-dbg up;
  ip link set veth-private master br0-tun;

# echo "-- set ipv6 local link for veth-dbg"
#    nmcli con add connection.interface-name veth-dbg type ethernet
#    nmcli con mod ethernet-veth-dbg ipv6.method link-local

echo "-- set [ff02::01] multicast to veth-dbg"
sudo ip route add multicast ff00::/8 dev veth-dbg table local metric 100
echo "-- ipv6 [ff02::01] routing to iface: `ip -6 route get ff02::01 | awk '{print $6}'`"

VETH_IPV6=`ip -6 addr show dev veth-dbg | grep inet6 | awk '{print $2}' | awk -F '/' '{print $1}'`
echo "-- veth-dbg ipv6: $VETH_IPV6"
echo "-- check on target: ping -I br0-tun $VETH_IPV6"

echo "-- Start debug session with:"
echo "# ping 12.12.12.1; # check wireguard VPN connectivity"
echo "# wireshark -i veth-dbg; # remote monitoring of Codico layer2 traffic"
echo "# IFACE=veth-dbg afb-test/etc/binding-test-slac.sh; # start SLAC test"
echo "# ip link show master br0-tun  # display bridged ifaces"


