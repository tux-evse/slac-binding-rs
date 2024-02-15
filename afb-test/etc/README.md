In order to test locally SLAC you should setup a fake network with two interfaces.
Otherwise all packets would be send to a unique address. And both PEV/EVSE would receive a copy of every message they send.

The goal is to build a fake network as such
```
    pev -i vethA <--> br0 <--> vethB slac-binding
```

Create a br0 bridge and add virtual interface vethA+B to it
```bash
// create a virtual bridge for vethA & vethB
sudo ip link add br0 type bridge
sudo ip link set br0 up

for DEV in vethA:peerA vethB:peerB ; do \
  SRC=`echo $DEV | cut -f 1 -d :`
  DST=`echo $DEV | cut -f 2 -d :`
  echo "Connecting iface=$SRC to br0"; \
  sudo ip link add $SRC type veth peer name $DST; \
  sudo ip link set $SRC up; \
  sudo ip link set $DST up; \
  sudo ip link set $DST master br0; \
done
sudo ip link show master br0
```

Start wireshark on br0 to introspect all trafic
```
wireshark -i br0
```

Start afb-binder
```
IFACE="vethA" ./afb-test/etc/binding-test-slac.sh
```

Start EV emulator (require open-plc-utils)
```
pev -i vevthB
```


## Debug remote eth2 natively from your desktop

reference:


In order to expose the board eth2/codico ethernet device you need to setup your network as following:

```
 +--------------------------------------+                       +---------------------+
 | br0-tun bridge (codico ethX)         |                       | (remote dbg iface)  |
 | +--------------+                     |                       |                     |
 | | ethX gre-tun |<->wg0-tap<->udp2raw | <-Internet, TCP 443-> | udp2raw<->wg0-tap   |
 | +--------------+                     |                       |                     |
 +--------------------------------------+                       +---------------------+

 wg0-tap: 12.12.12.2/24                                         wg0-tap: 12.12.12.1/24
 br0-tun: 192.168.29.200/24
 gre-tun: 12.12.12.2->12.12.12.1
```

Generate PKI key
```
    su && cd
    mkdir wg-layer2
    cd wg-layer2
    on target: wg genkey | tee server-private.key | wg pubkey > server-public.key
    on desktop: wg genkey | tee client-private.key | wg pubkey > client-public.key

    exchange your public key files
```

Server on target
```
# open wireguard listening port on firewall
firewall-cmd --add-port=51820/udp --permanent
firewall-cmd --reload

# create wireguard interface
  ip l a wg0-tap type wireguard
  wg set wg0-tap private-key ./server-private.key
  ip a a 12.12.12.1/24 dev wg0-tap

# configure wireguard pki
  ip l set dev wg0-tap up
  wg set wg0-tap listen-port 51820 peer $(cat client-public.key) allowed-ips 0.0.0.0/0

# create layer2 tap device (require 'gre' kernel module)
  modprobe gre
  ip l a gre-tun type gretap local 12.12.12.1 remote 12.12.12.2
  ip l s gre-tun up

# configure bridge
  ip l add name br0-tun type bridge
  ip l set dev br0-tun up
  ip l set gre-tun master br0-tun
  ip l set eth2 master br0-tun  # or any other interface mapping with Codico

# assign a routable ip addr to the bridge
  ip a a 192.168.29.51/24 dev br0-tun # optional
```

Client on desktop
```
# create wireguard
ip l a wg0-tap type wireguard
wg set wg0-tap private-key ./client-private.key
ip a a 12.12.12.2/24 dev wg0-tap

# configure wireguard pki
ip l set dev wg0-tap up
wg set wg0-tap listen-port 51820 peer $(cat server-public.key) allowed-ips 0.0.0.0/0 endpoint YOUR_PUBLIC_IP:51820 persistent-keepalive 15
```


sending test udp-broadcast packet from target
```
echo -ne "titi-tata-toto" | socat -u - udp-datagram:255.255.255.255:30222,sourceport=30222,broadcast,reuseaddr
```

Debugging/delete config
```
ip link show master br0-tun
ip link delete wg0-tap
ip link delete br0-tun

```