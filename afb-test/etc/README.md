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
