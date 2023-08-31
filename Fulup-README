# libslac Iso15118-3 binding
=============================

WARNING: on going work, will probably not work for you

## Provides

* Rust implementation of libslac Iso15118-3
* afb-binding micro service architecture and security model [api-v4](https://github.com/redpesk-common/afb-librust/blob/master/docs/1-architecture_presentation.md)

## References

This code is freely inspired from differences open-sources references:

* Switch PySlac [1]
* Pionix SLAC   [2]
* Qualcomm [3]
* HomePlug(SLAC) [4] [5]

## Abbreviation

 * AVLN/sub-AVLN: AV In-Home Logical Network
 * STA: Network Station
 * NMK: Network MemberShip Key
 * NID: Network Identifier (7 bytes)
 * SNID: Short Network ID (4bits)
 * PEV: Plug-In Electric Vehicule
 * EVSE: Electric Vehicle Supply Equipment
 * CCo Capability (CCoCap) Spec: 4.4.3.14 p155
 * HLE: Higher Layer Entity spec: 11.1 p 467
 * HPGP: Homeplug Green PHY

## Few Security Concepts

* From spec definition, all stations sharing the same NMK/NID are assumed to be trustworthy.
* STA station from a sub-AVLN should be able to exchange confidential information not exposed outside sub-AVLN
* We assume that a neighbor may be able to eavesdrop on transmissions within a residence,
  and may also be able to send transmissions to stations within that residence, without the
  knowledge of the users in that residence
* The mechanism for generating the NID Offset from the NMK shall be the PBKDF1 using SHA-256.
  The iteration count used to calculate the NID Offset shall be 5. (see spec:p182)
* this process require CAP_NET_RAW

To add CAP_NET_RAW to afb-binder use
```
# afb-binder started from bash should have CAP_NET_RAW capability
sudo setcap cap_net_raw+eip /usr/(local)/bin/afb-binder

# when debugging from vscode/codium (use 'ps -ef | grep lldb-server' to find corresponding version)
sudo setcap cap_net_raw+eip $HOME/.vscode-oss/extensions/vadimcn.vscode-lldb-1.9.2-universal/lldb/bin/lldb-server
```

## General Flow

![overview](docs/slac-overview.png)
[see Synacktiv V2G] [6]

* STATE: JOIN_NETWORK
    * EVSE -> HPGP node CM_SET_KEY.REQ
    * HPGP -> EVSE CM_SET_KEY.CNF
    Set NID from NMK

 * STATE: IDLE/WAITING
    * PEV  -> EVSE CM_SLAC_PARAM.REQ
    * EVSE -> PEV CM_SLAC_PARAM.CNF
        - forwarding_stat (mac addr)
        - num_sound
        - timeout

 * State: SOUNDING/MATCHING
    * PEV->EVSE CM_MNBC_SOUND.IND (* EVSE requested number of sound)
    * EVSE -> PEV  CM_ATTEN_CHAR.IND
    * PEV  -> EVSE CM_ATTEN_CHAR.RSP (msg.result == 0)
    * PEV  -> EVSE CM_SLAC_MATCH.REQ

 * State: MATCHED
    * EVSE -> PEV  CM_SLAC_MATCH.CNF

## testing with simulator

### create dummy eth iface
Following script will create a virtual bridge whit two iface (vethA+VethB)
Any layer2 broadcast packet send on vethA is propagated to vethB

```
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
# sudo ip link show master br0
# sudo ip dev dev br0,vethA,...
```

lancer wireshark sur interface veth-xx
```
# note on OpenSuse sudo fail to start wireshark
su -c  "wireshark -i vethA -k -S"
```

## Reference

* [1]: Switch PySlac: https://github.com/SwitchEV/pyslac
* [2]: Pionix SLAC simple library https://github.com/EVerest/libslac
* [3]: Qualcomm Open-Pcl: https://github.com/qca/open-plc-utils
* [5] https://docbox.etsi.org/Reference/homeplug_av11/homeplug_av11_specification_final_public.pdf
* [5] https://docbox.etsi.org/Reference/homeplug_av21/homeplug_av21_specification_final_public.pdf
* [6]: Synacktiv V2G injector (https://www.sstic.org/media/SSTIC2019/SSTIC-actes/v2g_injector_playing_with_electric_cars_and_chargi/SSTIC2019-Article-v2g_injector_playing_with_electric_cars_and_charging_stations_via_powerline-dudek.pdf)

------------ Fulup TBD -----------------
- Verifier que les data de CM request sont OK

