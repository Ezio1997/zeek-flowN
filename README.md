# Zeek flowN

This project performs layer3 and layer4 network analysis and generate a set of features. These features contain the first-N packets of a flow and its 5-tuple composed of connection's orig_h/orig_p/resp_h/resp_p/protocol.

This project outputs json log and doesn't record icmp && ipv6 flows by default.