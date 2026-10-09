# The miu protocol (wire format, version 2)

English | [简体中文](PROTOCOL.zh-CN.md)

This document is the wire format of miu and the behaviour it requires. Implementations follow this document.

There are only two goals: **no waiting for a new connection** (opening a stream on a warm lane needs no handshake and
waits for no reply) and **no slowdown for bulk traffic** (the inner TLS is not encrypted twice, there is no
application-level flow control, and streams do not block one another).

## 1. Model

```
lane        = one TCP connection + outer TLS 1.3 / REALITY + one authentication
lane state    idle (in the pool) → busy (exactly one stream) → idle → …
```

- A lane carries one stream at a time and goes back to the pool when the stream ends. There is no multiplexing, hence
  no flow-control windows; back-pressure is left entirely to TCP.
- Two kinds of things alternate on a lane: **frames** inside outer TLS records, and **raw segments** that follow a RAW
  frame and are written directly on TCP, bypassing the outer TLS.
- When the outer layer is not a TLS / REALITY connection sitting directly on TCP (plaintext, WebSocket, TLS terminated
  by a reverse proxy), there are no raw segments; everything else is the same.

## 2. Authentication header (the first bytes the client sends after the outer handshake)

```
token(32) · padlen(u16 BE) · padding(padlen)
token = sha256(psk string)        // the UTF-8 bytes of the configured string with leading and trailing whitespace removed; not base64-decoded
```

- The server looks the user up by token and closes the connection when there is no match. The psk string must be
  byte-for-byte identical on both ends.
- `padlen` is entry 0 of the padding scheme (30 by default).
- The Settings frame follows the authentication header immediately (in the same write). After that the client may open
  a stream at any time, **without waiting for any reply**.

## 3. Frames

```
type(1) · len(u16 BE) · payload
```

| type | Name | Direction | payload |
|---|---|---|---|
| 0 | PAD | both | anything; discarded |
| 1 | Settings | C→S | text |
| 2 | ServerSettings | S→C | text |
| 3 | UpdatePaddingScheme | S→C | scheme text |
| 4 | OPEN | C→S | target as a socksAddr |
| 5 | DATA | both | data (encrypted once, by the outer TLS only) |
| 6 | RAW | both | u32 BE = N. **Must be the last frame of its TLS record**; N raw bytes follow on TCP, then TLS records resume |
| 7 | END | both | empty. The data of this direction ends here |
| 8 | RESET | C→S | empty. Abort this stream: the uplink ends here (as with END), and the server is asked to stop the downlink as soon as possible and send END |

- A frame may span TLS records (the receiver parses frames from the byte stream). The one exception is RAW: the sender
  puts it in a record of its own; the receiver only requires that it is the last frame of its record.
- Address encoding (socksAddr): `family(1) · addr · port(u16 BE)`, with family 0x01 IPv4 (4 B) / 0x03 domain name
  (len(1)+bytes) / 0x04 IPv6 (16 B).
- There are no stream ids, no SYNACK and no heartbeats.

## 4. Settings (newline-separated key=value)

```
C→S  v=2 · raw=0|1 · padding-md5=<md5 hex of this side's scheme>
S→C  v=2 · raw=0|1 · idle=<seconds the server keeps an idle lane>
```

- `raw`: whether this side can **receive** raw segments (only when the outer layer is TLS / REALITY directly on TCP).
  RAW may be sent to a peer only after it has declared `raw=1`. The client does not need to wait for ServerSettings on
  purpose: by the time it wants to send a raw segment (after the inner handshake) ServerSettings has long arrived.
- When the server sees a `padding-md5` different from its own scheme, it follows ServerSettings with an
  UpdatePaddingScheme frame.
- ServerSettings / UpdatePaddingScheme / PAD may appear anywhere; every place that reads frames must accept them.

## 5. A stream

```
C→S  OPEN(target) · DATA(the application's first bytes, if any)          // one packet, sent immediately
…    in each direction: DATA* → (RAW N · N raw bytes)* → END
both sides have sent END → the lane is idle; the client puts it back in the pool and the next stream starts with OPEN
```

- The server does not answer OPEN. When it cannot reach the target, the downlink is just END, and the uplink is
  discarded until the client's END.
- Half-close: a direction sends END when its data source ends; the other direction carries on.
- When one end can no longer write to its local peer (which has already closed), it must still read that direction on
  the lane up to END and discard it; only then can the lane be used again.
- When a lane has been idle for `idle` seconds without an OPEN, the server closes it.
- The end of a stream (END) and a broken connection are different things: if the connection breaks before a direction
  has received END, that is an error for the layer above, not a normal end.

### 5.1 When raw segments are used

The sender of each direction decides. The condition is the same as XTLS-Vision's switch to direct copy, but the record
boundaries of the inner TLS are tracked on the byte stream, so no single read has to happen to be aligned:

1. Parse the record headers of this direction's inner data as it passes (5 bytes: type · 0x03 · ver · len). If the
   first record does not look like TLS (the second byte is not 0x03, or type is outside 0x14–0x17) → this stream uses
   DATA for good. If 64 KiB have passed without reaching step 3 below → give up likewise.
2. When the downlink shows a ServerHello (a handshake record, message type 2) whose supported_versions extension selects
   0x0304 → note that "the inner layer is TLS 1.3". The client recognises this in the DATA it receives (its uplink
   depends on this conclusion).
3. Once "the inner layer is TLS 1.3" holds, when a record header with type = 0x17 is met at a record boundary: the
   batch that contains this record header still goes as DATA, and **from then on this direction is in the raw phase**
   until END, with no further inspection of the content. The peer must have declared `raw=1`.
4. In the raw phase the sender chooses RAW or DATA for each batch (the receiver must accept either at any time). A batch
   smaller than 4 KiB goes as DATA: a RAW frame takes a record of its own, so small data would double the packet count,
   and the little encryption saved is not worth it.

So plaintext, the plaintext part of the inner handshake, and TLS 1.2 stay inside the outer TLS; raw segments hold only
inner TLS 1.3 ciphertext records.

### 5.2 Raw segments

- The sender declares as many bytes as it has at hand (at most 1 MiB per segment): it first writes a record holding
  only the RAW frame, then writes the bytes directly to TCP. Where possible, let the two writes leave together
  (TCP_CORK on Linux, or a single combined write) so that the record of a few dozen bytes does not take a packet of its
  own.
- After reading a RAW frame, the receiver takes exactly N bytes from TCP (first those the TLS layer has already read
  into its buffer, then from the socket) and goes back to reading TLS records.
- Raw segments are not protected by the outer TLS's integrity check; tampering is detected by the inner TLS itself. A
  wrong byte count makes the next outer record undecryptable, and the lane is closed as a result.

### 5.3 Abort

When the client no longer wants the stream (the application closed the connection, a speed test has read enough, a UDP
session expired): send RESET, then read the downlink up to the server's END and discard it; the lane goes back to the
pool as usual. **Do not close the lane just because a stream is aborted** — these cases are common, and discarding a
lane each time means the pool never keeps warm connections.

- RESET may be sent before the uplink END (in place of it) or after the uplink END (the application half-closes first
  and then closes entirely; this is the most common order). It may be sent as long as the downlink END has not been
  received. If the stream is aborted before OPEN was sent, nothing needs to be sent. If it is aborted after the
  downlink END has been received while the uplink is still open, there is nothing left to abort: send END to finish
  the uplink, not RESET.
- On RESET the server stops the stream (closes the connection to the target) and sends END on the downlink after the
  segment in progress. If it is in the middle of moving a raw segment onto the connection, it finishes that segment
  first — the declared byte count must be delivered in full, otherwise the lane is out of sync. A RESET that arrives
  after the stream has ended is ignored.
- The client waits for END with a deadline (3 s) and closes the lane only when the deadline passes. The server's read
  loop must keep reading frames after a stream's uplink END (otherwise it cannot receive a RESET sent afterwards).
- A server that does not know RESET closes the lane as a protocol error, which amounts to "abort = close the lane".
- When a relay can no longer write to its local peer (which has already closed), treat it as an abort too: send RESET
  rather than receiving the rest of the downlink for nothing.

## 6. Packet-length shaping

The text format of AnyTLS's padding scheme is reused (`stop=N` and `<idx>=<a>-<b>[,c,<a>-<b>…]`). There is a built-in
default scheme, and the server may push one to replace it.

The default scheme:

```
stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000
```

- Entry 0: the length of the padding after the authentication header.
- Packet numbers start at 1 **per stream and per direction**. Each batch of data in the DATA phase is one packet (the
  client's packet 1 = OPEN · first DATA). A packet whose number is below stop is cut into TLS records of the prescribed
  lengths, filled up with PAD frames where the data is short; whatever is left when the scheme runs out follows in one
  piece. `c` means "stop here if the data has all been sent, otherwise keep cutting".
- RAW frames and raw segments are not shaped (once in the raw phase there are no "packets" any more).
- **END is not shaped, and it is the last byte of its direction**: no PAD and no record of any kind may follow END.
  Bytes that arrive after the lane has gone back to the pool are taken by the peer as "the server is closing this
  lane", and the lane is dropped.
- `padding-md5` is the md5 of the scheme text bytes (lowercase hex). The text of the default scheme is the 9 lines
  above joined with `\n`, without a trailing newline; for a scheme pushed by the server it is computed over the bytes in
  the UpdatePaddingScheme frame.

## 7. UDP (UoT v2; the wire format is the same as sing's)

- The target in OPEN is `sp.v2.udp-over-tcp.arpa:0`. The bytes in the stream are: a request header
  `isConnect(1) · socksAddr(target)`, then for each packet `[uotAddr (when not connect)] · len(u16 BE) · payload`;
  uotAddr family 0x00 IPv4 / 0x01 IPv6 / 0x02 domain name. When not connect, the target in the request header is the
  destination of the first packet; every packet after that carries its own address.
- DATA is used throughout, and a packet may span frames. The server uses one UDP socket per UoT stream and sends back
  inbound packets from any source together with their source address (full-cone).
- The lane is exclusive, so a UDP stream is never blocked by another stream's loss and retransmission.

## 8. Lane pool (client)

| Item | Value |
|---|---|
| Idle lane retention | The 4 most recently returned lanes for 120 s, the rest for 30 s; never more than the server's `idle` − 5 s (the server's default `idle` is 180) |
| Idle lane limit | 32 (16 is reasonable on memory-constrained mobile devices); beyond that the oldest is closed |
| Pre-warming | When the previous stream was opened within the last 10 s, top the idle lanes up to 2 (complete the outer handshake, send the authentication header and Settings, and leave them there) |
| Taking a lane | Last in, first out. Before taking one, peek without reading data; if the peer has closed it, drop it and try the next |
| Opening a stream | Wait at most 10 ms for the application's first data and merge it into the same packet as OPEN; if none arrives, send OPEN on its own |

- Why 4 lanes are kept for 120 s: two clicks are often more than half a minute apart, and with an empty pool the next
  one needs a handshake again. Idle lanes send no heartbeats, so keeping a few more costs almost nothing.
- No data should arrive on a used lane while it is idle: if it does, the server is closing the lane; drop it. This
  does not apply to a pre-warmed lane that has never been used: the server's ServerSettings stays unread in the
  socket, so seeing data in the peek before use is normal there.
- After a network change (Wi-Fi ↔ cellular) every lane in the pool is dead; empty the whole pool.
- Replay on a dead lane (recommended): the peek before use does not reveal every dead lane (an expired NAT entry, a peer
  that vanished silently). If the stream was opened on a lane taken from the pool, has not yet received any downlink,
  and has sent no more than 64 KiB of uplink, then on a write or read failure empty the pool, dial a new lane and resend
  OPEN and the uplink sent so far (including END if the uplink has already ended) exactly once. Replay only once; the
  application does not notice.

## 9. Implementation notes

- **Never read past a frame.** Read frames on demand and take exactly what was read. A buffered reader would also
  swallow the raw bytes that follow a RAW frame, as if they were TLS plaintext.
- **Go's crypto/tls (including forks that keep the same structure, such as uTLS and REALITY)**: once `Read` has drained
  a record it peeks at the next byte in the buffer and, if that byte is 0x15, parses it as an alert record; the first
  byte of a raw segment can be anything. What to do: read the first 3 bytes of the RAW frame body with `Read` as usual,
  and take the last one directly from the connection's `input` buffer, so that `Read` never drains the record. Take the
  raw segment from `rawInput` first (the TLS layer over-reads from the socket, so the beginning of the segment is often
  already there), then read the underlying connection; when reading the underlying connection, do not read more than
  what is left of this segment, or push the surplus back into `rawInput`. These two buffers are unexported fields and
  can only be reached by reflection. After a change of Go version, run a self-test first (send a raw segment whose first
  byte is 0x15 and check that it arrives unchanged); if the buffers cannot be reached or the self-test fails, declare
  `raw=0`.
- It must be possible to keep reading after a read timeout: a read timeout does not damage the read state of a Go TLS
  connection, and the implementation itself keeps the progress of a half-read frame header. A write timeout, however,
  invalidates the TLS write state, and that lane can only be closed.
- The bytes of raw segments do not pass through any traffic-counting wrapper on the connection; to count them, account
  for them by hand.
- KeyUpdate on the outer layer is not handled: none of the TLS stacks used by known implementations sends it on its
  own.
- The server's downlink can be zero-copy on Linux: first ask how many bytes are in the receive buffer of the target
  connection right now (FIONREAD), write a RAW frame for that number, then splice exactly that many bytes to the client
  connection — they are already in the kernel, so what was declared can always be delivered. On an abort, finish the
  segment in hand before closing the connection to the target.
