---
title: "Rooting a Tapo camera through its Wi-Fi setup — CVE-2026-105810"
date: 2026-11-02
draft: false
tags: ["vulnerability-research", "firmware", "iot", "reverse-engineering", "exploitation", "cve"]
summary: "An authenticated client on the local network overflows a 1024-byte stack buffer in the TP-Link Tapo C320WS onboarding path and gets a ROP chain to system() as root. The bug is one wrong length argument."
cover:
  alt: "TP-Link Tapo C320WS"
---

This is the write-up for **[CVE-2026-105810](https://www.cve.org/CVERecord?id=CVE-2026-105810)**, a
stack overflow in the TP-Link Tapo C320WS camera that an authenticated client on
the adjacent network can turn into remote command execution as `root`. It was
reported through TP-Link's PSIRT, fixed in firmware `1.6.6 Build 260917`, and
[publicly credited](https://www.tp-link.com/us/support/faq/5351/). The PoC and a
terse technical summary live in the
**[disclosure repo](https://github.com/M0ud4/CVE-2026-105810)**; this post is the
longer story — where I looked, why this path, and the one line that was actually
wrong.

| | |
| --- | --- |
| **Product** | Tapo C320WS, hardware V2.0 |
| **Affected** | firmware ≤ `1.5.3 Build 260304` |
| **Fixed** | `1.6.6 Build 260917 Rel.81089n` |
| **Class** | CWE-121 — stack-based buffer overflow |
| **CVSS v4.0** | 8.5 (High) — `AV:A/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/...` |
| **Impact** | command execution as `root` |

## Why this target, and why the onboarding path

The camera is a cheap, extremely common device, and consumer IoT firmware is
reliably under-examined compared to anything that ships on a phone or a browser.
My rule for picking targets is to go where the fuzzers and the crowd aren't —
and to prove *attacker byte-reachability* before I spend a day on a bug. On a
camera, the interesting attack surface is the small local HTTP API: it parses
attacker-shaped input, it runs as root, and a good chunk of it is reachable the
moment you have a local account.

After extracting the filesystem and loading the main service binary into the
disassembler, I inventoried the API handlers and asked a boring question of each
one: *does attacker-controlled length ever drive a copy into a fixed buffer?*
The Wi-Fi onboarding handler — `onboarding.connect`, internally `connectAp` —
stood out immediately. It takes the encrypted Wi-Fi password the app sends
during setup and base64-decodes it into a buffer on the stack.

A decode-into-a-fixed-buffer is exactly the shape worth chasing: the output size
is a function of attacker input, and the destination is bounded. The only thing
standing between that and an overflow is whether the capacity argument passed to
the decoder is the *real* buffer size.

## The bug: the right library, the wrong argument

The buffer is a fixed **1024 bytes** on the stack. The decode goes through a
shared wrapper around mbedTLS's base64 routine. mbedTLS does the right thing —
`mbedtls_base64_decode` takes a destination length and refuses to write past it,
returning `BUFFER_TOO_SMALL` if the output won't fit. That bounds check is the
whole point of the API.

The problem is what the wrapper *tells* it the capacity is. Instead of passing
`1024` (the true size of the destination), the wrapper computes the capacity
from the **encoded input length**:

```c
// paraphrased from the decompiled wrapper
size_t olen = 4 * ((in_len + 2) / 3) + 1;   // "how big could the output be?"
mbedtls_base64_decode(dst /* 1024-byte stack buf */, olen, &out, in, in_len);
```

That formula is the base64 *encode* sizing formula — it answers "how many bytes
could decoding *produce*," not "how many bytes does `dst` have room for." So the
capacity handed to mbedTLS grows with the attacker's input. The library's bounds
check still runs faithfully; it just can never fail, because the number it's
checking against is derived from the same attacker data that's about to
overflow. You send a longer password, the claimed capacity gets bigger, and the
decode writes straight past the end of the 1024-byte stack buffer.

This is the part I find worth remembering: **using a memory-safe decoder buys
you nothing if you lie to it about the destination size.** The vulnerability
isn't in mbedTLS. It's one argument, computed from the wrong thing, one frame up.

## From overflow to root

Two properties of the binary turned the overwrite into reliable code execution:

- **No stack canary** on the decode routine. The function saves registers and
  returns through `POP {R4-R11, PC}`, so overwriting far enough past the buffer
  lands directly on a saved `PC`. Nothing checks a cookie on the way out.
- **Non-PIE ARM**. The executable loads at a fixed base, so gadget and string
  addresses are stable across runs. No infoleak needed — I could build the chain
  statically against the firmware image.

From there it's an ordinary ARM ROP chain: stage the command string, set up the
argument register, and return into `system()`. Since the service runs as root,
the command runs as root. The CVSS vector reflects the realistic preconditions —
adjacent network (`AV:A`) and a valid local account (`PR:H`) — which is the
camera's normal setup posture, not a remote-internet exposure.

## The annoying part: it's blind

The overflow executes the command but the API returns nothing useful — the
handler is already off the rails by the time it would reply. So you get no
confirmation in-band. For a while this is the thing that makes you doubt whether
the chain fired at all.

The verification I settled on is the one baked into the published PoC: run a
**benign marker command** — write `id`'s output to a file on the device —
and confirm it out of band from a shell on the hardware. The PoC defaults to
exactly that rather than anything hands-free, and it has a `--print-payload`
flag so you can inspect the bytes without sending them. The gadget offsets are
pinned to `1.5.3 Build 260304`; a different build needs them re-based.

```bash
# benign marker, verify the file out of band on your own device
python3 poc.py --host 192.168.0.10 --username admin --password 'YourCameraPassword'

# inspect the payload, send nothing
python3 poc.py --host x --password x --command 'id' --print-payload
```

## The fix

TP-Link addressed it in `1.6.6 Build 260917`. The correct fix is the obvious
one: pass the decoder the **actual destination capacity** (the real buffer size)
so its bounds check protects the buffer it's writing into, and reject input that
doesn't fit. If you own one of these cameras, update — the affected range is
everything at or below `1.5.3 Build 260304`.

## Takeaways

- **Decode-into-fixed-buffer is a reliable smell.** When output size is a
  function of attacker input and the destination is bounded, the only question
  is whether the capacity argument is honest.
- **A safe primitive with a dishonest length is an unsafe primitive.** mbedTLS
  did its job. The bug was the caller lying about the room it had.
- **Reachability first.** The reason this was worth exploiting is that the path
  is reachable with nothing more than a local account the owner already has, and
  it runs as root. A beautiful overflow behind an unreachable code path is a
  hobby, not a finding.

Full PoC, payload builder, and the responsible-use notes are in the
[disclosure repo](https://github.com/M0ud4/CVE-2026-105810).
