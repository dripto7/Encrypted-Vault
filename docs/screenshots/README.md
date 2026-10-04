# Demo screenshots

Seven steps of the five-minute demo, captured from a real run against
`kvault.ko` loaded on Linux 7.1.5+kali-amd64.

| | Step | What it shows |
|---|---|---|
| `01-load.png` | Load | `/proc/kvault/status` reads `SEALED`; the two device nodes with different groups |
| `02-unseal.png` | Unseal and lockout | Unseal from the vault file; then three wrong passphrases lock it, and the **correct** one is refused too |
| `03-rbac.png` | Reference monitor | The same command denied, granted, allowed; eve refused by the kernel, carol refused at `open()` |
| `04-kvsim.png` | Simulation | Four principals in forked children, each dropped to its own UID — 16/16 |
| `05-audit-stream.png` | Live audit | A second terminal asleep in `poll()`, woken by the kernel as decisions are taken |
| `06-tamper.png` | The file on disk | Hex dump shows ciphertext; one flipped byte fails the GCM tag check |
| `07-autolock.png` | Auto-lock | A kernel timer wipes the key with no user-space process involved |

## How these were made

The commands were run for real and their output captured to
`transcripts/*.log`. Those transcripts are the evidence; the PNGs are the
same text rendered in a terminal-styled page so the important lines — an
allow, a denial, a state change — are findable at a glance in a report or
on a slide.

They are therefore **renderings of a real session, not photographs of a
screen**. The raw logs sit beside them so anything in an image can be
checked against the text it came from, and the whole run can be reproduced
by following the commands shown.

Colour is applied per token rather than per line: a results row contains
both `allow` and `deny`, so colouring whole lines would paint every denial
green merely because the row also contains the word "allow".
