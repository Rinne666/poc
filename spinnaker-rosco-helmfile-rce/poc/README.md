# PoC

One script, one finding.

| File | What it does |
|---|---|
| `entry_hook_marker.py` | sends a control and a payload bake to rosco and reports which one executed |

## Run it

```bash
python3 poc/entry_hook_marker.py \
    --base http://localhost:18087 \
    --container <rosco-container> \
    --confirm-authorised
```

| Option | Meaning |
|---|---|
| `--base` | rosco base URL **as this host reaches it** (not as rosco reaches it) |
| `--container` | rosco container name; the marker is only visible from inside it |
| `--artifact-host` | how rosco reaches this machine (default `host.docker.internal`) |
| `--marker` | marker filename (default `rosco-poc-marker.txt`) |
| `--confirm-authorised` | **required.** The script refuses without it and exits 1 |

## What it sends

Two helmfile bodies, served from a temporary local HTTP server, referenced as
`http/file` input artifacts.

**control** — a `hooks:` entry and nothing else. Parseable, so the guard reads it:

```yaml
hooks:
  - events: ["prepare"]
    command: "sh"
    args: ["-c", "id > /tmp/rosco-poc-marker.txt; pwd >> ...; date >> ..."]
```

**payload** — byte-identical, plus one value nested past SnakeYAML's 50-level limit
(`GUARD_DEPTH_LIMIT + 12`; the document measures 64 levels deep). A guard parsing with
the default depth limit throws. Whether that throws is a *rejection* or a *skip* is the
vulnerability.

## Reading the result

| build | control | payload | exit |
|---|---|---|---|
| ≤ 2026.3.0 — no guard | executes | executes | **0** |
| 2026-09-19 `main-latest` — incomplete guard | rejected | **executes** | **0** |
| rosco-2026.3.1 — hardened | rejected | rejected | **2** |

| Exit | Meaning |
|---|---|
| 0 | reproduced — the marker was written by the hook |
| 1 | usage error, or rosco unreachable |
| 2 | did not reproduce; the guard rejected the request |
| 3 | inconclusive — no marker and no rejection. Check `../report.md` §5 |

Exit 3 is a real outcome, not a bug: the common causes are the wrong artifact type
(`http` and `file` both 404; only `http/file` resolves), `--helm-binary` not being helm3,
checking the marker from the host instead of inside the container, or trusting a `202`
from gate as proof that orca accepted the trigger.

## Inertness

| Prohibited by this repository's rules | What this does instead |
|---|---|
| reverse shell | writes one marker file into rosco's own `/tmp` |
| data exfiltration | prints `uid`/`gid` — the value needed to prove execution |
| outbound beacon | **none.** The original audit used one as an observation aid; it is dropped here |
| persistence | nothing survives; the marker is removed after being read |
| bundled gadget chain | a `prepare` hook whose only behaviour is the marker write |

It needs `docker exec` access to the rosco container to verify, which is a local
privilege you already have on your own test stack.

## State

This script was written to this repository's conventions from the documented
reproduction. **It has not been executed** — the evidence in `../evidence/` is from the
original bash drivers of 2026-09-19. Run it, capture the output verbatim into
`../evidence/`, and correct anything that does not hold.
