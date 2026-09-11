# NAT traversal comparison lab

This Linux-only lab uses the local `zakura-network` crate's
`ZakuraLocalLimits::from_config(...).transport_config()` and the published
`zakura-iroh 1.1.0-rc.1` transport. It compares the committed
`network.zakura.nat_traversal` opt-in against the disabled default.

The endpoints run in separate Patchbay network namespaces behind separate
moderate NATs (endpoint-independent mapping, address-and-port-dependent
filtering). They use IPv4 only, so IPv6 cannot bypass the NAT experiment.
A third network hosts a local relay. No public relay is contacted.

```text
phone -- NAT B -- simulated Internet -- NAT A -- home
                         |
                    local relay
```

## Run

From the repository root, on Linux with unprivileged user namespaces, `ip`,
`nft`, and `tc` available:

```sh
qa/nat-lab/run.sh
# Or choose a fresh output directory:
qa/nat-lab/run.sh /tmp/zakura-nat-results
```

Run as an ordinary user, outside any sandbox that blocks netlink or namespace
operations. The runner initializes a user namespace before starting threads.
Virtual interfaces, routes, and firewall rules belong to disposable namespaces;
it does not change the host firewall. Dependencies need network access on the
first build. The two helper binaries are built with their checked-in lockfiles.

The relay has a separate Cargo workspace and process because its server feature
requires stable `digest`, incompatible with the node's BIP32 prerelease pin.
The endpoint lockfile was seeded from the node's lockfile to preserve the
production dependency versions, including noq 1.2.0. Keep these aligned when
updating the node's transport. The relay's self-signed certificate is accepted
only by this lab's endpoint builder.

## Assertions

For each case, create fresh endpoints, routers, and NAT state. Bootstrap using
only the relay address, with no direct socket hints. Transfer 1 MiB to the server
and echo it back, validating length and a BLAKE2b digest. Observe the selected
path for up to ten seconds. Kill and reap the relay process, remove its virtual
device, and attempt another checksummed transfer, with an eight-second deadline.

| Server traversal | Client traversal | UDP | Expected selected path | Transfer after relay cutoff |
| --- | --- | --- | --- | --- |
| Off | Off | Allowed | Relay | Fails |
| Off | On | Allowed | Relay | Fails |
| On | Off | Allowed | Relay | Fails |
| On | On | Allowed | Direct IP | Succeeds |
| On | On | Blocked on client | Relay | Fails |

The UDP control keeps DNS and TCP available, allowing the relay connection while
blocking QUIC and QUIC address discovery. Disabled/mixed cases additionally
assert zero candidate-address and traversal-probe frames at the client.

Two further cases disable the relay entirely, with traversal off/off and on/on.
The dialer receives the server's identity, NAT WAN IP, and local listening port,
but no forwarding or NAT mapping is installed. Both must fail to connect within
ten seconds. This demonstrates that the flag alone supplies no rendezvous path.

## Output and limits

Each run saves `summary.json`, `results.jsonl`, `lab.log`, the repository revision,
and Patchbay's per-device events and topology state. Reports include connection
time, selected paths, traversal-frame counts, payload digest, and the result
following relay cutoff. `observed_ms` measures time through the first transfer
and path observation; it is not a precise hole-punch latency benchmark.

This tests production **transport configuration**, not the full Zakura protocol,
peer admission, block sync, mobile OS behavior, or production relay support.
The lab adds a relay explicitly; shipping `zakurad` still disables relays and
external address lookup. A relay-only successful transfer is never counted as
successful hole punching. The local simulated NAT results do not establish
success across arbitrary home routers or carrier NATs.

The lab design follows the pinned Iroh package's `tests/patchbay.rs` and
`tests/patchbay/util.rs`; the test runner here uses the Zakura configuration and
adds the on/off matrix and destructive relay-cutoff check.

## Recorded validation

The 2026-09-11 run against production commit `265e5b141` passed all seven cases.
See [example-results.json](example-results.json). With both ends enabled, the
selected path changed from relay to `198.18.0.11:60101`, and the 1 MiB echo
transfer succeeded after relay termination. The other four relay cases failed
the post-cutoff transfer as expected. Neither no-relay case connected.

Formatting, shell syntax, and Clippy with `--no-deps -- -D warnings` passed for
both standalone crates. These results cover one complete seven-case run;
they are not a statistical reliability or real mobile-network benchmark.
