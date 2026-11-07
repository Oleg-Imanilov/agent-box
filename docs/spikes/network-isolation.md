# Spike: Docker network isolation

Task `net-spike` (Phase 0). Question: can a Docker `--internal` network plus a dual-homed gateway container force **all** agent egress through the gateway, without host iptables?

**Answer: yes, with one mandatory addition.** `--internal` alone leaks host-namespace services; the network must also use `gateway_mode_ipv4=isolated`.

## Setup

Script: [test/spikes/network/run.sh](../../test/spikes/network/run.sh) (`make spike-net`).

```text
ab-spike-int   (--internal, gateway_mode_ipv4=isolated)  ← agent + gateway
ab-spike-egress (normal bridge)                           ← gateway + "victim" container
host namespace: service on 0.0.0.0:18080                  ← stand-in for host services
```

- Agent probes run as `--cap-drop ALL --security-opt no-new-privileges` on the internal network only.
- Every negative probe has a **control** (same command from the egress network) so that a failure is not just a broken test. A probe whose control fails is reported INCONCLUSIVE.
- Image: `busybox:1.36`.

## Results

Environment: Docker Engine 29.8.0 on Docker Desktop (Windows, Linux VM). **Not native Linux** — re-run on native Linux before relying on these results (see open items).

| Probe | Result |
| --- | --- |
| agent → gateway by name, TCP 8080 | reachable (expected) |
| gateway → internet | reachable (expected) |
| direct TCP to `1.1.1.1:80`, `:443` | blocked |
| ICMP to `1.1.1.1` | blocked |
| UDP DNS to `1.1.1.1`, `8.8.8.8` | blocked |
| default resolver, external name | blocked (no external resolution) |
| cloud metadata `169.254.169.254` | blocked |
| host-namespace service via a bridge IP | blocked |
| other container on egress network; gateway's egress-side IP | blocked |
| `host.docker.internal` | does not resolve |
| `/var/run/docker.sock` | absent |
| Docker API on `:2375` | blocked |
| IPv6 TCP to `2606:4700:4700::1111` | **inconclusive** — control failed (host has no IPv6) |
| **Comparison:** plain `--internal` → host-namespace service via bridge IP | **LEAK** (reachable) |

Summary line from the last run: `pass=16 fail=0 inconclusive=1`.

## Findings

1. **No default route** on the agent network (`ip route` shows only the subnet), so all non-gateway destinations are unroutable.
2. **DNS:** the embedded resolver (`127.0.0.11`) resolves container names on the same network (e.g. the gateway) but **does not resolve external names** on an internal network. The gateway must therefore resolve names itself when handling `CONNECT host:port` (this matches the design). External DNS servers are unreachable over UDP, so no DNS tunneling out directly. The embedded resolver is still a side channel to examine: query names the agent can make the resolver forward to the host's upstream (`ExtServers: host(...)` is shown in `resolv.conf`) must be re-tested on native Linux.
3. **Plain `--internal` is insufficient.** Docker assigns an address to the host bridge for internal networks, and containers can reach **any** host service listening on `0.0.0.0` through that address. Verified: the comparison probe reached a host-namespace service. Docker's documentation describes this ("containers in the network can access host services listening on 'any' host address") and states that `isolated` gateway mode assigns no bridge address ([port publishing → gateway modes](https://docs.docker.com/engine/network/port-publishing/#gateway-modes)). With `isolated`, the same probe is blocked.
4. In isolated mode the first container receives the `.1` address; there is no host-side address on the network, so **the host/launcher cannot reach the agent over that network**. The launcher must use `docker exec`/attach (Docker API) for the TTY, not network access.
5. Isolated mode is only valid together with `--internal`; the launcher must create networks with both and verify the options via inspect.
6. The gateway is the only dual-homed container; its egress-side address is not routable from the agent network.

## Requirements derived for later tasks

- `launcher-core`: create agent network with `--internal` and `-o com.docker.network.bridge.gateway_mode_ipv4=isolated`; inspect and refuse to start if options are not applied; `doctor` checks engine support. Disable IPv6 on the network.
- `net-gateway`: resolve names itself; block private/loopback/link-local/metadata destinations **after** resolution (the gateway is on the egress network and can reach the LAN and host); do not publish any gateway admin port on the agent network.
- Never attach the controller or MCP servers to the agent network; only the gateways are dual-homed.
- Agents must use an explicit proxy/endpoint; non-proxy-aware traffic simply fails (fail closed).

## Open items (carry into `neg-tests`)

- [ ] Re-run on native Linux (Ubuntu CI runner) with a host listener on `0.0.0.0`.
- [ ] IPv6: run with an IPv6-capable host and a network created with IPv6 disabled/enabled; confirm no v6 egress.
- [ ] Embedded-DNS side channel: determine whether queries for external names from the agent are forwarded upstream on native Linux (`--internal` should not forward). Consider replacing with `--dns` pointed at the gateway resolver.
- [ ] `--network host`, `--privileged`, `NET_ADMIN`/`NET_RAW` are forbidden for agent containers; add tests proving the launcher never sets them.
- [ ] Minimum Docker Engine version for `gateway_mode_ipv4=isolated`; tested here on 29.8.0.
- [ ] Rootless Docker and Podman behavior.
