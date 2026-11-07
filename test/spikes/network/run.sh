#!/bin/sh
# AgentBox Phase 0 spike: can a Docker `--internal` network + gateway container
# force all agent egress through the gateway?
#
# For every probe we run it twice:
#   control: from a container on a normal (egress-capable) network  -> shows the probe CAN work
#   agent:   from a container on the internal network only          -> must be blocked
# A probe is only meaningful when the control succeeds (otherwise it is reported as INCONCLUSIVE).
#
# Requires: docker CLI + Linux engine. Uses public busybox image and 1.1.1.1 / example.com.
# Usage: sh test/spikes/network/run.sh
set -u

INT=ab-spike-int
INT_PLAIN=ab-spike-int-plain
EGR=ab-spike-egress
GW=ab-spike-gw
VICTIM=ab-spike-victim
HOSTSVC=ab-spike-hostsvc
IMG=busybox:1.36
PASS=0; FAIL=0; INCON=0
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

cleanup() {
  docker rm -f "$GW" "$VICTIM" "$HOSTSVC" >/dev/null 2>&1
  docker network rm "$INT" "$INT_PLAIN" "$EGR" >/dev/null 2>&1
}
cleanup
trap cleanup EXIT

docker pull -q "$IMG" >/dev/null || { echo "cannot pull $IMG"; exit 2; }

# Agent network: internal (no external route) + isolated (no host-side bridge IP, so host services are unreachable).
docker network create --internal -o com.docker.network.bridge.gateway_mode_ipv4=isolated "$INT" >/dev/null || exit 2
# Comparison network: plain --internal, which keeps a host-side bridge IP.
docker network create --internal "$INT_PLAIN" >/dev/null || exit 2
docker network create "$EGR" >/dev/null || exit 2

# Stand-in gateway: dual-homed (internal + egress), serves HTTP on 8080.
docker run -d --name "$GW" --network "$INT" "$IMG" \
  sh -c 'echo gateway-ok > /tmp/index.html; exec httpd -f -p 8080 -h /tmp' >/dev/null || exit 2
docker network connect "$EGR" "$GW" || exit 2

# Stand-in for another service on the host's default bridge (LAN-like target).
docker run -d --name "$VICTIM" --network "$EGR" "$IMG" \
  sh -c 'echo victim > /tmp/index.html; exec httpd -f -p 8080 -h /tmp' >/dev/null || exit 2
VICTIM_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$EGR\").IPAddress}}" "$VICTIM")

# Service listening in the host network namespace on all interfaces (the engine host / Docker Desktop VM).
docker run -d --name "$HOSTSVC" --network host "$IMG" \
  sh -c 'echo hostsvc > /tmp/index.html; exec httpd -f -p 18080 -h /tmp' >/dev/null || exit 2
EGR_GATEWAY_IP=$(docker network inspect -f '{{(index .IPAM.Config 0).Gateway}}' "$EGR")
GW_EGRESS_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$EGR\").IPAddress}}" "$GW")
INT_GATEWAY_IP=$(docker network inspect -f '{{(index .IPAM.Config 0).Gateway}}' "$INT_PLAIN")
sleep 1

agent()   { docker run --rm --network "$INT" --cap-drop ALL --security-opt no-new-privileges "$IMG" sh -c "$1" 2>&1; }
control() { docker run --rm --network "$EGR" --cap-drop ALL --security-opt no-new-privileges "$IMG" sh -c "$1" 2>&1; }

# probe <name> <command> <control: yes|no>
# Passes when the command FAILS from the agent network (and succeeds from control when control=yes).
probe() {
  name=$1; cmd=$2; ctl=$3; ctlcmd=${4:-$2}
  if [ "$ctl" = yes ]; then
    if ! control "$ctlcmd" >/dev/null; then
      printf 'INCONCLUSIVE  %s (control failed)\n' "$name"; INCON=$((INCON+1)); return
    fi
  fi
  if agent "$cmd" >/dev/null; then
    printf 'FAIL          %s (agent could reach target)\n' "$name"; FAIL=$((FAIL+1))
  else
    printf 'PASS          %s (blocked)\n' "$name"; PASS=$((PASS+1))
  fi
}

# allow <name> <command>: must SUCCEED from the agent network.
allow() {
  name=$1; cmd=$2
  if agent "$cmd" >/dev/null; then
    printf 'PASS          %s (reachable)\n' "$name"; PASS=$((PASS+1))
  else
    printf 'FAIL          %s (should be reachable)\n' "$name"; FAIL=$((FAIL+1))
  fi
}

echo "== Positive: gateway path =="
allow "agent -> gateway by name (TCP 8080)"      "wget -T 3 -q -O- http://$GW:8080/ | grep -q gateway-ok"
if docker exec "$GW" wget -T 5 -q -O /dev/null http://1.1.1.1/ >/dev/null 2>&1 || \
   docker exec "$GW" wget -T 5 -q -O /dev/null http://example.com/ >/dev/null 2>&1; then
  echo "PASS          gateway itself can reach the internet"; PASS=$((PASS+1))
else
  echo "FAIL          gateway cannot reach the internet"; FAIL=$((FAIL+1))
fi

echo "== Negative: direct egress from agent network =="
probe "direct TCP 1.1.1.1:80"                   "wget -T 3 -q -O /dev/null http://1.1.1.1/" yes
probe "direct TCP 1.1.1.1:443 (nc)"             "echo | nc -w 3 1.1.1.1 443" yes
probe "ICMP ping 1.1.1.1"                       "ping -c 1 -W 3 1.1.1.1" no
probe "UDP DNS to 1.1.1.1:53"                   "nslookup -timeout=3 example.com 1.1.1.1" yes
probe "UDP DNS to 8.8.8.8:53"                   "nslookup -timeout=3 example.com 8.8.8.8" yes
probe "default resolver resolves external name" "nslookup -timeout=3 example.com" yes
probe "IPv6 TCP [2606:4700:4700::1111]:80"      "wget -T 3 -q -O /dev/null 'http://[2606:4700:4700::1111]/'" yes
probe "cloud metadata 169.254.169.254:80"       "wget -T 3 -q -O /dev/null http://169.254.169.254/" no
probe "internal-net gateway IP $INT_GATEWAY_IP (host side)" "wget -T 3 -q -O /dev/null http://$INT_GATEWAY_IP:8080/" no
probe "host-namespace service via other bridge IP $INT_GATEWAY_IP:18080" "wget -T 3 -q -O /dev/null http://$INT_GATEWAY_IP:18080/" yes "wget -T 3 -q -O /dev/null http://$EGR_GATEWAY_IP:18080/"
probe "other container on egress network $VICTIM_IP:8080" "wget -T 3 -q -O /dev/null http://$VICTIM_IP:8080/" yes
probe "gateway's egress-side IP $GW_EGRESS_IP:8080" "wget -T 3 -q -O /dev/null http://$GW_EGRESS_IP:8080/" yes
probe "host.docker.internal"                    "wget -T 3 -q -O /dev/null http://host.docker.internal/" no
probe "docker.sock present"                     "test -S /var/run/docker.sock" no
probe "docker API tcp 2375 on bridge gateway"   "wget -T 3 -q -O /dev/null http://$INT_GATEWAY_IP:2375/version" no

echo "== Comparison: plain --internal network (without gateway_mode_ipv4=isolated) =="
if docker run --rm --network "$INT_PLAIN" --cap-drop ALL "$IMG" \
     wget -T 3 -q -O /dev/null "http://$INT_GATEWAY_IP:18080/" >/dev/null 2>&1; then
  echo "INFO          plain --internal LEAKS host-namespace services via bridge IP $INT_GATEWAY_IP (isolated mode required)"
else
  echo "INFO          plain --internal did not leak host-namespace services on this engine"
fi

echo "== Information (not pass/fail) =="
echo "agent /etc/resolv.conf:"; agent "cat /etc/resolv.conf"
echo "agent routes:";           agent "ip route; ip -6 route"
echo "agent default-route present? (expect none)"; agent "ip route | grep -c '^default' || true"
echo "agent can resolve gateway name via embedded DNS:"; agent "nslookup -timeout=3 $GW 2>&1 | tail -n 3"

echo
echo "Summary: pass=$PASS fail=$FAIL inconclusive=$INCON"
[ "$FAIL" -eq 0 ]
