#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# End-to-end ipvs test suite
# Topology:
#--------------------------------------------------------------+
#                      |                                       |
#         ns0          |         ns1                           |
#      -----------     |     -----------    -----------        |
#      | veth01  | --------- | veth10  |    | veth12  |        |
#      -----------    peer   -----------    -----------        |
#           |          |                        |              |
#      -----------     |                        |              |
#      |  br0    |     |-----------------  peer |--------------|
#      -----------     |                        |              |
#           |          |                        |              |
#      ----------     peer   ----------      -----------       |
#      |  veth02 | --------- |  veth20 |     | veth21  |       |
#      ----------      |     ----------      -----------       |
#                      |         ns2                           |
#                      |                                       |
#--------------------------------------------------------------+
#
# We assume that all network driver are loaded
#

source lib.sh

ret=0
GREEN='\033[0;92m'
RED='\033[0;31m'
NC='\033[0m' # No Color

readonly port=8080

readonly vip_v4=207.175.44.110
readonly cip_v4=10.0.0.2
readonly gip_v4=10.0.0.1
readonly dip_v4=172.16.0.1
readonly rip_v4=172.16.0.2
readonly sip_v4=10.0.0.3

readonly vip_v6=fd00:3::1
readonly cip_v6=fd00:1::2
readonly gip_v6=fd00:1::1
readonly dip_v6=fd00:2::1
readonly rip_v6=fd00:2::2

readonly infile="$(mktemp)"
readonly outfile="$(mktemp)"
readonly datalen=32

sysipvsnet="/proc/sys/net/ipv4/vs/"
if [ ! -d $sysipvsnet ]; then
	if ! modprobe -q ip_vs; then
		echo "skip: could not run test without ipvs module"
		exit $ksft_skip
	fi
fi

checktool "ipvsadm -v" "run test without ipvsadm"
checktool "socat -h" "run test without socat"
checktool "python3 -c pass" "run test without python3"

setup() {
	setup_ns ns0 ns1 ns2

	ip link add veth01 netns "${ns0}" type veth peer name veth10 netns "${ns1}"
	ip link add veth02 netns "${ns0}" type veth peer name veth20 netns "${ns2}"
	ip link add veth12 netns "${ns1}" type veth peer name veth21 netns "${ns2}"

	ip netns exec "${ns0}" ip link set veth01 up
	ip netns exec "${ns0}" ip link set veth02 up
	ip netns exec "${ns0}" ip link add br0 type bridge
	ip netns exec "${ns0}" ip link set veth01 master br0
	ip netns exec "${ns0}" ip link set veth02 master br0
	ip netns exec "${ns0}" ip link set br0 up
	ip netns exec "${ns0}" ip addr add "${cip_v4}/24" dev br0

	ip netns exec "${ns1}" ip link set veth10 up
	ip netns exec "${ns1}" ip addr add "${gip_v4}/24" dev veth10
	ip netns exec "${ns1}" ip link set veth12 up
	ip netns exec "${ns1}" ip addr add "${dip_v4}/24" dev veth12

	ip netns exec "${ns2}" ip link set veth21 up
	ip netns exec "${ns2}" ip addr add "${rip_v4}/24" dev veth21
	ip netns exec "${ns2}" ip link set veth20 up
	ip netns exec "${ns2}" ip addr add "${sip_v4}/24" dev veth20

	sleep 1

	dd if=/dev/urandom of="${infile}" bs="${datalen}" count=1 status=none
}

cleanup() {
	cleanup_all_ns

	if [ -f "${outfile}" ]; then
		rm "${outfile}"
	fi
	if [ -f "${infile}" ]; then
		rm "${infile}"
	fi
}

server_listen() {
	ip netns exec "$ns2" timeout 5 socat -u -4 TCP-LISTEN:8080,reuseaddr STDOUT > "${outfile}" &
	server_pid=$!
	sleep 0.2
}

client_connect() {
	ip netns exec "${ns0}" timeout 2 socat -u -4 STDIN TCP:"${vip_v4}":"${port}" < "${infile}"
}

verify_data() {
	wait "${server_pid}"
	cmp "$infile" "$outfile" 2>/dev/null
}

test_service() {
	server_listen
	client_connect
	verify_data
}


test_dr() {
	ip netns exec "${ns0}" ip route add "${vip_v4}" via "${gip_v4}" dev br0

	ip netns exec "${ns1}" sysctl -qw net.ipv4.ip_forward=1
	ip netns exec "${ns1}" ipvsadm -A -t "${vip_v4}:${port}" -s rr
	ip netns exec "${ns1}" ipvsadm -a -t "${vip_v4}:${port}" -r "${rip_v4}:${port}"
	ip netns exec "${ns1}" ip addr add "${vip_v4}/32" dev lo:1

	# avoid incorrect arp response
	ip netns exec "${ns2}" sysctl -qw net.ipv4.conf.all.arp_ignore=1
	ip netns exec "${ns2}" sysctl -qw net.ipv4.conf.all.arp_announce=2
	ip netns exec "${ns2}" ip addr add "${vip_v4}/32" dev lo:1

	test_service
}

test_nat() {
	ip netns exec "${ns0}" ip route add "${vip_v4}" via "${gip_v4}" dev br0

	ip netns exec "${ns1}" sysctl -qw net.ipv4.ip_forward=1
	ip netns exec "${ns1}" ipvsadm -A -t "${vip_v4}:${port}" -s rr
	ip netns exec "${ns1}" ipvsadm -a -m -t "${vip_v4}:${port}" -r "${rip_v4}:${port}"
	ip netns exec "${ns1}" ip addr add "${vip_v4}/32" dev lo:1

	ip netns exec "${ns2}" ip link del veth20
	ip netns exec "${ns2}" ip route add default via "${dip_v4}" dev veth21

	test_service
}

test_tun() {
	ip netns exec "${ns0}" ip route add "${vip_v4}" via "${gip_v4}" dev br0

	modprobe -q ipip
	ip netns exec "${ns1}" ip link set tunl0 up
	ip netns exec "${ns1}" sysctl -qw net.ipv4.ip_forward=0
	ip netns exec "${ns1}" sysctl -qw net.ipv4.conf.all.send_redirects=0
	ip netns exec "${ns1}" sysctl -qw net.ipv4.conf.default.send_redirects=0
	ip netns exec "${ns1}" ipvsadm -A -t "${vip_v4}:${port}" -s rr
	ip netns exec "${ns1}" ipvsadm -a -i -t "${vip_v4}:${port}" -r ${rip_v4}:${port}
	ip netns exec "${ns1}" ip addr add ${vip_v4}/32 dev lo:1

	ip netns exec "${ns2}" ip link set tunl0 up
	ip netns exec "${ns2}" sysctl -qw net.ipv4.conf.all.arp_ignore=1
	ip netns exec "${ns2}" sysctl -qw net.ipv4.conf.all.arp_announce=2
	ip netns exec "${ns2}" sysctl -qw net.ipv4.conf.tunl0.rp_filter=0
	ip netns exec "${ns2}" ip addr add "${vip_v4}/32" dev lo:1

	test_service
}

# Send one UDP datagram of ${2} bytes from the client to the IPv6 service and
# keep the socket open for a moment, so that a packet too big message for it
# is accepted.
udp_send_v6() {
	ip netns exec "${ns0}" python3 -c '
import socket, sys, time
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 0))
s.sendto(b"x" * int(sys.argv[3]), (sys.argv[2], int(sys.argv[4])))
time.sleep(0.5)
' "${cip_v6}" "${vip_v6}" "${1}" "${port}"
}

# Send a packet too big message with MTU ${1} for ${dip_v6} -> ${rip_v6} from
# the real server to the director. The director sees what a router on the path
# to the real server would tell it, and learns a PMTU exception for ${rip_v6}.
send_ptb_v6() {
	ip netns exec "${ns2}" python3 -c '
import socket, struct, sys
src, dst, mtu = sys.argv[1], sys.argv[2], int(sys.argv[3])
inner = struct.pack("!IHBB", 6 << 28, 8, 58, 64)
inner += socket.inet_pton(socket.AF_INET6, src)
inner += socket.inet_pton(socket.AF_INET6, dst)
inner += struct.pack("!BBHHH", 128, 0, 0, 0, 0)
msg = struct.pack("!BBHI", 2, 0, 0, mtu) + inner
s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
s.sendto(msg, (src, 0))
' "${dip_v6}" "${rip_v6}" "${1}"
}

# The director keeps the route to a real server for as long as it passes
# ip6_dst_check(). In DR mode that is a FLOWI_FLAG_KNOWN_NH clone, which is not
# cached on the nexthop. A PMTU learned for the real server after the route was
# cached must still reach it: packets that exceed the PMTU must get a packet
# too big message back to the client.
test_dr_v6_pmtu() {
	ip netns exec "${ns0}" ip addr add "${cip_v6}/64" dev br0 nodad
	ip netns exec "${ns0}" ip route add "${vip_v6}/128" via "${gip_v6}" dev br0

	ip netns exec "${ns1}" ip addr add "${gip_v6}/64" dev veth10 nodad
	ip netns exec "${ns1}" ip addr add "${dip_v6}/64" dev veth12 nodad
	ip netns exec "${ns1}" ip addr add "${vip_v6}/128" dev lo nodad
	ip netns exec "${ns1}" ipvsadm -A -u "[${vip_v6}]:${port}" -s rr
	ip netns exec "${ns1}" ipvsadm -a -u "[${vip_v6}]:${port}" \
		-r "[${rip_v6}]:${port}" -g

	ip netns exec "${ns2}" ip addr add "${rip_v6}/64" dev veth21 nodad
	ip netns exec "${ns2}" ip addr add "${vip_v6}/128" dev lo nodad

	# Let the director cache its route to the real server
	udp_send_v6 100

	send_ptb_v6 1280
	sleep 0.2
	if ! ip netns exec "${ns1}" ip -6 route get "${rip_v6}" | grep -q "mtu 1280"; then
		echo "FAIL: director did not learn the PMTU of the real server"
		return 1
	fi

	# A datagram that exceeds the PMTU must be answered with a packet too
	# big message, which gives the client a PMTU for the service
	udp_send_v6 1400
	if ! ip netns exec "${ns0}" ip -6 route get "${vip_v6}" | grep -q "mtu 1280"; then
		echo "FAIL: director kept using a route that bypasses the learned PMTU"
		return 1
	fi
}

run_tests() {
	local errors=

	echo "Testing DR mode..."
	cleanup
	setup
	test_dr
	errors=$(( $errors + $? ))

	echo "Testing NAT mode..."
	cleanup
	setup
	test_nat
	errors=$(( $errors + $? ))

	echo "Testing Tunnel mode..."
	cleanup
	setup
	test_tun
	errors=$(( $errors + $? ))

	echo "Testing IPv6 DR mode PMTU..."
	cleanup
	setup
	test_dr_v6_pmtu
	errors=$(( $errors + $? ))

	return $errors
}

trap cleanup EXIT

run_tests

if [ $? -ne 0 ]; then
	echo -e "$(basename $0): ${RED}FAIL${NC}"
	exit 1
fi
echo -e "$(basename $0): ${GREEN}PASS${NC}"
exit 0
