#!/bin/bash
#
# PMTU handling with multipath routing.
#
#          .-- sw1 --.
#   h1 ----|-- sw2 --|---- h2 -------- h3
#          |   ...   |       reduced mtu
#          .-- swN --.
#
# h2-h3 segment has reduced mtu.
# Exceptions created in h1 for h3.

# number of paths - 8 exaggerates the problem
NUMPATHS=8

PAUSE_ON_FAIL=no

VRF=red
VRF_TABLE=1111
H1_IP=10.100.1.1
H1_IP6=2001:db8:100:1::64
H3_IP=10.100.2.254
H3_IP6=2001:db8:100:2::64
H3_MTU=1420

which ping6 > /dev/null 2>&1 && ping6=$(which ping6) || ping6=$(which ping)

################################################################################
#
log_test()
{
	local rc=$1
	local expected=$2
	local msg="$3"

	if [ ${rc} -eq ${expected} ]; then
		printf "TEST: %-60s  [ OK ]\n" "${msg}"
		nsuccess=$((nsuccess+1))
	else
		ret=1
		nfail=$((nfail+1))
		printf "TEST: %-60s  [FAIL]\n" "${msg}"
		if [ "${PAUSE_ON_FAIL}" = "yes" ]; then
			echo
			echo "hit enter to continue, 'q' to quit"
			read a
			[ "$a" = "q" ] && exit 1
		fi
	fi
read ans
}

log_debug()
{
	if [ "$VERBOSE" = "1" ]; then
		echo "$*"
	fi
}

run_cmd()
{
	local cmd="$*"
	local out
	local rc

	if [ "$VERBOSE" = "1" ]; then
		printf "    COMMAND: $cmd\n"
	fi

	out=$(eval $cmd 2>&1)
	rc=$?
	if [ "$VERBOSE" = "1" -a -n "$out" ]; then
		echo "    $out"
	fi

	[ "$VERBOSE" = "1" ] && echo

	return $rc
}

check_exception_v4()
{
	local mtu="$1"
	local ret=0
	local j

	if [ "$VERBOSE" = "1" ]; then
		echo "COMMAND: ip -netns h1 ro get ${VRF_ARG} ${H3_IP} oif eth{j}-h1"
	fi

	for j in $(seq 1 $NUMPATHS)
	do
		ip -netns h1 ro get ${VRF_ARG} ${H3_IP} oif eth${j}-h1 |\
		grep -q "cache expires [0-9]*sec mtu ${mtu}"
		if [ $? -ne 0 ]; then
			log_debug "ERROR: mtu exception not created for path ${j}"
			ret=1
		fi
	done

	return $ret
}

check_exception_v6()
{
	local mtu="$1"
	local ret=0
	local j

	if [ "$VERBOSE" = "1" ]; then
		echo "COMMAND: ip -netns h1 -6 ro get ${VRF_ARG} ${H3_IP6} oif eth{j}"
	fi

	for j in $(seq 1 $NUMPATHS)
	do
		ip -netns h1 -6 ro get ${VRF_ARG} ${H3_IP6} oif eth${j} |\
		grep -q "${mtu}"
		if [ $? -ne 0 ]; then
			log_debug "ERROR: mtu exception not created for path ${j}"
			ret=1
		fi
	done

	return $ret
}

do_test()
{
	local desc="$1"
	local ret

	# check connectivity
	run_cmd ip netns exec h1 ${PING_PFX} ping -c1 -w1 -I ${H1_IP} ${H3_IP}
	ret=$?
	if [ $ret -eq 0 ]; then
		run_cmd ip netns exec h1 ${PING_PFX} ping -s 1450 -c5 -w5 -Mdo -I ${H1_IP} ${H3_IP}
		check_exception_v4 ${H3_MTU}
		ret=$?
	else
		log_debug "Basic connectivity broken"
	fi
	log_test $ret 0 "IPv4 multipath ${desc}"

	run_cmd ip netns exec h1 ${PING_PFX} ${ping6} -c1 -w1 -I ${H1_IP6} ${H3_IP6}
	ret=$?
	if [ $ret -eq 0 ]; then
		run_cmd ip netns exec h1 ${PING_PFX} ${ping6} -s 1450 -c5 -w5 -Mdo -I ${H1_IP6} ${H3_IP6}
		check_exception_v6 ${H3_MTU}
		ret=$?
	else
		log_debug "Basic connectivity broken"
	fi
	log_test $ret 0 "IPv6 multipath ${desc}"
}

################################################################################
# create namespaces for hosts and sws

create_vrf()
{
	local ns=$1

	ip -netns ${ns} link add ${VRF} type vrf table ${VRF_TABLE}
	ip -netns ${ns} link set ${VRF} up
	ip -netns ${ns} route add vrf ${VRF} unreachable default metric 8192
	ip -netns ${ns} -6 route add vrf ${VRF} unreachable default metric 8192

	ip -netns ${ns} addr add 127.0.0.1/8 dev ${VRF}
	ip -netns ${ns} -6 addr add ::1 dev ${VRF} nodad

	ip -netns ${ns} ru del pref 0
	ip -netns ${ns} ru add pref 32765 from all lookup local
	ip -netns ${ns} -6 ru del pref 0
	ip -netns ${ns} -6 ru add pref 32765 from all lookup local
}

create_ns()
{
	local ns=$1

	ip netns add ${ns}

	ip -netns ${ns} link set lo up

	ip netns exec ${ns} sysctl -qw net.ipv4.ip_forward=1
	ip netns exec ${ns} sysctl -qw net.ipv6.conf.all.keep_addr_on_down=1
	ip netns exec ${ns} sysctl -qw net.ipv6.conf.all.forwarding=1
	ip netns exec ${ns} sysctl -qw net.ipv6.conf.default.forwarding=1
}

get_linklocal()
{
	local ns=$1
	local dev=$2
	local addr

	addr=$(ip -netns $ns -6 -br addr show dev ${dev} | \
	awk '{
		for (i = 3; i <= NF; ++i) {
			if ($i ~ /^fe80/)
				print $i
		}
	}'
	)
	addr=${addr/\/*}

	[ -z "$addr" ] && return 1

	echo $addr

	return 0
}

setup_hosts()
{
	local lo_dev="lo"

	[ "${WITH_VRF}" = "yes" ] && lo_dev=${VRF}
	ip -netns h1 addr add dev ${lo_dev} ${H1_IP}/32
	ip -netns h1 addr add dev ${lo_dev} ${H1_IP6}/128

	ip -netns h2 link add eth0-h2 type veth peer name eth0-h3
	ip -netns h2 link set eth0-h2 up
	ip netns exec h2 ethtool -K eth0-h2 tso off
	ip netns exec h2 ethtool -K eth0-h2 gso off
	ip netns exec h2 ethtool -K eth0-h2 gro off
	ip -netns h2 addr add dev eth0-h2 10.100.2.2/24
	ip -netns h2 -6 addr add dev eth0-h2 2001:db8:100:2::2/64 nodad

	ip -netns h2 link set eth0-h3 netns h3
	ip -netns h3 link set eth0-h3 up
	ip netns exec h3 ethtool -K eth0-h3 tso off
	ip netns exec h3 ethtool -K eth0-h3 gso off
	ip netns exec h3 ethtool -K eth0-h3 gro off
	ip -netns h3 addr add dev eth0-h3 10.100.2.254/24
	ip -netns h3 -6 addr add dev eth0-h3 2001:db8:100:2::64/64 nodad
}

setup_path()
{
	local i=$1
	local j=$2
	local us=h${i}
	local peer=sw${j}

	ip netns exec ${us} sysctl -w net.ipv4.ip_forward_use_pmtu=1
	ip netns exec ${us} sysctl -w net.ipv4.ip_forward_use_pmtu=1
	ip -netns ${us} link add eth${j}-${us} type veth peer name eth${i}-sw
	ip -netns ${us} link set eth${j}-${us} up
	ip netns exec ${us} ethtool -K eth${j}-${us} tso off
	ip netns exec ${us} ethtool -K eth${j}-${us} gso off
	ip netns exec ${us} ethtool -K eth${j}-${us} gro off
	ip -netns ${us} addr add dev eth${j}-${us} 10.${i}.${i}${j}.254/24
	ip -netns ${us} -6 addr add dev eth${j}-${us} 2001:db8:${i}:${i}${j}::64/64 nodad

	ip -netns ${us} link set eth${i}-sw netns ${peer}
	ip -netns ${peer} link set eth${i}-sw name eth${i}-${us} up
	ip netns exec ${peer} ethtool -K eth${i}-${us} tso off
	ip netns exec ${peer} ethtool -K eth${i}-${us} gso off
	ip netns exec ${peer} ethtool -K eth${i}-${us} gro off
	ip -netns ${peer} addr add dev eth${i}-${us} 10.${i}.${i}${j}.${j}/24
	ip -netns ${peer} -6 addr add dev eth${i}-${us} 2001:db8:${i}:${i}${j}::${j}/64 nodad
}

setup()
{
	local ns

	for ns in h1 h2 h3; do
		create_ns ${ns}
	done

	# use L4 for hash
	ip netns exec h1 sysctl -w net.ipv4.fib_multipath_hash_policy=1

	for j in $(seq 1 $NUMPATHS); do
		create_ns sw${j}
	done

	# host 1 setup by sws below
	if [ "${WITH_VRF}" = "yes" ]; then
		create_vrf h1
	fi
	setup_hosts

	# drop the MTU on segment between h2 and h3
	ip -netns h2 li set eth0-h2 mtu ${H3_MTU}
	ip -netns h3 li set eth0-h3 mtu ${H3_MTU}

	# i is the host number; j the sw
	for i in 1 2
	do
		for j in $(seq 1 $NUMPATHS)
		do
			setup_path ${i} ${j}
		done
	done

	sleep 2
}

cleanup()
{
	local j

	for j in 1 2 3; do
		ip netns del h${j} 2>/dev/null
	done
	for j in $(seq 1 $NUMPATHS)
	do
		ip netns del sw${j} 2>/dev/null
	done
}

################################################################################
# Configure routing

setup_routing_legacy()
{
	local j

	NS1_MPATH=""
	NS1_MPATH6=""
	NS2_MPATH=""
	NS2_MPATH6=""

	for j in $(seq 1 $NUMPATHS); do
		if [ "${WITH_VRF}" = "yes" ]; then
			ip -netns h1 li set dev eth${j} vrf ${VRF}
		fi
		ip -netns sw${j} ro add 10.100.1.0/24 via 10.1.1${j}.254
		ip -netns sw${j} -6 ro add 2001:db8:100:1::/64 via 2001:db8:1:1${j}::64
		ip -netns sw${j} ro add 10.100.2.0/24 via 10.2.2${j}.254
		ip -netns sw${j} -6 ro add 2001:db8:100:2::/64 via 2001:db8:2:2${j}::64

		# tell h2 which leg to use for return path
		ip -netns h2 ro add 10.1.1${j}.0/24 via 10.2.2${j}.${j}
		ip -netns h2 -6 ro add 2001:db8:1:1${j}::/64 via 2001:db8:2:2${j}::${j}

		NS1_MPATH="${NS1_MPATH} nexthop via 10.1.1${j}.${j}"
		NS1_MPATH6="${NS1_MPATH6} nexthop via 2001:db8:1:1${j}::${j}"

		NS2_MPATH="${NS2_MPATH} nexthop via 10.2.2${j}.${j}"
		NS2_MPATH6="${NS2_MPATH6} nexthop via 2001:db8:2:2${j}::${j}"
	done

	ip -netns h1 ro add ${VRF_ARG} default ${NS1_MPATH}
	ip -netns h1 -6 ro add ${VRF_ARG} default ${NS1_MPATH6}

	ip -netns h2 ro add default ${NS2_MPATH}
	ip -netns h2 -6 ro add default ${NS2_MPATH6}

	ip -netns h3 ro add default via 10.100.2.2
	ip -netns h3 -6 ro add default via 2001:db8:100:2::2
}

setup_routing_new()
{
	local j

	for j in $(seq 1 $NUMPATHS); do
		if [ "${WITH_VRF}" = "yes" ]; then
			ip -netns h1 li set dev eth${j} vrf ${VRF}
		fi

		ip -netns h1 -4 nexthop add id 41${j} via 10.1.1${j}.${j} dev eth${j}
		ip -netns h1 -6 nexthop add id 61${j} via 2001:db8:1:1${j}::${j} dev eth${j}

		ip -netns h2 -4 nexthop add id 42${j} via 10.2.2${j}.${j} dev eth${j}
		ip -netns h2 -6 nexthop add id 62${j} via 2001:db8:2:2${j}::${j} dev eth${j}

		if [ $j -eq 1 ]; then
			NS1_MPATH="411"
			NS1_MPATH6="611"
			NS2_MPATH="421"
			NS2_MPATH6="621"
		else
			NS1_MPATH="${NS1_MPATH}/41${j}"
			NS1_MPATH6="${NS1_MPATH6}/61${j}"
			NS2_MPATH="${NS2_MPATH}/42${j}"
			NS2_MPATH6="${NS2_MPATH6}/62${j}"
		fi
	done

	ip -netns h1 nexthop add id 499 group ${NS1_MPATH}
	ip -netns h1 nexthop add id 699 group ${NS1_MPATH6}
	ip -netns h1 ro add 10.100.2.0/24 ${VRF_ARG} nhid 499
	ip -netns h1 -6 ro add 2001:db8:100:2::/64 ${VRF_ARG} nhid 699

	ip -netns h2 nexthop add id 499 group ${NS2_MPATH}
	ip -netns h2 nexthop add id 699 group ${NS2_MPATH6}
	ip -netns h2 ro add default nhid 499
	ip -netns h2 -6 ro add default nhid 699

	ip -netns h3 ro add default via 10.100.2.2
	ip -netns h3 -6 ro add default via 2001:db8:100:2::2
}

################################################################################
# usage

usage()
{
        cat <<EOF
usage: ${0##*/} OPTS

        -n <num>    Number of nexthops (default: $NUMPATHS)
        -p          Pause on fail
	-v          verbose mode (show commands and output)
EOF
}

################################################################################
# main

while getopts :n:pv o
do
	case $o in
	n) NUMPATHS=$OPTARG;;
	p) PAUSE_ON_FAIL=yes;;
	v) VERBOSE=1;;
	*) usage; exit 1;;
	esac
done

WITH_VRF="no"
VRF_ARG=
PING_PFX=
cleanup
setup
setup_routing_legacy

do_test

WITH_VRF="yes"
VRF_ARG="vrf ${VRF}"
PING_PFX="ip vrf exec ${VRF}"
cleanup
setup
setup_routing_legacy
do_test "- VRF"

ip nexthop ls >/dev/null 2>&1
if [ $? -eq 0 ]; then
	WITH_VRF="no"
	VRF_ARG=
	PING_PFX=
	cleanup
	setup
	setup_routing_new
	do_test "- nexthop objects"

	WITH_VRF="yes"
	VRF_ARG="vrf ${VRF}"
	PING_PFX="ip vrf exec ${VRF}"
	cleanup
	setup
	setup_routing_new
	do_test "- nexthop objects and VRF"
fi

cleanup
