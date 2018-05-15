import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.addresses import EthAddr
from pox.lib.addresses import IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.util import dpid_to_str, str_to_bool
import random

log = core.getLogger()
ip_vlan_dict = {}
ip_vlan_reverse_dict = {}

vlan = 0
switch3f = 0000000000000003
flow3fmsg = of.ofp_flow_mod()
nat_trans = {}
nat_reverse_trans = {}

blocked_ips = set()
blocked_ips.add('192.168.1.10')


def flow_3f(inport, input_ip, trans_port, original_port, vlan=0, out_port=2):
    # flow1:

    flow3fmsg.cookie = 0

    flow3fmsg.match.in_port = inport

    flow3fmsg.match.dl_type = 0x0800

    flow3fmsg.match.nw_src = IPAddr(input_ip)
    flow3fmsg.match.nw_proto = 6
    flow3fmsg.match.tp_src = original_port

    # ACTIONS---------------------------------

    flow3ftrans = of.ofp_action_tp_port.set_src(trans_port)
    flow3fout = of.ofp_action_output(port=out_port)

    flow3fsrcIP = of.ofp_action_nw_addr.set_src(IPAddr("10.0.0.2"))

    flow3fsrcMAC = of.ofp_action_dl_addr.set_src(EthAddr("00:00:00:00:00:05"))

    flow3fdstMAC = of.ofp_action_dl_addr.set_dst(EthAddr("00:00:00:00:00:06"))
    flow3fvlanid = of.ofp_action_vlan_vid(vlan_vid=vlan)

    flow3fmsg.actions = [flow3ftrans, flow3fsrcIP, flow3fsrcMAC, flow3fdstMAC, flow3fvlanid, flow3fout]
    return flow3fmsg


# flow3b:
def flow_3b(trans_port, out_port, out_ip, out_mac, original_port):
    switch3b = 0000000000000003

    flow3bmsg = of.ofp_flow_mod()

    flow3bmsg.cookie = 0

    flow3bmsg.match.in_port = 2

    flow3bmsg.match.dl_type = 0x0800

    flow3bmsg.match.nw_dst = IPAddr("10.0.0.2")
    flow3bmsg.match.nw_proto = 6
    flow3bmsg.match.tp_dst = trans_port
    # ACTIONS---------------------------------

    flow3bout = of.ofp_action_output(port=out_port)

    flow3bdstIP = of.ofp_action_nw_addr.set_dst(IPAddr(out_ip))

    flow3bsrcMAC = of.ofp_action_dl_addr.set_src(EthAddr("00:00:00:00:00:04"))

    flow3bdstMAC = of.ofp_action_dl_addr.set_dst(EthAddr(out_mac))
    flow3btrans = of.ofp_action_tp_port.set_dst(original_port)

    flow3bmsg.actions = [flow3bdstIP, flow3bsrcMAC, flow3bdstMAC, flow3btrans, flow3bout]
    return flow3bmsg


# flow1:
def flow_4f(vlanid):

    ip = ip_vlan_reverse_dict[vlanid]
    #print "flow4f ip - {0}".format(ip)
    flow4fmsg = of.ofp_flow_mod()
    flow4fmsg.cookie = 0
    flow4fmsg.match.in_port = 1
    #flow4fmsg.match.dl_type = 0x8100
    flow4fmsg.match.dl_vlan = vlanid
    flow4fmsg.hard_timeout = 60
    print blocked_ips

    # Clear blocked_ips
    # READ FROM FILE AND UPDATE blocked_ips
    with open("/home/mininet/pox/pox/misc/blocked_ips.txt","r") as f:
        b_l = []
        for i in f:
            b_l.append(i.strip())
    global blocked_ips
    blocked_ips = b_l
    if str(ip) not in blocked_ips:
    #if True:
        #flow4fmsg.match.nw_src = IPAddr("10.0.0.2")

        # ACTIONS---------------------------------
        flow4fout = of.ofp_action_output(port=2)
        # flow4fsrcIP = of.ofp_action_nw_addr.set_src(IPAddr("10.0.0.2"))
        flow4fsrcMAC = of.ofp_action_dl_addr.set_src(EthAddr("00:00:00:00:00:03"))
        flow4fdstMAC = of.ofp_action_dl_addr.set_dst(EthAddr("00:00:00:00:00:01"))
        flow4fvlanid = of.ofp_action_vlan_vid(vlan_vid=0)

        flow4fmsg.actions = [flow4fsrcMAC, flow4fdstMAC, flow4fvlanid, flow4fout]
    else:
        print "IP is blocked"
    return flow4fmsg

# flow1:
def flow_4b():
    switch4b = 0000000000000004

    flow4bmsg = of.ofp_flow_mod()

    flow4bmsg.cookie = 0

    flow4bmsg.match.in_port = 2

    flow4bmsg.match.dl_type = 0x0800

    # flow4bmsg.match.nw_src = IPAddr("10.0.0.2")

    # ACTIONS---------------------------------

    flow4bout = of.ofp_action_output(port=1)

    # flow4bsrcIP = of.ofp_action_nw_addr.set_src(IPAddr("10.0.0.2"))

    flow4bsrcMAC = of.ofp_action_dl_addr.set_src(EthAddr("00:00:00:00:00:06"))

    flow4bdstMAC = of.ofp_action_dl_addr.set_dst(EthAddr("00:00:00:00:00:05"))
    #flow4bvlanid = of.ofp_action_vlan_vid()

    flow4bmsg.actions = [flow4bsrcMAC, flow4bdstMAC, flow4bout]

    return flow4bmsg

def install_flows(event, vlan, input_ip, trans_port, original_port):
    log.info("    *** Installing static flows... ***")

    # Push flows to switches

    if event.dpid == 3:
        global switch
        flow3fmsg = flow_3f(inport=event.port, input_ip=input_ip, original_port = original_port, trans_port=trans_port, vlan=vlan, out_port=2)
        flow3bmsg = flow_3b(trans_port = trans_port, out_port = event.port, out_ip = input_ip, out_mac = event.parsed.src, original_port = original_port)
        core.openflow.sendToDPID(3, flow3fmsg)
        core.openflow.sendToDPID(3, flow3bmsg)

    elif event.dpid == 4:
        flow4fmsg = flow_4f(vlan)
        flow4bmsg = flow_4b()
        core.openflow.sendToDPID(4, flow4fmsg)
        core.openflow.sendToDPID(4, flow4bmsg)

    else:
        log.info(" INVALID CASE OF installing flows")
    log.info("    *** Static flows installed. ***")


def _handle_ConnectionUp(event):
    log.info("*** install flows *** {0}".format(str(event.dpid)))
    """
    if event.dpid == 4:
        flow4fmsg = flow_4f(1)
        flow4bmsg = flow_4b()
        core.openflow.sendToDPID(4, flow4fmsg)
        core.openflow.sendToDPID(4, flow4bmsg)
    """
    return

def get_free_vlan():
    global vlan
    vlan = vlan + 1
    return vlan


def get_free_port(ip, port):
    for _ in xrange(10):
        a = random.randint(49152, 65534)
        if a not in nat_reverse_trans:
            nat_trans[str(ip) + "_" + str(port)] = a
            nat_reverse_trans[a] = str(ip) + "_" + str(port)
            return a


def _handle_PacketIn(event):
    log.info("*** _handle_PacketIn... ***{0}, {1}".format(str(event.dpid), event.port))

    dpid = event.connection.dpid

    inport = event.port

    packet = event.parse()
    if not packet.parsed:
        log.warning("%i %i ignoring unparsed packet", dpid, inport)

        return

    a = packet.find('arp')

    if not a:
        if True:
            tcpp = packet.find('tcp')
            if not tcpp:
                tcpp = packet.find('udp')
                if not tcpp:
                    print "Not a good packet"
                    return
            print "finally a tcp packet"

            if dpid == 3:
                port = tcpp.srcport
                ip = tcpp.prev.srcip
                print ip
                trans_port = 0
                identifier = str(port) + "_" + str(ip)
                if identifier not in nat_trans:
                    trans_port = get_free_port(ip, port)
                else:
                    trans_port = nat_trans[identifier]

                if ip not in ip_vlan_dict:
                    ip_vlan_dict[ip] = get_free_vlan()
                    ip_vlan_reverse_dict[ip_vlan_dict[ip]] = ip
                vlan = ip_vlan_dict.get(ip, 0)
                print "About to install a flow ({0}, {1}) -> {2} came on port {3}".format(str(ip), str(port), str(trans_port), str(inport))
                install_flows(event=event, vlan=vlan, input_ip=ip, trans_port=trans_port, original_port=port)
            else:
                vlan = packet.find('vlan')
                if vlan:
                    vlan_id = vlan.id
                else:
                    vlan_id = 0

                print "***************TYPE {0}".format(str(packet.type))
                print "VLAN_IDDD {0}".format(str(vlan_id))
                install_flows(event=event, vlan=vlan_id, input_ip=None, trans_port=None, original_port=None)
                return
            return
        else:
            print "Not an ipv4 packet"
    else:
        log.info("%s ARP %s %s => %s", dpid_to_str(dpid),

                 {arp.REQUEST: "request", arp.REPLY: "reply"}.get(a.opcode,

                                                                  'op:%i' % (a.opcode,)), str(a.protosrc),
                 str(a.protodst))

        if a.prototype == arp.PROTO_TYPE_IP:

            if a.hwtype == arp.HW_TYPE_ETHERNET:

                if a.opcode == arp.REQUEST:

                    if str(a.protodst) == "192.168.1.1":
                        r = arp()

                        r.hwtype = a.hwtype

                        r.prototype = a.prototype

                        r.hwlen = a.hwlen

                        r.protolen = a.protolen

                        r.opcode = arp.REPLY

                        r.hwdst = a.hwsrc

                        r.protodst = a.protosrc
                        r.protosrc = a.protodst

                        r.hwsrc = EthAddr("00:00:00:00:00:03")

                        e = ethernet(type=packet.type, src=r.hwsrc,

                                     dst=a.hwsrc)

                        e.payload = r

                        log.info("%s answering ARP for %s" % (dpid_to_str(dpid),

                                                              str(r.protosrc)))

                        msg = of.ofp_packet_out()

                        msg.data = e.pack()

                        msg.actions.append(of.ofp_action_output(port=

                                                                of.OFPP_IN_PORT))

                        msg.in_port = inport

                        event.connection.send(msg)

                    if str(a.protodst) == "10.0.0.2":
                        r = arp()

                        r.hwtype = a.hwtype

                        r.prototype = a.prototype

                        r.hwlen = a.hwlen

                        r.protolen = a.protolen

                        r.opcode = arp.REPLY

                        r.hwdst = a.hwsrc

                        r.protodst = a.protosrc

                        r.protosrc = a.protodst

                        r.hwsrc = EthAddr("00:00:00:00:00:04")

                        e = ethernet(type=packet.type, src=r.hwsrc,

                                     dst=a.hwsrc)

                        e.payload = r

                        log.info("%s answering ARP for %s" % (dpid_to_str(dpid),

                                                              str(r.protosrc)))

                        msg = of.ofp_packet_out()

                        msg.data = e.pack()

                        msg.actions.append(of.ofp_action_output(port=

                                                                of.OFPP_IN_PORT))

                        msg.in_port = inport

                        event.connection.send(msg)


def launch():
    log.info("*** Starting... ***")

    log.info("*** Waiting for switches to connect.. ***")

    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)

    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
