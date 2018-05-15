"""

Script created by VND - Visual Network Description (SDN version)

"""

from mininet.cli import CLI
from mininet.link import Link, TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch, IVSSwitch, UserSwitch


#TO DO
def int2dpid(dpid):
    try:
        dpid = hex(dpid)[2:]
        dpid = '0' * (16 - len(dpid)) + dpid
        return dpid
    except IndexError:
        raise Exception('Unable to derive default datapath ID - '
                        'please either specify a dpid or use a '
                        'canonical switch name such as s23.')
def topology():
    "Create a network."

    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSKernelSwitch)

    print "*** Creating nodes"

    h1 = net.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1/24')

    h2 = net.addHost('h2', mac='00:00:00:00:10:02', ip='192.168.1.10/24')
    h3 = net.addHost('h3', mac='00:00:00:00:11:02', ip='192.168.1.11/24')
    h4 = net.addHost('h4', mac='00:00:00:00:12:02', ip='192.168.1.12/24')


    s3 = net.addSwitch('s3',dpid = int2dpid(3))

    s4 = net.addSwitch('s4',dpid = int2dpid(4))

    c4 = net.addController('c4', ip='127.0.0.1', port=6633)

    print "*** Creating links"

    #net.addLink(h1, s4)
    #net.addLink(s3, h2)
    #net.addLink(s3, s4)


    net.addLink(s3, h2, intfName1="s3-eth1", intfName2="h2-eth0")
    net.addLink(s3, s4, intfName1="s3-eth2", intfName2="s4-eth1")
    net.addLink(s3, h3, intfName1="s3-eth3", intfName2="h3-eth0")
    net.addLink(s3, h4, intfName1="s3-eth4", intfName2="h4-eth0")
    net.addLink(h1, s4, intfName1="h1-eth0", intfName2="s4-eth2")

    s3.setMAC(mac='00:00:00:00:00:03', intf="s3-eth1")
    s3.setMAC(mac='00:00:00:00:00:05', intf="s3-eth2")
    s4.setMAC(mac='00:00:00:00:00:06', intf="s4-eth1")
    s4.setMAC(mac='00:00:00:00:00:04', intf="s4-eth2")

    print "*** Starting network"

    net.build()

    c4.start()

    s3.start([c4])
    s4.start([c4])
    print "*** Running CLI"

    h2.cmd("ip route add default via 192.168.1.1 dev h2-eth0")
    h2.cmd("arp -s -i h2-eth0 192.168.1.1 00:00:00:00:00:03")
    h3.cmd("ip route add default via 192.168.1.1 dev h3-eth0")
    h3.cmd("arp -s -i h3-eth0 192.168.1.1 00:00:00:00:00:03")
    h4.cmd("ip route add default via 192.168.1.1 dev h4-eth0")
    h4.cmd("arp -s -i h4-eth0 192.168.1.1 00:00:00:00:00:03")

    h1.cmd("ip route add default via 10.0.0.2 dev h1-eth0")
    h1.cmd("arp -s -i h1-eth0 10.0.0.2 00:00:00:00:00:04")

    h1.sendCmd("python -m SimpleHTTPServer 80 &")

    # for i in xrange(10):
    #     h4.cmd("wget -O - 10.0.0.1")
    #     h3.cmd("wget -O - 10.0.0.1")
    CLI(net)

    print "*** Stopping network"

    net.stop()


if __name__ == '__main__':
    setLogLevel('info')

    topology()
