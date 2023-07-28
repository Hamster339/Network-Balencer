#!/usr/bin/python

#simple topolagy set-up, based on code from the ADVANCED NETWORKED SYSTEMS cource, lab 6,University of Glasgow
#GUID: 2464927p

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from functools import partial
from mininet.node import OVSSwitch
from mininet.node import RemoteController

class MyTopo( Topo ):
    def build(self):

        for i in range(1,9):
            self.addHost("h{}".format(i),
                             ip="10.0.0.{}".format(i),
                             mac="00:00:00:00:00:0{}".format(i),
                             cpu=.5/8
                             )

        for i in range(1,7):
            self.addSwitch("s{}".format((i)),
                           protocols="OpenFlow13")

        self.addLink( "h1", "s1", bw=10, delay="2ms", max_queue_size=8)
        self.addLink( "h2", "s1", bw=10, delay="2ms", max_queue_size=8)
        self.addLink( "h3", "s1", bw=10, delay="2ms", max_queue_size=8)
        self.addLink( "h4", "s1", bw=10, delay="2ms", max_queue_size=8)

        self.addLink( "s1", "s2", bw=10, delay="2ms", max_queue_size=8)
        self.addLink( "s1", "s3", bw=10, delay="2ms", max_queue_size=8)
        self.addLink( "s1", "s4", bw=10, delay="2ms", max_queue_size=8)
        self.addLink( "s1", "s5", bw=10, delay="2ms", max_queue_size=8)

        self.addLink( "s6", "s2", bw=10, delay="2ms", max_queue_size=8)
        self.addLink( "s6", "s3", bw=10, delay="2ms", max_queue_size=8)
        self.addLink( "s6", "s4", bw=10, delay="2ms", max_queue_size=8)
        self.addLink( "s6", "s5", bw=10, delay="2ms", max_queue_size=8)

        self.addLink( "h5", "s6", bw=10, delay="2ms", max_queue_size=8)
        self.addLink( "h6", "s6", bw=10, delay="2ms", max_queue_size=8)
        self.addLink( "h7", "s6", bw=10, delay="2ms", max_queue_size=8)
        self.addLink( "h8", "s6", bw=10, delay="2ms", max_queue_size=8)




def set_arp(net):
    print("Setting proper ARP entries manually")
    for h in net.hosts:
        for hh in net.hosts:
            if h!=hh: #we do not set ours
                h.cmd("arp -s {} {}".format(hh.params['ip'],hh.params['mac']))
        h.cmd("ping -c1 10.0.0.100 &") # generate packet-ins
    #preventing exiting
    CLI(net)


topos = { 'mytopo':MyTopo}
tests = {'set_arp': set_arp}

if __name__ == "__main__":
    topo = MyTopo
    net = Mininet(topo=topo(), host=CPULimitedHost, link=TCLink,
     controller=RemoteController)

    net.start()
    set_arp(net)

    CLI(net)
    net.stop()
