#!/usr/bin/env python3
# Mininet topology for P4 IDS testing
# Requires: Mininet, BMv2 (simple_switch_grpc running externally)

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def p4Topology():
    "Create a simple P4 topo: h1 -- s1(P4) -- h2"
    net = Mininet(controller=RemoteController, link=TCLink)

    info('*** Adding controller\n')
    net.addController('c0', type='remote', ip='127.0.0.1', port=6653)  # Dummy; P4 uses gRPC

    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip='192.168.1.1/24')  # Attacker IP (add to bad_sources table)
    h2 = net.addHost('h2', ip='192.168.1.2/24')  # Victim (web server)

    info('*** Adding P4 switch (external BMv2)\n')
    # s1 connects to BMv2 veth0 (h1) and veth1 (h2)
    s1 = net.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')  # Fallback; replace with P4Switch wrapper if available

    info('*** Creating links\n')
    net.addLink(h1, s1, port1=1, port2=1)  # h1 to s1 port 1
    net.addLink(h2, s1, port1=1, port2=2)  # h2 to s1 port 2

    info('*** Starting network\n')
    net.start()

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    p4Topology()
