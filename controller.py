 
#simple switch controller based on code from the ADVANCED NETWORKED SYSTEMS cource, lab 6,University of Glasgow
#GUID: 2464927p
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
import logging as log

from ryu.ofproto.ether import ETH_TYPE_CFM
from ryu.ofproto.ether import ETH_TYPE_LLDP

# Graph manipulation library
import networkx as nx

# Fetch topology information
from ryu.topology import event
from ryu.topology.api import get_switch, get_link, get_host

import random


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.G = nx.Graph()
        self.shortest_paths = dict()

        # necessary to enable the topology monitoring functionality
        self.topology_api_app = self

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.update_topology_data()

    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def switch_change(self, ev):
        datapath = ev.datapath
        if ev.state == DEAD_DISPATCHER:
            self.update_topology_data()

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype in (ETH_TYPE_LLDP, ETH_TYPE_CFM):
            # ignore lldp packet
            return

        self.update_topology_data()


    def update_topology_data(self):
        # Get lists for switches, links, and hosts
        switch_list = get_switch(self.topology_api_app, None)
        links_list = get_link(self.topology_api_app, None)
        hosts_list = get_host(self.topology_api_app, None)

        # Temporary lists for switches and hosts
        s_list = []
        h_list = []
        l_list = []

        # variable to store whether topology has been changed compared to the graph
        topology_changed = False

        for switch in switch_list:
            switch_name="s{}".format(switch.dp.id)
            s_list.append(switch_name)

            # add switches to graph with preset attribute names
            # define a recent_port data dictionary as an attribute for the
            # swithes - it will be updated in each case
            # a new port comes up
            if switch_name not in self.G.nodes():
                self.G.add_node(
                    switch_name,
                    name=switch_name,
                    dp=switch.dp,
                    port=switch.ports
                    )
                topology_changed = True

        for link in links_list:
            source = "s{}".format(link.src.dpid)
            source_port = link.src.port_no
            target = "s{}".format(link.dst.dpid)
            target_port = link.dst.port_no
            l_list.append(link)
            # networkx links in Graph() are not differentiated by source and destination, so a link and its data become
            # updated when add_edge is called with the source and destination swapped
            self.G.add_edge(source, target,
                                  src_dpid=source, src_port=link.src.port_no,
                                  dst_dpid=target, dst_port=link.dst.port_no)
            topology_changed = True



        if hosts_list:
            for host in hosts_list:
                # assemble name according to mac
                host_name="h{}".format(host.mac.split(":")[5][1])
                h_list.append(host_name)
                host_ipv4 = "10.0.0.{}".format(host_name[1])

                if host_name not in self.G.nodes():
                    log.info("Host found - added as {}".format(host_name))
                    self.G.add_node(
                                    host_name,
                                    name=host_name,
                                    ipv4=host_ipv4,
                                    ipv6=host.ipv6,
                                    mac=host.mac,
                                    connected_to="s{}".format(host.port.dpid),
                                    port_no=host.port.port_no)
                    # add corresponding links to the graph
                    self.G.add_edge(host_name,
                                    "s{}".format(host.port.dpid),
                                    dst_port=host.port.port_no,
                                    dst_dpid="s{}".format(host.port.dpid))
                    topology_changed = True


        # OK, each new element is added to the network,
        # but we also need to remove the elements that are not present anymore
        a = s_list + h_list

        # since it is converted to a set, this will produce a list() of the differences
        diff = list(set(self.G.nodes()) - set(a))
        if len(diff) > 0:
            # remove the additional nodes from the graph
            for i in diff:
                self.G.remove_node(i)
                log.info("The following node has been removed from the graph:")
                print(i)
                topology_changed = True

        if topology_changed:
            # update shortest paths
            self.calculate_all_pair_shortest_paths()
            print("Shortest Paths:\n{}".format(self.shortest_paths))
            self.install_shortest_paths_flow_rules()


    def calculate_shortest_paths(self,src,dst):
        '''
        This function returns all shortest paths between the given source and destination node
        :param src: String - the source node's name
        :param dst: String - the destination node's name
        :return: list of lists
        '''
        if src not in self.G.nodes() or dst not in self.G.nodes():
            return None
        paths = list()
        try:
            all_sp = nx.all_shortest_paths(self.G, src, dst)
            for path in all_sp:
                paths.append(path)

        except nx.NetworkXNoPath:  # no path between src and dst
            log.info("No path between {} and {}".format(src, dst))
            log.info(self.G.edges())
            return None

        return paths


    def calculate_all_pair_shortest_paths(self):
        '''
        This function calculates all shortest paths for all source and destinations
        Note: NetworkX also have similar function (all_pairs_shortest_path(G[, cutoff])),
        however that only gives one shortest path for a given (source,destination) pair
        :return: dictionary of dictionary of list of lists, e.g., h1:{h2:[[h1,s1,h2],[h1,s2,h2]]}
        '''
        all_paths = dict()
        for n in self.G.nodes():
            if n.startswith('h'): #only hosts are relevant
                all_paths[n] = dict()
                for m in self.G.nodes():
                    if m.startswith('h'):
                        if n == m:
                            continue
                        all_paths[n][m] = self.calculate_shortest_paths(n, m)

        self.shortest_paths = all_paths


    def install_flow_rule_for_chain_link(self, chain_link, chain_prev, chain_next, source_ip, destination_ip):
        '''
        This function installs matching flow rules on source_ip and destination_ip in switch
        chain_link and outputs packets on ports that are connected to its upstream (chain_prev)
        and downstream (chain_next) nodes, respectively.
        According to the chain_prev and chain_next, it gets the link/port number information
        from the graph that stores them
        :param chain_link: String - the name of the chain_link
        :param chain_prev: String - the name of the previous switch
        :param chain_next: String - the name of the next switch
        :param source_ip: tuple(String,String) - source host IP address and netmask for the upstream
        :param destination_ip: tuple(String,String) - the destination IP address and netmask for the downstream
        :return:
        '''

        datapath = self.G.nodes[chain_link]['dp']
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        match_source_ip = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_dst=source_ip)
        match_destination_ip = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_dst=destination_ip)

        # --- upstream
        # get edge_data
        edge = self.G[chain_link][chain_prev]
        print ("upstream edge: ", edge)
        if edge['dst_dpid'] == chain_link:
            # if prev is a host, then it is always the case that edge['dst_port'] stores the port number
            out_port = edge['dst_port']
        else:
            # if prev is a switch, then it might be the src_dpid
            out_port = edge['src_port']
        actions = [ofp_parser.OFPActionOutput(out_port, 0)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        print("install flow rule for SIP {} - DIP {} at {} to forward packet on port {}".
                 format(source_ip, destination_ip, chain_link, out_port))
        self.send_flow_mod(datapath, None, match=match_source_ip, inst=inst)

        # --- downstream
        # get edge_data
        edge = self.G[chain_link][chain_next]
        print("downstream edge: ", edge)
        if edge['dst_dpid'] == chain_link:
            # if next is a host, then it is always the case that edge['dst_port'] stores the port number
            out_port = edge['dst_port']
        else:
            # if next is a switch, then it might be the src_dpid
            out_port = edge['src_port']
        actions = [ofp_parser.OFPActionOutput(out_port, 0)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        log.info("install flow rule for SIP {} - DIP {} at {} to forward packet on port {}".
                 format(source_ip, destination_ip, chain_link, out_port))
        self.send_flow_mod(datapath, None, match=match_destination_ip, inst=inst)



    def install_shortest_paths_flow_rules(self):
        '''
        This function will install flow rules according to the shortest paths
        :return:
        '''
        paths = self.shortest_paths
        # paths looks like {h1:{h2:[[path1],[path2]]}} <- EXAMPLE
        if paths:
            for source in paths:  # source = h1
                source_host = self.G.nodes[source]
                print("Source host: {}".format(source_host))
                source_ip = (source_host['ipv4'], '255.255.255.255')
                print("Source ip: {}".format(source_ip))

                # self.log.info(paths[source])  # paths[source] = {h2: [[path1],[path2]]
                for p in paths[source]:  # p = h2
                    destination_host = self.G.nodes[p]
                    destination_ip = (destination_host['ipv4'], '255.255.255.255')
                    if paths[source][p]:
                        for path_num, j in enumerate(
                                paths[source][p]):  # paths[source][p] = [[path1],[path2]], j = one path from paths
                            # choose a random path
                            random_path = paths[source][p][random.randint(0,len(paths[source][p]))-1]
                            individual_path = random_path
                            if individual_path:
                                for num, sw in enumerate(individual_path):
                                    # print sw
                                    if sw.startswith('h'):
                                        # it's a host, skip (this will also prevent running out of indexes in both direction (see below))
                                        continue

                                    prev = individual_path[num - 1]
                                    current = individual_path[num]
                                    next = individual_path[num + 1]
                                    self.install_flow_rule_for_chain_link(current, prev, next, source_ip, destination_ip)



    def send_flow_mod(self, datapath, msg, **args):
        '''
        Sending a flow_mod to the given switch
        :param datapath: Datapath - datapath of the switch
        :param msg: PacketIn message
        :param args: cookie=0, table=0, cookie_mask=0,idle_timeout=0,hard_timeout=0,priority=100,buffer_id=OFP_NO_BUFFER,
                    mod_type= OFPFC_ADD, match=OFPMatch(in_port=1,broadcast_eth_dst),
                    inst=OFPInstructionActions(apply action,OFPActionOutput(2)),
        :return: nothing
        '''
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        table_id = args.get('table',0)
        cookie = args.get('cookie', 0)
        cookie_mask = args.get('cookie_mask',0)
        idle_timeout = args.get('idle_timeout', 0)
        hard_timeout = args.get('hard_timeout', 0)
        priority = args.get('priority', 100)
        if msg:
            buffer_id = args.get('buffer_id', msg.buffer_id)
        else:
            buffer_id=ofp.OFP_NO_BUFFER

        mod_type = args.get('mod_type', ofp.OFPFC_ADD)


        match = args.get('match',ofp_parser.OFPMatch(in_port=1, eth_dst='ff:ff:ff:ff:ff:ff'))
        inst = args.get('inst',
                        [ofp_parser.OFPInstructionActions(
                                ofp.OFPIT_APPLY_ACTIONS,
                                [ofp_parser.OFPActionOutput(2)])])



        flowmod = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                    table_id, mod_type,
                                    idle_timeout, hard_timeout,
                                    priority, buffer_id,
                                    ofp.OFPP_ANY, ofp.OFPG_ANY,
                                    ofp.OFPFF_SEND_FLOW_REM,
                                    match, inst)

        datapath.send_msg(flowmod)
