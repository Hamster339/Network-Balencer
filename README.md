# Network-Balencer
Simple Network simulaion and load balencer using Ryu and OpenFlow

A network is setup and a simple load-balancing algorithm is implemented. But it does not use and open flow load-balancing features.

To run code, first run the controller with the command:
ryu-manager controller.py –observe-links

Then run the set-up script with the command:
sudo python setup.py

Then simple run standard network tests, (ping, iperf), in the mini-net client that will be loaded.

commands written for the linux operating system.

