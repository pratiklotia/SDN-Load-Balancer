# SDN-Load-Balancer
Software Defined Network based Stateless Load Balancer based on Open Flow protocol

Load Balancer:
Server load-balancers (SLBs) are complex and expensive devices that perform load-balancing across servers based on several factors such as server capability, incoming requests, or round-robin fashion.

Software Defined Network (SDN):

SDN is a networking concept that aims to centralize networks and make network flows programmable, and NFV focusses on virtualized network functions. SDNFV can be used to manage networks better and reduce CapEx/ OpEx. SDN-based load-balancers use SDNFV functions and applications to create flexible, programmable, and virtual load-balancing that can be deployed, managed and manipulated with ease in the industry.

This is a stateless round robin load balancer designed to be executed on Control Plane of SDN. It uses Open Flow protocol. This is fully tested on Mininet VM.
The Controller supported is Ryu controller (https://osrg.github.io/ryu/) which is a Python based SDN controller.

OpenFlow:
OpenFlow® is the first standard communications interface defined between the control and forwarding layers of an SDN architecture. OpenFlow® allows direct access to and manipulation of the forwarding plane of network devices such as switches and routers, both physical and virtual (hypervisor-based).
OpenFlow-based SDN technologies enable IT to address the high-bandwidth, dynamic nature of today's applications, adapt the network to ever-changing business needs, and significantly reduce operations and management complexity.
For historical information about the origins of OpenFlow® at Stanford University prior to the creation of ONF, please see archive.openflow.org.

Ryu:
Ryu is a component-based software defined networking framework. Ryu provides software components with well defined API that make it easy for developers to create new network management and control applications. Ryu supports various protocols for managing network devices, such as OpenFlow, Netconf, OF-config, etc. About OpenFlow, Ryu supports fully 1.0, 1.2, 1.3, 1.4, 1.5 and Nicira Extensions. All of the code is freely available under the Apache 2.0 license.

Mininet:
Mininet creates a realistic virtual network, running real kernel, switch and application code, on a single machine (VM, cloud or native), in seconds, with a single command. Because you can easily interact with your network using the Mininet CLI (and API), customize it, share it with others, or deploy it on real hardware, Mininet is useful for development, teaching, and research.
Mininet is also a great way to develop, share, and experiment with OpenFlow and Software-Defined Networking systems.
Mininet is actively developed and supported, and is released under a permissive BSD Open Source license.

Topology:
3 Servers, 1 Data Plan Switch, 1+ Hosts
Service IP address of the load-balancer as 10.0.0.100 and the IP addresses of the servers as 10.0.0.1 (s1), 10.0.0.2 (s2), and 10.0.0.3 (s3). Client IPs are your choice.

Testing using Mininet:
On Mininet VM:
sudo mn --controller=remote,ip=192.168.56.111 --mac --switch ovs,protocols=OpenFlow13 --topo single,7 --ipbase=10.0.0.1/24 –x

Run HTTP Server on host with the command inside mininet shell ‘h1 python –m SimpleHTTPServer 80 &’
Client Test: ‘h2 wget h1’

The code can be slightly modified to make it 'Stateful' Load Balancer using Host's unique parameters (Host IP, Host MAC, etc).

I encourage you to contribute code, bug reports/fixes, documentation, and anything else that can improve the system!
For any queries, please email me at pratiklotia@yahoo.in
