.. _tunneling_with_openstack:

*******************************
Using tunneling  with OpenStack
*******************************
This section describes how to setup openstack (nova, quantum) and ryu-manage
with tunneling enabled.

Overview
========

* install necessary components

  Todo: when the modifications are upstreamed, drop them.

   * patched ryu
   * openstack

     * patched quantum
         Todo: Once the patch is merged, remove this entry.
     * patched devstack
         If you use devstack, it needs patch.
         Todo: Once the patch is merged, remove this entry.

     * other openstack component(nova, ...) can be used from the upstream as is
* setup configuration appropriately
* run those component
* start guest instance as you like.
* enjoy

If you have not tried openstack, it is strongly recommended to try normal
openstack setup with quantum OVS plugin at first.


Avaiable repository
-------------------
Unfortunately several components needs patches at the moemnt.
For convenience, they are avaiable at github as follows.
Todo: when the modifications are upstreamed, drop them.

Note: you may want to check if  configuration files of them.

* git://github.com/yamahata/ryu.git ryu-gre-tunnel-nov-21-2012
* git://github.com/yamahata/quantum.git ryu-gre-tunnel-nov-21-2012
* git://github.com/yamahata/devstack.git ryu-gre-tunnel-nov-21-2012

Other component of openstack can be used from the upstream.
Probably openstack Folsom stable tree would be safe choice.

Devstack way
============
It is recommended to use devstack.
Note: the patched openvswitch needs to be installed in advance in all nodes.

#. download the patched devstack from the above git repo
#. edit localrc depending on your environment

   Please see the next section for detailed parameters.

   .. simple code::

      # git clone git://github.com/yamahata/devstack.git ryu-gre-tunnel-sep-26-2012
      # cd devstack
      # vi localrc
      edit localrc appropriately.
      My localrc is included in the repository for your information.

#. run devstack::

   # ./stack.sh

#. wait stack.sh to finish and use openstack as usual

devstack localrc
----------------
See stack.sh for details and other optional variables.

* services
   * all-in-one node case
      * ENABLED_SERVICES="g-api,g-reg,key,nova,n-api,n-crt,n-obj,n-cpu,-n-net,n-sch,n-novnc,n-xvnc,n-cauth,horizon,mysql,rabbit,quantum,q-agt,q-l3,q-dhcp,q-svc,ryu,r-svc,cinder,c-api,c-vol,c-sch"
   * compute only node case
      * ENABLED_SERVICES="n-cpu,quantum,q-agt"

* nova virt driver stuff
   * LIBVIRT_TYPE=kvm

* quantum stuff
   * Q_PLUGIN=ryu

     We'd like to use ryu plugin
   * Q_HOST

     ip address on which qemutum server is running
   * Q_ADMIN_USERNAME

     quantum admin user name
   * Q_AUTH_STRATEGY

     quantum authentication strategy
   * QUANTUM_REPO=git://github.com/yamahata/quantum.git
   * QUANTUM_BRANCH=ryu-gre-tunnel-nov-21-2012

* ryu stuff
   * RYU_APPS=ryu.app.gre_tunnel,ryu.app.quantum_adapter,ryu.app.rest_quantum,ryu.app.rest,ryu.app.rest_conf_switch,ryu.app.rest_tunnel,ryu.app.tunnel_port_updater
   * RYU_REPO=git://github.com/yamahata/ryu.git
   * RYU_BRANCH=ryu-gre-tunnel-nov-21-2012

* optional available setting
   * quamtum ryu plugin
      IP address on which ryu-manager is running.

      * RYU_API_HOST
      * RYU_OFP_HOST


localrc example for all in one node
-----------------------------------
This is an example for all in one node.::

   ENABLED_SERVICES="g-api,g-reg,key,nova,n-api,n-crt,n-obj,n-cpu,-n-net,n-sch,n-novnc,n-xvnc,n-cauth,horizon,mysql,rabbit,quantum,q-svc,q-agt,q-l3,q-dhcp,ryu,r-svc,cinder,c-api,c-vol,c-sch"

   # password
   MYSQL_USER=mysql
   MYSQL_PASSWORD=mysql
   RABBIT_PASSWORD=rabbit
   SERVICE_TOKEN=service_token
   SERVICE_PASSWORD=service_password
   ADMIN_PASSWORD=admin

   # nova
   # when kvm fails, automatically falls back to qemu
   LIBVIRT_TYPE=kvm

   # quantum
   Q_PLUGIN=ryu
   QUANTUM_REPO=git://github.com/yamahata/quantum.git
   QUANTUM_BRANCH=ryu-gre-tunnel-sep-28-2012

   # ryu
   RYU_REPO=git://github.com/yamahata/ryu.git
   RYU_BRANCH=ryu-gre-tunnel-sep-28-2012
   RYU_APPS=ryu.app.gre_tunnel,ryu.app.quantum_adapter,ryu.app.rest,ryu.app.rest_conf_switch,ryu.app.rest_tunnel,ryu.app.tunnel_port_updater


localrc example for compute only node
-------------------------------------
This is an example for compute only node. You have to run all-in-one node
in advance.::

   ENABLED_SERVICES="n-cpu,quantum,q-agt,ryu"

   # Change SERVICE_HOST according to your environment
   # this is the IP address of all-in-one node
   SERVICE_HOST=172.17.60.198 # set this IP address on your environment

   # use same ip address for all services
   Q_HOST=$SERVICE_HOST
   RYU_API_HOST=$SERVICE_HOST
   RYU_OFP_HOST=$SERVICE_HOST
   MYSQL_HOST=$SERVICE_HOST
   RABBIT_HOST=$SERVICE_HOST
   GLANCE_HOSTPORT=$SERVICE_HOST:9292
   KEYSTONE_AUTH_HOST=$SERVICE_HOST
   KEYSTONE_SERVICE_HOST=$SERVICE_HOST

   # password
   MYSQL_USER=mysql
   MYSQL_PASSWORD=mysql
   RABBIT_PASSWORD=rabbit
   SERVICE_TOKEN=service_token
   SERVICE_PASSWORD=service_password
   ADMIN_PASSWORD=admin
   Q_PLUGIN=ryu

   # nova
   # when kvm fails, automatically falls back to qemu
   LIBVIRT_TYPE=kvm

   # quantum
   Q_PLUGIN=ryu
   QUANTUM_REPO=git://github.com/yamahata/quantum.git
   QUANTUM_BRANCH=ryu-gre-tunnel-sep-28-2012

   # ryu
   RYU_REPO=git://github.com/yamahata/ryu.git
   RYU_BRANCH=ryu-gre-tunnel-sep-28-2012
   RYU_APPS=ryu.app.gre_tunnel,ryu.app.quantum_adapter,ryu.app.rest,ryu.app.rest_conf_switch,ryu.app.rest_tunnel,ryu.app.tunnel_port_updater


common localrc example for both all-in-one node and compute only node
---------------------------------------------------------------------
As localrc is simple bash script, by using shell function same localrc can
be used for both all-in-one node and compute-only node.
This is just a example, you can customize for you requirement.::

   # Check if this host is all-in-one node or compute-only node
   # just use hostname because it's quite easy. it would be possible to use
   # IP address or whatever you like.
   SERVICE_HOST_NAME=host-name-of-all-in-one-node
   HOST_NAME=$(hostname)
   if [ "$HOST_NAME" = "$SERVICE_HOST_NAME" ]; then
      ENABLED_SERVICES="g-api,g-reg,key,nova,n-api,n-crt,n-obj,n-cpu,-n-net,n-sch,n-novnc,n-xvnc,n-cauth,horizon,mysql,rabbit,quantum,q-agt,q-l3,q-dhcp,q-svc,ryu,r-svc,cinder,c-api,c-vol,c-sch"
   else
      # for compute-only node
      ENABLED_SERVICES="n-cpu,quantum,q-agt"
   fi

   # Change SERVICE_HOST according to your environment
   # this is the IP address of all-in-one node
   SERVICE_HOST=172.17.60.198 # set this IP address on your environment

   # use same ip address for all services
   Q_HOST=$SERVICE_HOST
   RYU_API_HOST=$SERVICE_HOST
   RYU_OFP_HOST=$SERVICE_HOST
   MYSQL_HOST=$SERVICE_HOST
   RABBIT_HOST=$SERVICE_HOST
   GLANCE_HOSTPORT=$SERVICE_HOST:9292
   KEYSTONE_AUTH_HOST=$SERVICE_HOST
   KEYSTONE_SERVICE_HOST=$SERVICE_HOST

   # password
   MYSQL_USER=mysql
   MYSQL_PASSWORD=mysql
   RABBIT_PASSWORD=rabbit
   SERVICE_TOKEN=service_token
   SERVICE_PASSWORD=service_password
   ADMIN_PASSWORD=admin

   # nova
   # when kvm fails, automatically falls back to qemu
   LIBVIRT_TYPE=kvm

   # quantum
   Q_PLUGIN=ryu
   QUANTUM_REPO=git://github.com/yamahata/quantum.git
   QUANTUM_BRANCH=ryu-gre-tunnel-sep-28-2012

   # ryu
   RYU_REPO=git://github.com/yamahata/ryu.git
   RYU_BRANCH=ryu-gre-tunnel-sep-28-2012
   RYU_APPS=ryu.app.gre_tunnel,ryu.app.quantum_adapter,ryu.app.rest,ryu.app.rest_conf_switch,ryu.app.rest_tunnel,ryu.app.tunnel_port_updater


Manual way
==========
#. download the patched openvswitch from the above git repo and install it.
#. download the ryu repository from the above git repo
#. run ryu-manager with the following

   ::

      # git clone git://github.com/yamahata/ryu.git ryu-gre-tunnel-sep-28-2012
      # cd ryu
      # ./bin/ryu-manager --app_lists=ryu/app/gre_tunnel.py --app_lists=ryu/app/quantum_adapter.py --app_lists=ryu/app/rest_quantum.py --app_lists=ryu/app/rest.py --app_lists=ryu/app/rest_conf_switch.py --app_lists=ryu/app/rest_tunnel.py --app_lists=ryu/app/tunnel_port_updater.py --quantum_url=http://localhost:9696 --quantum_admin_auth_url=http://localhost:5000/v2.0/ --quantum_controller_addr=tcp:172.16.3.33:6633

   The point is to run the following ryu network applications.

   * gre_tunnel
   * quantum_adapter
   * tunnel_port_updater
   * rest
   * rest_conf_switch
   * rest_tunnel

   Here is the configurations for quantum adapter

   * --int_bridge

     the name of integration bridge of quantum which is same to
     the value of integration_bridge in quantum/plugin/ryu/ryu.ini
   * --quantum_url

     URL for connecting to quantum
   * --quantum_url_timeout

     timeout value for connecting to quantum in seconds
   * --quantum_admin_username

     username for connecting to quantum in admin context
   * --quantum_admin_password

     password for connecting to quantum in admin context
   * --quantum_admin_tenant_name

     tenant name for connecting to quantum in admin context
   * --quantum_admin_auth_url

     auth url for connecting to quantum in admin context
   * --quantum_auth_strategy

     auth strategy for connecting to quantum in admin context
     keystone or noauth
   * --quantum_controller_addr

     openflow mehod:address:port to set controller of
     This option must be specified as no default value is set.
#. necessary quantum settings

   * nova/nova.conf
      * libvirt_vif_driver = nova.virt.libvirt.vif.LibvirtHybridOVSBridgeDriver
   * quantum/plugin/ryu.ini
      * openflow_rest_api
   * quantum/quantum.conf
      * core_plugin = quantum.plugins.ryu.ryu_quantum_plugin.RyuQuantumPluginV2
      * interface_driver =  quantum.agent.linux.interface.OVSVethInterfaceDriver
#. install/run other openstack daemons as you want
   Please refer to openstack document for details.
#. don't forget to run quantum agent depending on your setup
    * quantum-ryu-agent
    * quantum-dhcp-agent
    * quantum-l3-agent
