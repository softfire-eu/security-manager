  <img src="https://www.softfire.eu/wp-content/uploads/SoftFIRE_Logo_Fireball-300x300.png" width="120"/>

  Copyright © 2016-2018 [SoftFIRE](https://www.softfire.eu/) and [TU Berlin](http://www.av.tu-berlin.de/next_generation_networks/).
  Licensed under [Apache v2 License](http://www.apache.org/licenses/LICENSE-2.0).

# Security Manager
The Security Manager inside the SoftFIRE Middleware makes available to the Experimenters a
set of security related functionalities that they might decide to include and use within their
activities on the SoftFIRE platform.

Here is the list of the available features for every type of Resource.

1. The Experimenters can deploy a Security Resource
2. The Experimenters can statically configure the Security Resource by means of its descriptor
1. The Experimenter can statically configure some features on her Resource
3. The Experimenters can dynamically configure the Resource once it has been deployed

Features **not** available for Resource _pfsense_

1. The Experimenters can enable logs collection from their Resource
4. The Experimenters can see Resources logs in a web dashboard
5. The Experimenters can perform searches among the Resources logs in a web dashboard
6. The Experimenters can see statistics related to the Resources logs in a web dashboard  

### Security Resources
A Security Resource is a commonly used security agent that the Experimenters can include in their
experiment. They can access and configure it through a static initial configuration, included in the
TOSCA description of the Experiment, or, once deployed, through the interfaces that expose its
main services. These interfaces can include SSH, a dashboard, or ReST APIs.
Depending on the type of Resource, Experimenters can also ask the Security Resource to send its log messages to a remote log
collector, which makes them available in a simple web page reserved to them. The Experimenters
could easily access it through its web browser and check the behaviour of all their security agents,
and to see some related statistics.

The Experimenters can get the Security Resource in two different formats:

* As an agent directly installed in the VM that they want to monitor. The system will
provide them a script that the Experimenters have just to run inside the VM. It will be already
configured as required in the TOSCA description of the resource. The output of the script
will provide to the Experimenters information on how to access the deployed resource
(URLs, etc.)

* As a standalone VM. The Security Resource will be deployed directly by the Security
Manager in the testbed chosen by the Experimenter. The Security Manager will take
care of the initial configuration of the resource.
The Experimenters have to set up on their own the redirection of the network traffic that they want
to control through the Security Resource VM (by means of OS configuration, or SDN capabilities provided by the SoftFIRE platform).  

The Security Manager provides three types of resources:

* [firewall][firewall]
* [suricata][suricata]
* [pfsense][pfsense]


### Security Resource definition
In this section the attributes that can be defined for a TOSCA node of type _SecurityResource_ are listed. Please note that
the meaning of the specific property depends on the type of resource (specified in the *resource_id* field). 
For more details, refer to the specific sections of the documentation. 

```yaml
SecurityResource:
    derived_from: eu.softfire.BaseResource
    description: "Defines a Security agent to be deployed. More details on [docu_url]"
    properties:

        resource_id:
            type: string
            required: true

        testbed:
            type: string
            required: false

        lan_name:
            type: string
            required: false

        wan_name: 
            type: string
            required: false
            description: valid for pfsense

        ssh_key:
            type: string
            required: false
            description: valid for firewall and suricata

        want_agent:
            type: boolean
            required: false
            description: valid for firewall and suricata
       
        logging:
            type: boolean
            required: false
            description: valid for firewall and suricata
        
        allowed_ips:
            type: list
            entry_schema:
                type: string
            required: false
            description: valid for firewall
        
        denied_ips:
            type: list
            entry_schema:
                type: string
            required: false
            description: valid for firewall
        
        default_rule:
            type: string
            required: false
            description: valid for firewall
        
        rules: 
            type: list
            entry_schema:
                type: string 
            required: false
            description: valid for suricata
```

Every node has different properties. Here they are listed for each type of resource:

**resource_id = [firewall][firewall]**

* **testbed**: Defines where to deploy the Security Resource selected. It is ignored if want_agent is True
* **want_agent**: Defines if the Experimenter wants the security resource to be an agent directly installed on the VM that he wants to monitor
* **ssh_key**: Defines the SSH public key to be pushed on the VM in order to be able to log into it
* **lan_name**: Select the network on which the VM is deployed (if __want_agent__ is False). If no value is entered, __softfire-internal__ is chosen
* **logging**: Defines if the Experimenter wants the security resource to send its log messages to a collector and he wants to see them on a dashboard
* **allowed_ips**: List of IPs (or CIDR  masks) allowed by the firewall. [allow from *IP*]
* **denied_ips**: List of IPs (or CIDR masks) denied by the firewall [deny from *IP*]
* **default_rule**: Default rule applied by the firewall (allow/deny)

**resource_id = [suricata][suricata]**

* **testbed**: Defines where to deploy the Security Resource selected. It is ignored if want_agent is True
* **want_agent**: Defines if the Experimenter wants the security resource to be an agent directly installed on the VM that he wants to monitor
* **ssh_key**: Defines the SSH public key to be pushed on the VM in order to be able to log into it
* **lan_name**: Select the network on which the VM is deployed (if __want_agent__ is False). If no value is entered, __softfire-internal__ is chosen
* **logging**: Defines if the Experimenter wants the security resource to send its log messages to a collector and he wants to see them on a dashboard
* **rules**: Defines the list of rules to be configured in Suricata VM. These rules follow the syntax 

**resource_id = [pfsense][pfsense]**

* **testbed**: Defines where to deploy the Security Resource selected
* **wan_name**: Selects the network on which the first interface of the VM is attached. It is configured as WAN on pfSense. It must be a network connected to the SoftFIRE-public network 
* **lan_name**: Selects the network on which the second interface of the VM is attached. It is configured as LAN on pfSense


##### Testbed Names

| Alias    | Testbed                          |
|----------|----------------------------------|
| fokus    | FOKUS testbed, Berlin            |
| ericsson | ERICSSON testbed, Rome           |
| surrey   | SURREY testbed, Surrey           |
| ads      | ADS testbed, Rome                |

## Technical details
This sequence diagram specifies the operations performed by the Security Manager based on the inputs received by the Experimenter.
![Security Manager sequence diagram][sequence]

## Technical Requirements

The Security Manager requires Python 3.5 or higher.

## Installation and configuration
You can install the Security Manager using pip:

```bash
$ pip install security-manager
```
and then start it with the security-manager command.

Or you can run it from source code by cloning the git repository, installing the dependencies as specified in the setup.py file and executing the security-manager script.

The Security Manager needs a configuration file present at /etc/softfire/security-manager.ini. An example of the configuration file can be found [here](https://github.com/softfire-eu/security-manager/blob/master/etc/template/security-manager.ini).

In order to deploy security resources you have to create a pfsense image and to configure a ELK server for logging functionalities

## pfSense installation guide

PfSense is an open source firewall/router computer software distribution based on FreeBSD.
In order to successfully deploy a pfsense resource, the Security Manager has to find a pfsense image stored inside the Openstack
we want to use.

In the following tutorial will be explained how to create and configure such kind of image.
VirtualBox is choosed as hypervisor to create the pfSense virtual disk, but users can choose alternative products (i.e. qemu, vmware, ...).

So, let's start!

### Download pfSense

download the latest pfSense stable version from [the official website](https://www.pfsense.org/download/).
Latest version of the Security Manager is using  pfSense 2.4.2-release (amd64) but should also works with recent pfsense build.

Once downloaded, unzip the archive.


### Install OS via VirtualBox

First of all, make sure to create an host-only virtual network interface in order to get access to the guest virtual machine from the host machine.

Open VirtualBox and create a new virtual machine:
    1. Choose 'BSD' as type and 'FreeBSD (64-bit)' as version;
    2. give virtual machine 512 MB of RAM (in case more RAM it is chosed more RAM remember to choose a different Openstack image flavor according to this value);
    3. create a fixed size virtual hard disk using 'VirtualBox Disk Image' type. Minimum suggested size is 1 GB. if you create a bigger disk remember to use a bigger Openstack flavour;

Before boot the newly create virtual machine, go onto settings and configure network and storage interfaces:
    1. Select 'Storage' from left panel and add optical driver clicking on 'adds new storage attachment'. When asked provide the location of the pfSense image;
    2. Select 'Network' from left panel and add following intefaces:
        - '''adapter 1''': the type of 'attached to' doesn't matter. it is only important to have the pfSense WAN interfaces mapped onto this one.
        - '''adapter 2''': this is the interface on which the pfSense LAN interface will be mapped. select 'host only adapter' because will be necessary to access the machine web dashboard
        in order to further configure it.

Now boot the virtual machine and follow the 'Quick/easy Install' instruction. Remember to detach the optical drive when installation will be completed.

### pfSense configuration

Once booted the following message will be promted to the user:

```bash
*** Welcome to pfSense 2.4.2-RELEASE (amd64) on pfSense ***

 WAN (wan)       -> em0        -> v4/DHCP4: 10.0.0.2/24
 LAN (lan)       -> em1        -> static

 0) Logout (SSH only)                  9) pfTop
 1) Assign Interfaces                 10) Filter Logs
 2) Set interface(s) IP address       11) Restart webConfigurator
 3) Reset webConfigurator password    12) PHP shell + pfSense tools
 4) Reset to factory defaults         13) Update from console
 5) Reboot system                     14) Disable Secure Shell (sshd)
 6) Halt system                       15) Restore recent configuration
 7) Ping host                         16) Restart PHP-FPM
 8) Shell

Enter an option:
```

It is necessary to configure network interfaces so select option '2) Set Interface(s) IP address and LAN interface':
    1. '''WAN''': this interface will receive an ip address from the virtual gateway provided by Openstack, so configure it to use DHCP4;
    2. '''LAN''': it is necessary to get access to pfSense web dashbord so we assign a static ip based on the subnet asigned from the host machine (in our case 192.168.56.0/24).
```bash
Enter the new LAN IPV4 address. Press <ENTER> for None:
> 192.168.56.2

...

Enter the new Lan IPv4 subnet bit count (1 to 31):
> 24

For a WAN, enter the new LAN IPv4 upstream gateway address.
For a LAN, press <ENTER> for none:
> 192.168.56.1
...
```

Enter the web dashboard at 192.168.56.2 using 'admin' as username and 'pfsense' as passsword.
Select 'LAN' from the 'interfaces' dropdown menu and set IPv4 configuration type to 'DHCP'. Save and close.
When you will boot your pfsense image on Openstack, it will assign you an ip on the LAN interface so you can get ssh access and customize it based on your experiment requirement.

Finally you have to enable ssh by selecting '14) Enable Secure Shell (sshd)' and open port 22 on pfSense. The latter is done by executing the command inside a pfSense shell:
```bash
$ easyrule pass LAN TCP any any 22
```

### Prepare the pfSense image

Before shutdown the virtual machine you have to compact VirtualBox's VDI file size issuing the following command on the guest machine:
```bash
$ dd if=/dev/zero of=/empty; rm /empty
```

On the host machine:
```bash
$ vboxmanage modifymedium --compact /path/to/pfsense.vdi
```

Finally convert the VDI disk to qcow2 format:
```bash
$ qemu-img convert pfsense.vdi -O qcow2 pfsense.qcow2
```

Now you can upload the pfsense image on your Openstack using the label and the flavor name provided inside the 'security-manage.ini'.

## Issue tracker

Issues and bug reports should be posted to the GitHub Issue Tracker of this project.

# What is SoftFIRE?

SoftFIRE provides a set of technologies for building a federated experimental platform aimed at the construction and experimentation of services and functionalities built on top of NFV and SDN technologies.
The platform is a loose federation of already existing testbed owned and operated by distinct organizations for purposes of research and development.

SoftFIRE has three main objectives: supporting interoperability, programming and security of the federated testbed.
Supporting the programmability of the platform is then a major goal and it is the focus of the SoftFIRE’s Second Open Call.

## Licensing and distribution
Copyright © [2016-2018] SoftFIRE project

Licensed under the Apache License, Version 2.0 (the "License");

you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.



<!--
 References
-->

[node_types]:etc/softfire_node_types.yaml
[firewall]:firewall.md
[suricata]:suricata.md
[pfsense]:pfsense.md
[docu_url]:http://docs.softfire.eu/security-manager/
[sequence]:security-manager.png



