# Overview

This charm allows for the configuration of VPP Neutron deployed host

### Initial deployment:

The following steps assume that an ubuntu unit with a subordinate vpp charm 
with the following config has been deployed:

```
application: vpp
application-config:
  trust:
    default: false
    description: VPP is an ML2 mechanism driver that controls the FD.io VPP software switch
    source: default
    type: bool
    value: false
charm: vpp
settings:
  cidr:
    description: |
      CIDR of the network interface to setup.
      e.g. 192.168.0.0/24
    source: user
    type: string
    value: 10.10.51.0/24
```

juju status looks like:

```
$ juju status 
Model        Controller  Cloud/Region         Version  SLA          Timestamp
model1  lxd         localhost/localhost  2.7.2    unsupported  11:52:19Z

App                       Version     Status   Scale  Charm                     Store       Rev  OS      Notes  
vpp                                   waiting      0  vpp                       local         3  ubuntu  
ubuntu                    18.04       active       1  ubuntu                    jujucharms   15  ubuntu  


Unit                   Workload  Agent      Machine  Public address  Ports               Message
ubuntu/0*              active    idle       127      10.0.8.155                          ready
  vpp/0*               active    idle                10.0.8.155                          Unit ready

```

### Deploy advanced-routing charm :

- ``` juju deploy ./vpp ```
- ``` juju add-relation neutron-gateway vpp ```

VPP is in status blocked with message: "Please disable charm-vpp"

Apply the config with the command:

```
juju config vpp --file ./vpp_config
```

# Usage

    juju deploy ./vpp

