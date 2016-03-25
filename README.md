# FlowSieve [![Build Status](http://drone.ais.cmc.osaka-u.ac.jp/api/badges/core-grid/flowsieve/status.svg)](http://drone.ais.cmc.osaka-u.ac.jp/core-grid/flowsieve)

---

OpenFlow controller for the "Network access control based on role-base security
policy" project

## Vagrant & Mininet

In this setup, we simulate the whole network using Mininet. Since Mininet
requires Linux  as the operating system, we use vagrant to start and provision
a Linux VM.  We use Ansible to provision the VM. This is the recommended way for
development.

### Configuration

1. Install [Vagrant](https://www.vagrantup.com/) and
  [Ansible](https://www.ansible.com/).
3. Clone this repository and move into the `tool/` directory.
3. Run `vagrant up` to start and provision the VM.
4. `vagrant ssh`

### Execution

All commands below shall be executed inside the VM.

1. `cd /vagrant`
2. `./tool/run_controller` (The controller will run in the foreground, so open
  up a new session for the following commands)
3. `sudo ./tool/run_network`

## Open vSwitch & KVM or Physical OpenFlow switch and physical server

In this setup, we construct the network using virtual machines/switches or
physical machines/switches. Then, we execute the OpenFlow controller in an
isolated environment using direnv and virtualenv. This is the recommended method
for evaluation.

### Configuration

1. Install python, pip and virtualenv.
2. Install and configure [direnv](https://github.com/direnv/direnv).
3. Clone this repository and move into the source code directory.
4. `direnv allow`
5. `pip install -r requirements.txt`
6. Configure each OpenFlow switch to connect to the TCP/6633 port of the
  machine where the controller will be running.


### Execution

1. Run `./tool/run_controller`

---

This software is released under the Apache 2.0 License. See LICENSE for the
full license text. This software includes a part of a work that is distributed
in the Apache 2.0 License.

