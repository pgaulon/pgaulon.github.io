# MiniCPS and Vagrant - 2018-10-22

[MiniCPS](https://github.com/scy-phy/minicps) ([https://arxiv.org/pdf/1507.04860.pdf](paper)) is a framework written in Python that allows to simulate Cyber Physical Systems (CPS) in real-time built on top of Mininet.
[Mininet](https://mininet.org/) is a lightweight network emulator and MiniCPS uses it to emulate a CPS network.

Having gone through it, the installation process is quite simple. However I usually prefer to install softwares in an isolated environment, and especially using virtual machines (VM). I think about it as a safety net in case the installation goes wrong. For that effect, Mininet provides a ready to go [image](http://mininet.org/download/#option-1-mininet-vm-installation-easy-recommended). So from there the only step missing is to [install MiniCPS](https://minicps.readthedocs.io/en/latest/userguide.html#install-minicps).

Mininet VM is based on Ubuntu 14.04 which officially joined the [old releases section](http://old-releases.ubuntu.com/releases/14.04.0/) and will reach its end of life next April. Also, the process of installing Mininet is quite long and requires manual intervention: one need to download the Mininet VM, install it using ones favorite virtualizer, find its IP, install MiniCPS and clone its repository to get started.

A better user experience can be achieved using [Vagrant](https://www.vagrantup.com/). From a single file, a virtual machine containing the already installed environment can be brought up using the magic words:

    $ vagrant up

Before having that ease of use someone needs to create the MiniCPS ready VM. So I decided to start from a brand new Ubuntu 18.04. Since I was a bit lazy to go over the whole process of packaging the VM myself I took a look at [Packer](https://www.packer.io/) templates for this version of Ubuntu. By chance someone named [Serainville](https://github.com/serainville/packer_templates) already did it! His template is simple and concise enough to make a good start for the MiniCPS vagrant box. In short it takes care of bringing up the machine through the Virtualbox provider, simulating the strokes to open the manual boot with predefined options, and setting few options likes the base image, the disk size and so on. Then a couple of shell scripts are invoked in order to setup the vagrant user sudo access, and cleanup the machine. The box is then ready to be packaged. The vagrant user is required in order to be able to use Vagrant to ssh into the box.

Most of the work being done here, I decided to [fork that project](https://github.com/pgaulon/packer_templates) and add a similar folder using the same structure as the Ubuntu one. I added the different needed packages for the installation in the ```preseed.cfg``` file. I also added a few bash scripts for the VM provision.

- the init scripts adds the default SSH key to the vagrant user, enabling passwordless ssh into the box
- there is now the VirtualBox guest additions installation, which will be used to share current directory between the host and the guest
- the mininet script follows the [installation from source of Mininet](http://mininet.org/download/#option-2-native-installation-from-source). I chose to install it system wide in ```/opt```
- the minicps script installs minicps

And now Packer can do its magic:

    $ packer build minicps.json

At the end of the procedure we are left with a ```output/minicps.box``` file. This file can be used locally. It can be added to Vagrant, then a Vagrantfile can be created, then the VM can be brought up:

    $ vagrant box add output/minicps.box --name minicps
    $ vagrant init minicps
    $ vagrant up

That would be troublesome if each developer has to build its own image before using it. The next step is then to host the packaged box on [Vagrant cloud](https://app.vagrantup.com/) so MiniCPS developers can download it directly as described in a Vagrantfile. So I created an account on Vagrant Cloud, uploaded the ```minicps.box``` [file](https://app.vagrantup.com/pgaulon/boxes/minicps).

Now the box is based on the latest Ubuntu LTS, packaged with both Mininet and MiniCPS and uploaded to Vagrant Cloud, anyone with:

- Virtualbox
- Vagrant
- a Vagrantfile containing:
  ```
  Vagrant.configure("2") do |config|
    config.vm.box = "pgaulon/minicps"
  end
  ```

can bring up the exact same virtual machine.
Adding such Vagrantfile at the root of MiniCPS repository allows any developer to be quickly bootstraped with a working developement environment they can SSH into for their tests without worrying about the installation process, focusing their efforts on building complex CPS. An example of such CPS could be [a water distribution system](https://itrust.sutd.edu.sg/testbeds/secure-water-treatment-swat/), a power grid or a nuclear power plant.

    $ git clone https://github.com/scy-phy/minicps
    $ cd minicps
    $ cat Vagrantfile
    Vagrant.configure("2") do |config|
      config.vm.box = "pgaulon/minicps"
    end
    $ vagrant up
    Bringing machine 'default' up with 'virtualbox' provider...
    ==> default: Importing base box 'pgaulon/minicps'...
    ==> default: Matching MAC address for NAT networking...
    ==> default: Checking if box 'pgaulon/minicps' is up to date...
    ==> default: Setting the name of the VM: minicps_default_1540743232867_9929
    ==> default: Clearing any previously set network interfaces...
    ==> default: Preparing network interfaces based on configuration...
        default: Adapter 1: nat
    ==> default: Forwarding ports...
        default: 22 (guest) => 2222 (host) (adapter 1)
    ==> default: Booting VM...
    ==> default: Waiting for machine to boot. This may take a few minutes...
        default: SSH address: 127.0.0.1:2222
        default: SSH username: vagrant
        default: SSH auth method: private key
        default: Warning: Connection reset. Retrying...
        default: Warning: Remote connection disconnect. Retrying...
        default: Warning: Connection reset. Retrying...
        default:
        default: Vagrant insecure key detected. Vagrant will automatically replace
        default: this with a newly generated keypair for better security.
        default:
        default: Inserting generated public key within guest...
        default: Removing insecure key from the guest if it's present...
        default: Key inserted! Disconnecting and reconnecting using new SSH key...
    ==> default: Machine booted and ready!
    ==> default: Checking for guest additions in VM...
    ==> default: Mounting shared folders...
        default: /vagrant => /Users/pgaulon/Downloads/minicps
    $ vagrant ssh
    Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 4.15.0-29-generic x86_64)

    * Documentation:  https://help.ubuntu.com
    * Management:     https://landscape.canonical.com
    * Support:        https://ubuntu.com/advantage

    vagrant@minicps:~$ cd minicps/
    vagrant@minicps:~/minicps$ sudo python examples/swat-s1/run.py
    *** Ping: testing ping reachability
    attacker -> plc1 plc2 plc3
    plc1 -> attacker plc2 plc3
    plc2 -> attacker plc1 plc3
    plc3 -> attacker plc1 plc2
    *** Results: 0% dropped (12/12 received)
    mininet>
    vagrant@minicps:~/minicps$
