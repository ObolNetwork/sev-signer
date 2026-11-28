# DVTEE and you

> This describes the 2024 Alpine prototype in `vm-scripts/`, which is superseded. The current guest
> image is described in [image/README.md](image/README.md).

This document details the design and architecture of `dvtee`.

The reference architecture is based on the following components:
 - a latest Ubuntu installation
 - an AMD SEV-SNP enabled processor
 - QEMU
 - Linux KVM hypervisor
 
This document will not detail *how* to setup such system, rather how it is designed.

## The basics

The aim of `dvtee` is to implement a secure system in which the software running in it is secure against both the 
hypervisor and other users - this is implemented by means of AMD SEV-SNP virtual machines running Alpine Linux.

In a standard virtual machine (VM), the hypervisor is capable of controlling every single bit of its execution, more 
importantly it is capable of reading and writing the VM's memory at will.

SEV-SNP provides a way for users to create virtual machines whose memory is cryptographically sealed off from the 
hypervisor, allowing workloads to run as if they were two completely different machines.

The SEV-SNP VM runs software that needs to be immutable for trust purposes, as well as store information that is 
considered to be important.

I will explain how those two properties are achieved later.

The trust chain in `dvtee` starts in the silicon: we trust that AMD private keys will not be compromised, and that 
the SEV-SNP implementation currently in the markets is impossible to circumvent or tampered with:

 1. If the silicon boots, then it's safe
 2. If it's safe, then I can boot my SEV-SNP VM, knowing it has not been tampered with
 3. If the SEV-SNP VM boots, then it's not been tampered with and my software is trusted
 4. I can trust that what the SEV-SNP VM tells me is true
 
## Linux booting primer

To understand better how this is implemented, we should have an understanding of the various components that are 
involved in booting a standard Linux system.

Let's assume you want to power on a modern computer that has some flavor of Linux installed on it, after pressing the 
power button the system will run a self-check-up to ensure all the connected hardware is viable, then it hands over the 
processor and memory it just initialized to the UEFI.

UEFI then loads its configuration file from an EEPROM residing on the motherboard, looks up the first bootable device 
in its config file, then proceeds executing the UEFI PE executable it finds in the bootable device.

This executable usually is a boot loader like GRUB, or systemd-boot.

To boot the actual Linux system, you need three things:

 - a Linux kernel image, usually called `zImage` or `vmlinuz`
 - an initial ramdisk filesystem, abbreviated initramfs
 - a series of configuration parameters, called `cmdline`
 
Besides the Linux kernel image, which is self-explanatory, the initramfs and cmdline are two interesting components.

Essentially, booting a Linux computer involves booting the kernel and mounting the initramfs as root, then using the 
cmdline parameters to e.g. look for the real system root and continuing the boot off of that: we use a smaller root 
filesystem to load the bigger root filesystem.

A ramdisk is required as a flexibility constraint: the Linux kernel image might not contain some driver that your 
hardware needs, so you use an initramfs, that contains said driver, to initiate the boot process.

After the initramfs finishes booting and mounting the required filesystems, the real Linux system is ready to be used.

It is important to understand that initramfs is just an archive with a shell script in it and some other files: it 
reads the cmdline and configures the system with the configuration flags contained in it.

## Booting Linux in a SEV-SNP VM

Booting a SEV-SNP virtual machine is slightly different than the flow described above.

SEV-SNP does some __measurements__ on *what* you're booting, in order to provide a trust anchor for the system.

This trust anchor should be used to determine whether or not the system is in a known-good state: if the trust anchor 
changes, the system may have been tampered with.

SEV-SNP measures three things:
 - the Linux kernel image
 - the initramfs
 - the cmdline
 
Measurement in this instance means hash string.

The boot process starts from QEMU, which needs to be configured properly to boot in SEV-SNP mode: this is all taken 
care of by the provisioning scripts in `vm-scripts`.

QEMU starts a special UEFI that works in conjunction with the SEV-SNP subsystem - measurements are enforced by the 
hardware itself, so a special implementation is needed in order for the trust anchor to be actually trustable.

Instead of relying on a boot loader, `dvtee` passes what's called a Unified Kernel Image (UKI) to QEMU to boot 
from: less moving parts means less potential security issues in the future.

UKIs make future improvements like boot signature verification easier, since they unify kernel image, initramfs and 
cmdline in a single file.

As a consequence, the measurements done by SEV-SNP are comprised of a single file: neat!

## Installation

Creating a `dvtee` VM is more involved than usual, because we had to split the VM creation in several steps.

The following paragraph assume the user have compiled an initramfs and Linux kernel image by using the `make kernel` 
command at the root of the `dvtee` repository.

### Step 1. Provisioning the installer

The first step is creating an installer environment that can run in SEV-SNP.

This is done with the `vm-scripts/provision-installer.sh` script, which downloads an Alpine Linux installer and creates 
a `cloud-init` setup for the installer to run into.

`cloud-init` is used to install the special Linux kernel image *inside* the VM itself: since we pass it to QEMU 
directly for booting, we also need it in the VM disk to do things like loading the AMD SEV kernel module.

After that's done, `ukify` is used to create a UKI to boot the installer from.

The user can set up the software and configuration they want in the final system by writing an `user-install.sh` script 
somewhere, and passing the directory containing it to `provision-installer.sh`: the entire directory will be copied on 
the installer for later use.

### Step 2. Running the installer

The `vm-scripts/run-installer.sh` script boots the installer provisioned earlier, sets up the VM disk partition and 
install the Alpine Linux system.

The installer runs `vm-scripts/installer/install.sh`, which does the actual setup.

Disks are formatted as follows:

 - 30GB for /
 - 6GB for the dm-verity partition
 - 2GB for /var
 - 11GB for /home
 - ~1GB for a plaintext partition
 
The installer will use dm-crypt to encrypt the filesystem with a __zero key__ at this stage, because we want to protect 
the disk with a silicon-derived key.

Silicon-derived key are influenced from the SEV-SNP measurements, since the installer system has a different cmdline 
from the final system, if we encrypted with such key now the final system won't boot.

We defer to the first boot the burden of adding a final, working silicon-derived decryption key to the dm-crypt key 
pool.

After the Alpine Linux system is installed, we run `user-install.sh` if present in order to set up the system as the 
user wanted.

To recap, at this stage we have:
 - a partitioned disk
 - filesystems encrypted with dm-crypt that contain an Alpine Linux system
 
To seal the state of the system, we use dm-verity.

dm-verity is a Linux kernel subsystem that verifies at run-time that the content of the disk are exactly as expected: 
if even a single bit is different, the system will fail with a kernel panic making sure to be as loud as possible.

To avoid such thing to happen by chance, we mount the root filesystem as read-only: this is why we run 
`user-install.sh` before applying dm-verity.

`veritysetup` is used to calculate the hash of the state of the root filesystem, which is then written in the dm-verity 
partition.

The dm-verity root hash is then stored in the plaintext partition for later use.

### Step 3. Provisioning the final system

The `vm-scripts/provision.sh` script is the final step before booting to the real system.

It reads the dm-verity root hash from the plaintext partition and embeds it into the final system's cmdline.

This is a very powerful step: since the cmdline is measured alongside the Linux kernel image and the initramfs, the 
root filesystem encryption key is tied to the known-good state of the system.

It does so by creating a new UKI with the newly-generated cmdline inclusive of the dm-verity root hash.

If an attacker tried modifying any of those three components, one of two things would happen:
 - the root filesystem is not decrypted, since the measurement has changed
 - if the root filesystem was mismanaged in any way, the root hash would change, hence dm-verity would panic the system
 
### Step 4. Run the system

The `vm-scripts/run.sh` boots the QEMU VM with the provisioned disk and UKI.

Congrats!


