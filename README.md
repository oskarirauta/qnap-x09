# qnap-x09

### Kernel 3.12.6

This is linux kernel v3.12.6 sources for QNap TS-509 and TS-809.
Source is also provided by QNap's sourceforge page at https://sourceforge.net/projects/qosgpl/ but it's incomplete and broken.
QNap's kernels are patched versions of stock kernels with support for QNap's hardware and software (frontend).

This *fork* of qnap's kernel has been modified and *fixed* to build properly.
At the moment it is untested on a real device. There's not even a guarantee that it will boot.

### Warning
So far, this is unpatched version. Patches are coming soon.

### Build instructions

Linux kernel v3.12.6 is not compilable with modern versions of GCC. I found a forum thread that last one able to compile it would be gcc-4.8, but that version only provides non-bootable kernel. So that's why we need gcc-4.7. Multilib version is the best here as it can be used to compile both, 32-bit and 64-bit code.

 - Install Arch Linux's x86_64 version, either to real computer or virtualized one.
 - Set it up and install development packages.
 - Remove GCC
 - Install gcc-multilib-4.7 available from this repository's tools branch. It depends on another available package there: cloog-git. Install that one also.
 - Make symbolic links at /usr/bin for all existing gcc's binary's. For example: ln -s /usr/bin/gcc-4.7 /usr/bin/gcc
 - Get source of kernel from this branch
 - Select kernel config template from kernel_cfg directory by copying it to .config at kernel's root directory.
 - Make necessary changes to configuration (make menuconfig)
 - Build the kernel
 - Test kernel first on the virtual machine to see if it even boots..
 - Populate kernel and modules to qnap's initrd and rootfs files along with necessary edits.
