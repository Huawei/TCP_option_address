# TCP Option Address

The TCP Option Address (TOA) module is a kernel module that obtains the source IPv4 address from the option section of a TCP header.

## How to use the TOA module?

### Requirement

The development environment for compiling the kernel module consists of: 
- kernel headers and the module library
- the gcc compiler
- GNU Make tool

### Installation

Download and decompress the source package:
```
https://github.com/Huawei/TCP_option_address/archive/master.zip
```

Enter the source code directory and compile the module:
```
cd src
make
```

Load the kernel module:
```
sudo insmod toa.ko
```

## Distribution license

TOA is distributed under the terms of the GNU General Public License v2.0. The full terms and conditions of this license are detailed in the LICENSE file.