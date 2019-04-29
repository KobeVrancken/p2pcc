Introduction
------------

This repository contains a research prototype of a peer-to-peer compiler based on [Intel SGX](https://software.intel.com/en-us/sgx), [Graphene-SGX](https://github.com/oscarlab/graphene), [distcc](https://github.com/distcc/distcc) and [clang](https://clang.llvm.org/).

The corresponding paper was published at The 34th ACM/SIGAPP Symposium On Applied Computing (SAC 2019).
Once the conference proceedings are publicly available, I will link the paper here.


Warning
------------
This is a research prototype. **Do not use any of this code in any real deployment.**
It uses bad randomness, hard-coded keys, unsafe memory management and much more.

Prerequisites
------------

This project requires installation of 
- [Intel SGX Linux Driver](https://github.com/intel/linux-sgx-driver)
- [Intel SGX Linux SDK](https://github.com/intel/linux-sgx)
- [Graphene-SGX](https://github.com/oscarlab/graphene)
- [LLVM](https://github.com/llvm/llvm-project)

It uses CMake as the main build system.

Disclaimer
-----------
Currently, only part of the code for the research prototype is available in this repository.
A complete build from this repository is not yet possible.
The modifications of distcc and LLVM needed to deploy the p2pcc enclaves were done in forks of
the LLVM and distcc repositories, and need to be bundled with this repository in a less "hacky" way.
If you already want full access to this code, feel free to send me an e-mail at [kobe.vrancken@cs.kuleuven.be](mailto:kobe.vrancken@cs.kuleuven.be).
