# Asylo - A framework for enclave applications

Copyright 2018 Asylo authors

This package provides a Skylark provider in `enclave_info.bzl`, called
`enclave_info`. All Asylo backends should have build rules that produce targets
that are known to be enclaves. The backend should use `enclave_info` to mark
their enclave targets so that Asylo's build rules can recognize them as legal
enclave dependencies.
