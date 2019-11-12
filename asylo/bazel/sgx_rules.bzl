"""SGX-backend-specific build rules for binaries and tests."""

load("//asylo/bazel:asylo.bzl", "enclave_test")
load("@linux_sgx//:sgx_sdk.bzl", "sgx")

def sgx_enclave_test(name, srcs, **kwargs):
    """Build target for testing one or more instances of 'debug_sign_enclave'.

    This macro invokes enclave_test with the "asylo-sgx" tag added.

    Args:
      name: The target name.
      srcs: Same as cc_test srcs.
      **kwargs: enclave_test arguments.
    """
    enclave_test(
        name,
        srcs = srcs,
        backends = sgx.backend_labels,
        **kwargs
    )
