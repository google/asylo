"""SGX-backend-specific build rules for binaries and tests."""

load("//asylo/bazel:asylo.bzl", "enclave_test")

def sgx_enclave_test(name, srcs, **kwargs):
    """Build target for testing one or more instances of 'sgx.debug_enclave'.

    This macro invokes enclave_test with the "asylo-sgx" tag added.

    Args:
      name: The target name.
      srcs: Same as cc_test srcs.
      **kwargs: enclave_test arguments.
    """
    tags = kwargs.pop("tags", [])
    enclave_test(
        name,
        srcs = srcs,
        tags = tags + [
            "asylo-sgx",
            "manual",
        ],
        **kwargs
    )
