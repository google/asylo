"""SGX-backend-specific build rules for binaries and tests."""

load("@linux_sgx//:sgx_sdk.bzl", "sgx")
load("//asylo/bazel:asylo.bzl", "cc_unsigned_enclave", "debug_sign_enclave", "enclave_test")

def sgx_cc_unsigned_enclave(name, **kwargs):
    """Shorthand for cc_unsigned_enclave with only SGX backends.

    Args:
        name: The name of the rule.
        **kwargs: The arguments to cc_unsigned_enclave (may not include
            "backends").
    """
    cc_unsigned_enclave(name, backends = sgx.backend_labels, **kwargs)

def sgx_debug_sign_enclave(name, **kwargs):
    """Shorthand for debug_sign_enclave with only SGX backends.

    Args:
        name: The name of the rule.
        **kwargs: The arguments to debug_sign_enclave (may not include
            "backends").
    """
    debug_sign_enclave(name, **kwargs)

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
