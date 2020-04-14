# intel_certs

Certificates and other data in this directory are included for convenience.
Asylo authors make no assertions of the accuracy of these certificates. Asylo
users should either import their own copies of these certificates or verify the
accuracy of the certificates herein.

## intel_sgx_root_ca_cert

This certificate is the root certificate for certificates from the Intel SGX PCK
Platform CA and the Intel SGX PCK Processor CA, and the root certificate for the
Intel SGX TCB Signing Certificate. Its use is further discussed in the
Certificate Hierarchy section of
[this document](https://download.01.org/intel-sgx/dcap-1.0.1/docs/SGX_PCK_Certificate_CRL_Spec-1.0.pdf).

## qe_identity

This is an `asylo::SgxIdentity` textproto representation of the Intel ECDSA QE
identity. It is fetched from the
[Get Quote Verification Enclave Identity](https://api.portal.trustedservices.intel.com/documentation#pcs-qve-identity-v2)
API in Intel's Provisioning Certification Service.
