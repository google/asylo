# Hello World Primitives Layer

A hello world enclave using the enclave primitives.

## Building

To build the hello_enclave:

`bazel build :hello_dlopen_enclave.so`

To build the hello_driver program:

`bazel build :hello_dlopen_driver`

To run the program, invoke the driver binary (from bazel-bin), and pass in the
path to the enclave:

```bash
$(bazel info bazel-bin)/asylo/platform/primitives/examples/hello_dlopen_driver \
  --enclave_path="$(bazel info bazel-bin)/asylo/platform/primitives/examples/hello_dlopen_enclave.so"
```
