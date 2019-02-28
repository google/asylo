# Hello World Primitives Layer

A hello world enclave using the enclave primitives.

## Building

To build the hello_enclave:

`bazel build :hello_enclave.so --config=asylo --define=ASYLO_SIM=1`

The `--config=asylo` flag selects our enclave cross compiler toolchain, which
builds code to run inside enclaves.

The `--define=ASYLO_SIM=1` flag lets the build know which Asylo backend to use.
In this case it selects the simulator.

To build the hello_driver program:

`bazel build :hello_driver --define=ASYLO_SIM=1`

To run the program, invoke the driver binary (from bazel-bin), and pass in the
path to the enclave:

`` `bazel info
bazel-bin`/third_party/asylo/platform/primitives/examples/hello_driver
--enclave_path=`bazel info --config=asylo
bazel-bin`/third_party/asylo/platform/primitives/examples/hello_enclave_simulated.so``
