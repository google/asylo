# POSIX interface for SGX enclaves

This directory defines a number of common POSIX interfaces for the SGX
environment.

The purpose of this library is to expose a number of critical system services
via the POSIX API and support porting a handful of core packages. The objective
is not to implement POSIX per se: No effort has been made to provide a strictly
conformant POSIX implementation, and users of this library should carefully
review the headers they consume for notes on what features and what behaviors
have been implemented.
