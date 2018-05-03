""" Asylo-specific copts.

Flags specified here should not affect any ABI, but may influence warnings and
optimizations.  They are used on top of any flags provided by the crosstool in
use and are intended to be only used within the Asylo project (not affecting
consumers of the Asylo project).
"""

# Customization of compiler-generated warning output.
_WARNING_FLAGS = [
    "-Wall",
    "-Wextra",
    "-Wno-sign-compare",
    "-Wno-unused-parameter",
]

ASYLO_DEFAULT_COPTS = _WARNING_FLAGS
