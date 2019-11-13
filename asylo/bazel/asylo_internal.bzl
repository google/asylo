"""Shared rules and macros within the Asylo implementation."""

def asylo_package():
    """Returns an appropriate-to-caller package name for Asylo."""

    return "//asylo" if "asylo" in native.package_name() else "@com_google_asylo//asylo"

internal = struct(
    package = asylo_package,
)
