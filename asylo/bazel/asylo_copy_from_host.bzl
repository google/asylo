"""Rules that cross toolchain boundaries without using transitions."""

def _parse_label(label):
    """Parse a label into (package, name).

    Args:
      label: string in relative or absolute form.

    Returns:
      Pair of strings: package, relative_name
    """
    if label.startswith("//"):  # Absolute label.
        label = label[2:]  # drop the leading //
        colon_split = label.split(":")
        if len(colon_split) == 1:  # no ":" in label
            pkg = label
            _, _, target = label.rpartition("/")
        else:
            pkg, target = colon_split  # fails if len(colon_split) != 2
    else:
        colon_split = label.split(":")
        if len(colon_split) == 1:  # no ":" in label
            pkg, target = native.package_name(), label
        else:
            pkg2, target = colon_split  # fails if len(colon_split) != 2
            pkg = native.package_name() + ("/" + pkg2 if pkg2 else "")
    return pkg, target

def copy_from_host(target, output, name = "", visibility = None):
    """Genrule that builds target with host CROSSTOOL.

    Args:
      target: The host target to be copied.
      output: Location of the target copy made by the rule.
      name: Optional name of the rule; if missing, generated automatically
            from the target.
      visibility: Optional visibility of the rule by other packages;
            default is '//visibility:private' unless default_visibility
            is specified in the package.

    """
    _, local_name = _parse_label(target)
    name = name if name else local_name + "_as_host"
    native.genrule(
        name = name,
        srcs = [],
        outs = [output],
        # Instead of running the "tool" for build-time file generation, copy it
        # to the output so it can be used within the context of a different
        # toolchain.
        cmd = "cp $(location %s) $@" % target,
        executable = 1,
        output_to_bindir = 1,
        # Builds target on the exec platform, which has coincidentally been the
        # same as the host platform. This allows using both the Asylo toolchain
        # and the host toolchain in the same build without using the
        # experimental transitions feature. Only works for executable targets.
        tools = [target],
        testonly = 1,
        visibility = visibility,
    )
