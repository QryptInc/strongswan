def _print_config_impl(ctx):
    arch = ctx.attr.arch

    # Create a dummy output file
    out = ctx.actions.declare_file(ctx.label.name + ".txt")

    # Run a command that prints the architecture
    ctx.actions.run_shell(
        outputs = [out],
        command = 'echo "Building for architecture: {}" && touch {}'.format(arch, out.path),
    )

    return [DefaultInfo(files = depset([out]))]

print_config = rule(
    implementation = _print_config_impl,
    attrs = {
        "arch": attr.string(),
    },
)
