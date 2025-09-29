load(
    "@bazel_tools//tools/build_defs/cc:action_names.bzl",
    "CPP_LINK_EXECUTABLE_ACTION_NAME",
)
load(
    "@bazel_tools//tools/cpp:cc_toolchain_config_lib.bzl",
    "action_config",
    "tool",
    "tool_path",
)

# CPP toolchain for cross building from linux arm to amd.
# run 'apt-get install g++-x86-64-linux-gnu libc6-dev-amd64-cross'

def _impl(ctx):
    tool_paths = [
        tool_path(
            name = "gcc",
            path = "/usr/bin/x86_64-linux-gnu-gcc",
        ),
        tool_path(
            name = "ld",
            path = "/usr/bin/x86_64-linux-gnu-ld",
        ),
        tool_path(
            name = "ar",
            path = "/usr/bin/x86_64-linux-gnu-ar",
        ),
        tool_path(
            name = "cpp",
            path = "/usr/bin/x86_64-linux-gnu-cpp",
        ),
        tool_path(
            name = "gcov",
            path = "/usr/bin/x86_64-linux-gnu-gcov",
        ),
        tool_path(
            name = "nm",
            path = "/usr/bin/x86_64-linux-gnu-nm",
        ),
        tool_path(
            name = "objdump",
            path = "/usr/bin/x86_64-linux-gnu-objdump",
        ),
        tool_path(
            name = "strip",
            path = "/usr/bin/x86_64-linux-gnu-strip",
        ),
    ]

    return cc_common.create_cc_toolchain_config_info(
        ctx = ctx,
        toolchain_identifier = "x86_64-toolchain",
        host_system_name = "local",
        target_system_name = "x86_64-unknown-linux-gnu",
        target_cpu = "x86_64",
        target_libc = "unknown",
        compiler = "gcc",
        action_configs = [
            action_config(
                action_name = CPP_LINK_EXECUTABLE_ACTION_NAME,
                enabled = True,
                tools = [tool(path = "/usr/bin/x86_64-linux-gnu-gcc")],
            ),
        ],
        cxx_builtin_include_directories = [
            "/usr/lib/gcc-cross/x86_64-linux-gnu/10/include",
            "/usr/lib/gcc-cross/x86_64-linux-gnu/11/include",
            "/usr/include",
            "/usr/x86_64-linux-gnu/include",
        ],
        abi_version = "unknown",
        abi_libc_version = "unknown",
        tool_paths = tool_paths,
    )

cc_toolchain_config = rule(
    implementation = _impl,
    attrs = {},
    provides = [CcToolchainConfigInfo],
)
