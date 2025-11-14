load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")
load(":strongswan.bzl", "strongswan_qrypt")

package(default_visibility = ["//visibility:public"])

cmake(
    name = "hiredis",
    lib_source = "@hiredis-repo//:hiredis-src",
    out_shared_libs = [
        "libhiredis.so",
        "libhiredis.so.1",
        "libhiredis.so.1.3.0",
    ],
)

cmake(
    name = "liboqs",
    lib_source = "@liboqs-repo//:liboqs-src",
	generate_args = [
        "-G Ninja",
    ],
    cache_entries = {
        "OQS_USE_OPENSSL": "ON",
        "BUILD_SHARED_LIBS": "ON",
        "CMAKE_INSTALL_PREFIX": "/usr",
        "CMAKE_BUILD_TYPE": "Release",
        "OQS_BUILD_ONLY_LIB": "ON",
    },
	out_shared_libs = [
		"liboqs.so",
		"liboqs.so.8"
	],
)

filegroup(
    name = "strongswan-qrypt-repo",
    srcs = glob(["**"]),
)

strongswan_qrypt(
	name = "strongswan-systemd",
	enable_systemd = True,
)

strongswan_qrypt(
	name = "strongswan-no-systemd",
	enable_systemd = False,
)
