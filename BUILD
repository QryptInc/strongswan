load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake", "configure_make")

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

genrule(
    name = "hiredis-lib",
    srcs = [":hiredis"],
    outs = [
        # "libhiredis.so",
        "libhiredis.so.1",
        # "libhiredis.so.1.3.0",
    ],
    cmd = """
        for f in $(locations :hiredis); do
            if [[ $$f == *"libhiredis.so.1" ]]; then
                cp $$f $(location libhiredis.so.1)
            fi
        done
""",
)

filegroup(
    name = "strongswan-qrypt-repo",
    srcs = glob(["**"]),
)

configure_make(
    name = "strongswan-qrypt",
    args = [
        "-j",
        "DESTDIR=$INSTALLDIR",
    ],
    autogen = True,
    configure_in_place = True,
    configure_options = [
        "--enable-openssl",
        "--disable-random",
        "--prefix=/usr",
        "--sysconfdir=/etc",
        "--enable-systemd",
        "--enable-cmd",
        "--with-systemdsystemunitdir=/lib/systemd/system",
        # "--with-systemduserunitdir=$$INSTALLDIR/usr/lib/systemd",
    ],
    data = [
        ":strongswan-qrypt-repo",
    ],
    env = select({
        "//tools/platforms:is_x86_64": {
            "PKG_CONFIG_PATH": "/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/share/pkgconfig",
        },
        "//conditions:default": {
            "PKG_CONFIG_PATH": "/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/share/pkgconfig",
        },
    }),
    lib_source = ":strongswan-qrypt-repo",
    out_bin_dir = "usr/sbin",
    out_binaries = [
        "charon-cmd",
        "swanctl",
        "charon-systemd",
    ],
    out_data_dirs = [
        "etc",
        "usr/share/man",
    ],
    out_data_files = ["lib/systemd/system/strongswan.service"],
    out_lib_dir = "usr/lib/ipsec",
    out_shared_libs = [
        "libcharon.so.0",
        "libstrongswan.so.0",
        "libtls.so.0",
        "libvici.so.0",
        "plugins/libstrongswan-attr.so",
        "plugins/libstrongswan-blast.so",
        "plugins/libstrongswan-cmac.so",
        "plugins/libstrongswan-constraints.so",
        "plugins/libstrongswan-counters.so",
        "plugins/libstrongswan-dnskey.so",
        "plugins/libstrongswan-drbg.so",
        "plugins/libstrongswan-kdf.so",
        "plugins/libstrongswan-kernel-netlink.so",
        "plugins/libstrongswan-nonce.so",
        "plugins/libstrongswan-openssl.so",
        "plugins/libstrongswan-pem.so",
        "plugins/libstrongswan-pgp.so",
        "plugins/libstrongswan-pkcs1.so",
        "plugins/libstrongswan-pkcs7.so",
        "plugins/libstrongswan-pkcs8.so",
        "plugins/libstrongswan-pubkey.so",
        "plugins/libstrongswan-redis.so",
        "plugins/libstrongswan-resolve.so",
        "plugins/libstrongswan-revocation.so",
        "plugins/libstrongswan-socket-default.so",
        "plugins/libstrongswan-sshkey.so",
        "plugins/libstrongswan-updown.so",
        "plugins/libstrongswan-vici.so",
        "plugins/libstrongswan-x509.so",
        "plugins/libstrongswan-xauth-generic.so",
        "plugins/libstrongswan-xcbc.so",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":hiredis",
        "//libs/imports/qryptsdkwrapper:qryptsecurity_c",
    ],
)
