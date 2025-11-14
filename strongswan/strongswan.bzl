load("@rules_foreign_cc//foreign_cc:defs.bzl", "configure_make")

def strongswan_qrypt(name, enable_systemd = True):
    """
    Builds strongswan-qrypt with all dependencies hard-coded.

    Args:
        name: The name of the target.
        enable_systemd: If True, builds with systemd support,
                        including the charon-systemd binary and service file.
    """

    # Base configuration
    configure_options = [
        "--enable-openssl",
        "--disable-random",
        "--prefix=/usr",
        "--sysconfdir=/etc",
        "--enable-cmd",
        "--enable-oqs",
        "--with-systemdsystemunitdir=/lib/systemd/system",
    ]

    out_binaries = [
        "charon-cmd",
        "swanctl",
    ]

    out_data_files = []

    # Conditionally add systemd-related options
    if enable_systemd:
        configure_options.append("--enable-systemd")
        out_binaries.append("charon-systemd")
        out_data_files.append("lib/systemd/system/strongswan.service")

    # Rule instantiation
    configure_make(
        name = name,

		# Configurable settings
        configure_options = configure_options,
        out_binaries = out_binaries,
        out_data_files = out_data_files,

        # Hard-coded attributes
        args = [
            "-j",
            "DESTDIR=$INSTALLDIR",
        ],
        autogen = True,
        configure_in_place = True,
        out_bin_dir = "usr/sbin",
        out_data_dirs = [
            "etc",
            "usr/share/man",
        ],
        out_lib_dir = "usr/lib/ipsec",
        visibility = ["//visibility:public"],

        # Hard-coded labels
        # These labels are resolved relative to this .bzl file's package.
        lib_source = ":strongswan-qrypt-repo",
        data = [
            ":strongswan-qrypt-repo",
        ],
        deps = [
            ":hiredis",
            ":liboqs",
            "//qryptsecurity:qryptsecurity_c",
        ],

        env = select({
            "//tools/platforms:is_x86_64": {
                "PKG_CONFIG_PATH": "/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/share/pkgconfig",
            },
            "//conditions:default": {
                "PKG_CONFIG_PATH": "/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/share/pkgconfig",
            },
        }),

        # Hard-coded output lists
        out_shared_libs = [
            "libcharon.so.0",
            "libstrongswan.so.0",
            "libtls.so.0",
            "libvici.so.0",
            "plugins/libstrongswan-attr.so",
            "plugins/libstrongswan-blast.so",
            "plugins/libstrongswan-cmac.so",
            "plugins/libstrongswan-constraints.so",
            "plugins/libstrongswan-dnskey.so",
            "plugins/libstrongswan-drbg.so",
            "plugins/libstrongswan-kdf.so",
            "plugins/libstrongswan-kernel-netlink.so",
            "plugins/libstrongswan-nonce.so",
            "plugins/libstrongswan-openssl.so",
            "plugins/libstrongswan-oqs.so",
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
    )

