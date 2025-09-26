genrule(
    name = "setup_conan",
    srcs = ["setup_conan.sh"],
    outs = ["conan_home.tar.gz"],
    cmd = """
		CONAN_HOME_DIR="$$(mktemp -d)"

        # Run the setup script, telling it to create the conan home in a temp dir
        ./$(location setup_conan.sh) "$$CONAN_HOME_DIR"

        # Package the resulting conan_home directory into the declared output tarball
        tar -czf $@ -C "$$CONAN_HOME_DIR" .
    """,
)

genrule(
    name = "pull_sdk",
    srcs = [
        "pull_sdk.sh",
		":setup_conan",
    ],
    outs = ["qrypt_sdk.tar.gz"],
    cmd = """
        # Create a directory to hold the extracted Conan configuration
        CONAN_HOME_DIR=$$(mktemp -d)
        tar -xzf $(location :setup_conan) -C $$CONAN_HOME_DIR

        # Create a directory for the final deployed files
        DEPLOY_DIR=$$(mktemp -d)

        # Run the deploy script, pointing it to the config and the output dir
        ./$(location pull_sdk.sh) $$CONAN_HOME_DIR $$DEPLOY_DIR

        # Package the final SDK files into the declared output tarball
        tar -czf $@ -C $$DEPLOY_DIR .
    """,
)

genrule(
	name = "h",
	srcs = [":pull_sdk"],
	outs = ["qryptsecurity_c.h"],
	cmd = """
		tar -xvf $(location pull_sdk)
		cp include/QryptSecurityC/qryptsecurity_c.h $(location qryptsecurity_c.h)
	""",
)

genrule(
	name = "so",
	srcs = [":pull_sdk"],
	outs = ["libQryptSecurityC.so"],
	cmd = """
		tar -xvf $(location pull_sdk)
		cp lib/libQryptSecurityC.so $(location libQryptSecurityC.so)
	""",
)

cc_import(
	name = "precompiled",
	shared_library = ":so",
)

cc_library(
	name = "qryptsecurity_c",
	hdrs = [":h"],
	deps = [":precompiled"],
    visibility = ["//visibility:public"],
)
