genrule(
    name = "setup_conan",
    srcs = ["setup_conan.sh"],
    outs = ["conan_home.tar.gz"],
    cmd = select({
        "//tools/platforms:exec_x86_64": """
            CONAN_HOME_DIR="$$(mktemp -d)"
            ./$(location setup_conan.sh) "$$CONAN_HOME_DIR" "x86_64"
            tar -czf $@ -C "$$CONAN_HOME_DIR" .
        """,
        "//tools/platforms:exec_aarch64": """
            CONAN_HOME_DIR="$$(mktemp -d)"
            ./$(location setup_conan.sh) "$$CONAN_HOME_DIR" "aarch64"
            tar -czf $@ -C "$$CONAN_HOME_DIR" .
        """,
    }),
)

genrule(
    name = "pull_sdk",
    srcs = [
        "pull_sdk.sh",
        ":setup_conan",
    ],
    outs = ["qrypt_sdk.tar.gz"],
    cmd = select({
        "//tools/platforms:exec_x86_64": """
            CONAN_HOME_DIR=$$(mktemp -d)
            tar -xzf $(location :setup_conan) -C $$CONAN_HOME_DIR
            DEPLOY_DIR=$$(mktemp -d)
            ./$(location pull_sdk.sh) $$CONAN_HOME_DIR $$DEPLOY_DIR "x86_64"
            tar -czf $@ -C $$DEPLOY_DIR .
        """,
        "//tools/platforms:exec_aarch64": """
            CONAN_HOME_DIR=$$(mktemp -d)
            tar -xzf $(location :setup_conan) -C $$CONAN_HOME_DIR
            DEPLOY_DIR=$$(mktemp -d)
            ./$(location pull_sdk.sh) $$CONAN_HOME_DIR $$DEPLOY_DIR "aarch64"
            tar -czf $@ -C $$DEPLOY_DIR .
        """,
    }),
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
