genrule(
	name = "h",
	outs = ["qryptsecurity_c.h"],
	cmd = select({
		"//:is_x86_64": """
			TEMP_DIR="$$(mktemp -d)"
			conan install --requires qryptsdkwrapper/0.12.2@qrypt/dev -o "&:language=c" --profile linux-x86_64 --deployer-package="&" --deployer-folder="$$TEMP_DIR"
			cp "$$TEMP_DIR"/asdf/include/QryptSecurityC/qryptsecurity_c.h $(location qryptsecurity_c.h)
		""",
		"//conditions:default": """
			TEMP_DIR="$$(mktemp -d)"
			conan install --requires qryptsdkwrapper/0.12.2@qrypt/dev -o "&:language=c" --profile linux-aarch64 --deployer-package="&" --deployer-folder="$$TEMP_DIR"
			cp "$$TEMP_DIR"/include/QryptSecurityC/qryptsecurity_c.h $(location qryptsecurity_c.h)
		""",
    }),
)

genrule(
	name = "so",
	outs = ["libQryptSecurityC.so"],
	cmd = select({
		"//:is_x86_64": """
			TEMP_DIR="$$(mktemp -d)"
			conan install --requires qryptsdkwrapper/0.12.2@qrypt/dev -o "&:language=c" --profile linux-x86_64 --deployer-package="&" --deployer-folder="$$TEMP_DIR"
	 		cp ""$TEMP_DIR"/lib/libQryptSecurityC.so $(location libQryptSecurityC.so)
		""",
		"//conditions:default": """
			TEMP_DIR="$$(mktemp -d)"
			conan install --requires qryptsdkwrapper/0.12.2@qrypt/dev -o "&:language=c" --profile linux-aarch64 --deployer-package="&" --deployer-folder="$$TEMP_DIR"
	 		cp "$$TEMP_DIR"/lib/libQryptSecurityC.so $(location libQryptSecurityC.so)
		""",
    }),
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
