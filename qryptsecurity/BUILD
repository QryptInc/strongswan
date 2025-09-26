genrule(
	name = "h",
	outs = ["qryptsecurity_c.h"],
	cmd = select({
		"//:is_x86_64": """
			conan install --requires qryptsdkwrapper/0.12.2@qrypt/dev -o "&:language=c" --profile linux-x86_64 --deployer-package="&" --deployer-folder=.
			cp include/QryptSecurityC/qryptsecurity_c.h $(location qryptsecurity_c.h)
		""",
		"//conditions:default": """
			conan install --requires qryptsdkwrapper/0.12.2@qrypt/dev -o "&:language=c" --profile linux-aarch64 --deployer-package="&" --deployer-folder=.
			cp include/QryptSecurityC/qryptsecurity_c.h $(location qryptsecurity_c.h)
		""",
    }),
)

genrule(
	name = "so",
	outs = ["libQryptSecurityC.so"],
	cmd = select({
		"//:is_x86_64": """
			conan install --requires qryptsdkwrapper/0.12.2@qrypt/dev -o "&:language=c" --profile linux-x86_64 --deployer-package="&" --deployer-folder=.
	 		cp lib/libQryptSecurityC.so $(location libQryptSecurityC.so)
		""",
		"//conditions:default": """
			conan install --requires qryptsdkwrapper/0.12.2@qrypt/dev -o "&:language=c" --profile linux-aarch64 --deployer-package="&" --deployer-folder=.
	 		cp lib/libQryptSecurityC.so $(location libQryptSecurityC.so)
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
