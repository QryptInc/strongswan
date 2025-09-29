config_setting(
    name = "is_x86_64",
    constraint_values = [
        "@platforms//cpu:x86_64",
        "@platforms//os:linux",
    ],
)

alias(
	name = "strongswan-qrypt",
	actual = "//strongswan:strongswan-qrypt",
	visibility = ["//visibility:public"]
)

genrule(
    name = "hiredis-lib",
    srcs = ["//strongswan:hiredis"],
    outs = [
        "libhiredis.so.1",
    ],
    cmd = """
        for f in $(locations //strongswan:hiredis); do
            if [[ $$f == *"libhiredis.so.1" ]]; then
                cp $$f $(location libhiredis.so.1)
            fi
        done
		""",
		visibility = ["//visibility:public"]
)

genrule(
    name = "liboqs-lib",
    srcs = ["//strongswan:liboqs"],
    outs = [
        "liboqs.so",
    ],
    cmd = """
        for f in $(locations //strongswan:liboqs); do
            if [[ $$f == *"liboqs.so" ]]; then
                cp $$f $(location liboqs.so)
            fi
        done
		""",
		visibility = ["//visibility:public"]
)
