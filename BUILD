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
        "liboqs.so.8",
    ],
    cmd = """
        for f in $(locations //strongswan:liboqs); do
            if [[ $$f == *"liboqs.so.8" ]]; then
                cp $$f $(location liboqs.so.8)
            fi
        done
		""",
		visibility = ["//visibility:public"]
)
