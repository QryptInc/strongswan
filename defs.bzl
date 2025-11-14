"""
This is the public Starlark API for this repo.
"""

load("//strongswan:strongswan.bzl", _strongswan_qrypt = "strongswan_qrypt")

# Re-export macro under its public name
strongswan_qrypt = _strongswan_qrypt

