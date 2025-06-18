# Introduction

This fork of strongswan includes Qrypt's BLAST plugin, providing the ability to use BLAST as an IKE in the IPsec protocol. The code is otherwise unchanged.

# Abridged instructions

These instructions are abridged from [our documentation for Nvidia](https://docs.qrypt.com/sdk/nvidia/). Scroll to the section "Build strongSwan with liboqs and Qrypt’s BLAST plugin" for the entire set of instructions that the two included scripts will execute. These scripts are located in the `quickstart` directory.

# Build

To build, run `build.sh` from the `quickstart` directory. This builds strongswan and our BLAST plugin.

The strongswan daemon can then be started and controlled as such:

```bash
sudo systemctl daemon-reload
sudo systemctl stop strongswan
sudo systemctl start strongswan
sudo systemctl status strongswan
```

There are also two other important commands: `swanctl` and `charon-cmd`.

`swanctl` lets you directly control the daemon. This lets you reload configurations, initiate connections, and far more. Run 

`charon` relates to the IKE daemon in strongswan, for example `charon-systemd` is the binary that runs when invoking the daemon as above. `charon-cmd` is a CLI ipsec client that can be used to interface with a server running the daemon. Many of the options mirror the strongswan configuration options.

# Configuration

A file `swanctl.conf` has been included in the root which is partially filled out. It defines a connection using BLAST as a KE and uses pre-shared keys for initialization. Some parts are labeled accordingly and require modification. Notably, all the IPs for `local*` and `remote*` settings should be changed. Additionally, replace `abcd` with a private key to use PKI. Or keep it as `abcd` for now.

A script `update_conf.sh` is included to replace the confs in `/etc/swanctl/conf.d/` with `swanctl.conf` in the current directory.

## Keys

Create a free account at https://docs.qrypt.com/getting_started/ This will enable you to generate JSON web tokens (JWT) that you'll need to add to the conf files (for BLAST and/or Quantum Entropy). Replace the values set for `jwt` with the corresponding key.

# Troubleshooting

Please ensure the following when trying to run the Blast plugin:

- Use `journalctl -xeu strongswan` to check for errors
- If plugin/KE doesn't load:
    - `-esn` is at end of KEs
    - `libQryptSecurity.so` and `libQryptSecurityC.so` were in the `src/libstrongswan/plugins/blast` directory when build. Ensure they are the correct architecture too by running `file libQryptSecurityC.so`.
- If key doesn't load:
    - Need `/etc/ipsec.secrets`
    - Use local IP as “id” field in secrets of `swanctl.conf`
    - Only place one `*.conf` file in the `/etc/swanctl/conf.d/` directory
- Sockets already bound
    - Stop the service
    - Check `sudo netstat -ntlp` doesn't have strongswan still running and it or anything else bound to ports `4500` or `500`, if so kill it to free up those ports.
    - Try running `sudo systemctl start strongswan-starter`. Then try starting the `strongswan` service again. Check journalctl for success.