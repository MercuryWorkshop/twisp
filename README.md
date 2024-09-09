# twisp
[Wisp protocol](https://github.com/MercuryWorkshop/wisp-protocol) server that exposes PTYs over the Wisp connection.

> [!WARNING]
> twisp has been replaced with [epoxy-server](https://github.com/MercuryWorkshop/epoxy-tls/tree/multiplexed/server/) and the twisp feature.

## Migrating from twisp to epoxy-server
Compile epoxy-server with the `twisp` feature.
Use the following config to replicate `twisp --pty /path/to/pty` behavior:
```toml
[server]
bind = "/path/to/pty"
socket = "file"
transport = "lengthdelimitedle"
file_raw_mode = true

[wisp]
wisp_v2 = true

[stream]
allow_twisp = true
```

## License
twisp is licensed under the [GNU GPL-3.0-or-later license](https://www.gnu.org/licenses/gpl-3.0.html).
