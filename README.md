# MineTunnel
Simple application for creating VPN tunnels.  
Supported tun and tap virtual interfaces.  
Supported protocols: udp, icmp.  
The main idea of this app it is the easy configuration and serverless solution (without special server like in the OpenVPN or other popular solutions).

# Supported platforms
Linux Debian based systems and Windows 7+.

# Build and requirements

## Linux
Just run make in the folder with cloned project. The gcc 12 is recommended but the older versions should work as well.
For running the application requires root privilegies (need for granting acces to /dev/net/tun)

## Windows
Run compile.bat with MinGW-w64. You'll find the compiled `.exe` in `build` directory. Also you need to install `wintun.dll` (it is located in `drivers` directory) by copying the `.dll` to the main `.exe` directory. For installing TAP0901 driver you need to use the command `pnputil -i -a tap0901.inf` in the specific to OS arch directory which located in the `drivers` directory (if OpenVPN is installed on the machine you don't need to install this driver because this is installed with OpenVPN). By the way you can compile Windows binaries via Linux'es mingw-w64-gcc with `make` (just replace `GCC` variable inside `Makefile` to the `x86_64-w64-mingw32-gcc`).

**WINTUN** is an original driver from [this](https://github.com/WireGuard/wintun "WinTun") project.
**TAP0901** is an original driver from [this](https://github.com/OpenVPN/tap-windows6/releases "tap0901 NDIS6 releases") project.

# How to use it
After building the binary you need to write a config file (the example config you can find in examples folder). The config file is a JSON file with the next structure:

```
{
    proto : "udp",
    port : 4880,
    encryption_plugins : [
        { name : "xor", path : "./xor_encrypt.so" }
    ],
    tunnels : [
        {
          remote : "192.168.1.101", 
          local : "192.168.1.100", 
          proto : "udp", 
          mode : "tap", 
          device : "tunnel_tap0", 
          bringup_script : "script1_start.sh", 
          shutdown_script : "script1_stop.sh", 
          icmp_id : 1408, 
          encryption : "xor",
          encryption_params : { 
              key_length : 4, 
              key : "abcd" 
          }
        }
    ]
}
```

Where `proto` in root node is tunnel's proto by default, `port` in root node is default port and `encryption_plugins` is array of encryptors (object with name field and path to the encryptor's so; name is unique for encryptor and using as an identificator). Available proto's values now: udp, icmp. The array `tunnels` describes all tunnels which have to be created in system. Descriptions of each parameter:

- `remote` - ip address of the remote endpoint. Also available syntax in format "192.168.1.101:5555" where 5555 is port value. If port is not setted then the default port value will be used as a port. Special value "0.0.0.0" enables **dynamic endpoints mode** (server-like mode) — see [Dynamic Endpoints](#dynamic-endpoints-server-like-mode) below.
- `local` - ip address of the local interface which have to be used as VTEP. Also available syntax in format "192.168.1.101:5555" (like for remote parameter). In dynamic endpoints mode use "0.0.0.0" to listen on all interfaces.
- `proto` - define the protocol for tunneling. This is optional field. If the field is not used here the default tunnel's proto value will be used as the proto.
- `mode` - set tun or tap type of interface for virtual network. Obviously available only 2 values: tun, tap. This parameter is necessary.
- `device` - override the name of created virtual interface in system. This is optional parameter. If it is not setted then new interfaces will have name mine_tun\<num\> or mine_tap\<num\> (depends of the type). \<num\> is the ordered number which begins from 0
- `bringup_script` - path to the script in the OS which will be executed after bringing up the virtual interface.
- `shutdown_script` - path to the script in the OS which will be executed before stopping the interface.
- `bringup_embed` - inline embedded script executed after bringing up the virtual interface. Commands separated by semicolons. See [Embedded Scripts](#embedded-scripts) below.
- `shutdown_embed` - inline embedded script executed before stopping the interface.
- `icmp_id` - value of icmpid field in icmp header for echo request packets. This field makes sense only for icmp tunnels. For udp tunnels this parameter will be ignored. This is optional parameter and by default it's equal to the value 1234
- `encryption` - optional parameter which switches on the encryption of tunnel. If this parameter is setted the `encryption_params` option is necessary. The value must have a name from the `encryption_plugins` array.
- `encryption_params` - the custom parameter and has not the constant structure. The value of this parameter depends of the selected `encryption_plugin`. More detailed about encryption texted below.

The config can contain more than one tunnel. For implementing this it requires to add new tunnel's JSON object into the `tunnels` array. Each tunnel will be executed within a separate thread (one thread per tunnel). Also it has functionality about the global bringup and shutdown scripts (like for a tunnel but it has to be described in root's JSON node). The global `bringup_script` will be executed AFTER bringing up of the all tunnels and the global `shutdown_script` will be executed BEFORE stopping of the all tunnels.

The next step is just execute the next command in a terminal:

```
sudo ./minetunnel --config config.json
```

The available command line options are (or help text by the command `./minetunnel --help`):

```
Usage: ./minetunnel [options]
         --daemon       -d : run in background mode (Linux only)
         --verbose      -v : switch on verbose output
         --pid          -p : set path to pid file (for background mode only, Linux)
         --config       -c : set config path (by default it is ./config.json)
         --control-port -l : set control socket port (default: 9880)
         --version      -V : print application version
```

# Examples

Here the basic examples with basic scenarios. The configs for each example are located in "examples" folder.

## Point-to-Point UDP tunnel

The simplest case. This scenario displays the gist of tunneling. Let's draw the topo:


            tun0                                                 tun0
             |                                                    |
       10.10.10.1/24                                        10.10.10.2/24
             |                                                    |
    |-----------------|                                  |-----------------|
    |      Host1      |                                  |      Host2      |
    |-----------------|                                  |-----------------|
             |                                                    |
       192.168.1.100                                        192.168.1.101
             |                                                    |
             |-----------------(UDP port 4880)--------------------|

Here displayed two hosts with ip's on the exeternal interfaces (or VTEPS) where the virtual network 10.10.10.0/24 have to be created.
The config for the Host1:

```
{
    proto : "udp",
    port : 4880,
    tunnels : [
        {
          remote : "192.168.1.101",
          local : "192.168.1.100",
          proto : "udp",
          mode : "tun",
          device : "tun0",
          bringup_script : "script1_start.sh",
          shutdown_script : "script1_stop.sh"
        }
    ]
}
```

The simplest config has `bringup_script` and `shutdown_script` options. Those scripts should have the next scenarios similiar to this:

### script1_start.sh

```
#!/bin/sh

ip link set dev tun0 up
ip addr add 10.10.10.1/24 dev tun0
exit 0

```

### script1_stop.sh

```
#!/bin/sh

ip link set dev tun0 down
exit 0

```

The scripts should be located in the same folder where `minetunnel` binary is located. Those scripts needs to automatically up and down `tun0` interface in the OS.

For the Host2 the config is almost the same but with some mirror replacement in  parameters `remote` and `local`:

```
{
    proto : "udp",
    port : 4880,
    tunnels : [
        {
          remote : "192.168.1.100",
          local : "192.168.1.101",
          proto : "udp",
          mode : "tun",
          device : "tun0",
          bringup_script : "script1_start.sh",
          shutdown_script : "script1_stop.sh"
        }
    ]
}
```

And the Host2 requires replacement for helper scripts:

### script1_start.sh

```
#!/bin/sh

ip link set dev tun0 up
ip addr add 10.10.10.2/24 dev tun0
exit 0

```

### script1_stop.sh

```
#!/bin/sh

ip link set dev tun0 down
exit 0

```

The last step - run in a terminal (it's command for both hosts):

```
sudo ./minetunnel --config config.json
```

For creating ICMP tunnel just replace `proto` value from udp to icmp and add `icmp_id` value into tunnel's JSON object if it's necessary to replace icmpid inside ICMP header.

## Point-to-Multipoint UDP tunnel (or triangle topology)

This is unusual case where it requires to union more than two nodes into one subnet without the server (OpenVPN has the special server node and several hosts can be connected into the one virtual network via this node but in general minetunnel is a serverless solution).


            tun0                                                 tun0
             |                                                    |
       10.10.10.1/24                                        10.10.10.2/24
             |                                                    |
    |-----------------|                                  |-----------------|
    |      Host1      |                                  |      Host2      |
    |-----------------|                                  |-----------------|
             |                                                    |
       192.168.1.100                                        192.168.1.101
             |                                                    |
             |-----------------(UDP port 4880)--------------------|
                                     |
                                     |
                               192.168.1.102
                                     |
                             |-----------------|
                             |      Host3      |
                             |-----------------|
                                     |
                               10.10.10.3/24
                                     |
                                    tun0

Just the same scheme but the Host3 connected to others. In few words any host directly connected to others. The configuration has to be expanded.  
The config for the Host1:

```
{
    proto : "udp",
    port : 4880,
    tunnels : [
        {
          remote : "192.168.1.101",
          local : "192.168.1.100",
          proto : "udp",
          mode : "tun",
          device : "tun0",
          bringup_script : "script1_start.sh",
          shutdown_script : "script1_stop.sh"
        },
        {
          remote : "192.168.1.102",
          local : "192.168.1.100",
          proto : "udp",
          mode : "tun",
          device : "tun0",
          bringup_script : "script1_start.sh",
          shutdown_script : "script1_stop.sh"
        }
    ]
}
```

The helper scripts have the same containing like in the Point-to-Point example.
For the Host2 the config looks similar:

```
{
    proto : "udp",
    port : 4880,
    tunnels : [
        {
          remote : "192.168.1.100",
          local : "192.168.1.101",
          proto : "udp",
          mode : "tun",
          device : "tun0",
          bringup_script : "script1_start.sh",
          shutdown_script : "script1_stop.sh"
        },
        {
          remote : "192.168.1.102",
          local : "192.168.1.101",
          proto : "udp",
          mode : "tun",
          device : "tun0",
          bringup_script : "script1_start.sh",
          shutdown_script : "script1_stop.sh"
        }
    ]
}
```

And for the Host3 it has almost the same containing:

```
{
    proto : "udp",
    port : 4880,
    tunnels : [
        {
          remote : "192.168.1.100",
          local : "192.168.1.102",
          proto : "udp",
          mode : "tun",
          device : "tun0",
          bringup_script : "script1_start.sh",
          shutdown_script : "script1_stop.sh"
        },
        {
          remote : "192.168.1.101",
          local : "192.168.1.102",
          proto : "udp",
          mode : "tun",
          device : "tun0",
          bringup_script : "script1_start.sh",
          shutdown_script : "script1_stop.sh"
        }
    ]
}
```

By this principle the virtual network can be expanded to more clients. The helper scripts must have the same view (for the Host3 obviously ip should be replaced to 10.10.10.3/24)

# Encryption

The app supports encryption. Any encryption is presented as encryption plugins. An encryption pluging is a special `.so` library with the specific external functions. More detailed about how to write a custom encryption plugin [here](https://github.com/MastMind/MineTunnel_xor_encryptor "xor encryption example"). The tunnels in encryption mode will be encrypted by plugin's algorythm (it means all packets will be encrypted). It supports only symmetric encryptions (asymetric will be available in future).  
For adding encryption it requires to register an encryption plugin in general section at the first order:
```
encryption_plugins : [
    { name : "xor", path : "./xor_encrypt.so" }
]
```

You can also use `path_auto` for cross-platform builds — the correct extension (.so on Linux, .dll on Windows) is added automatically:
```
encryption_plugins : [
    { name : "aes", path_auto : "./libmine_tunnel_aes_encryptor" }
]
```
After this we can use the encryption plugin in tunnel's parameters:
```
encryption : "xor",
encryption_params : {
    key_length : 4,
    key : "abcd"
}
```
The `encryption_params` is a very specific value. It is necessary parameter if the parameter `encryption` is added. The value's format depends of the choosen `encryption` and the JSON's object in value will be parsed by encryption plugin. Here the xor plugin is using and it requires `key_length` and `key` parameters. See more detailed information about the loaded encryption plugin for the correct configuring.

# Dynamic Endpoints (Server-like Mode)

In the standard configuration each tunnel knows its remote endpoint in advance. But when remote peers have dynamic IPs (e.g., behind NAT, or connecting from different networks), you cannot hardcode their addresses. MineTunnel supports a **server-like mode** where the tunnel listens for incoming connections and automatically registers new remote endpoints.

To enable this mode, set `remote` to `"0.0.0.0"`:

```json
{
    proto : "udp",
    port : 4880,
    tunnels : [
        {
          remote : "0.0.0.0",
          local : "192.168.1.100",
          proto : "udp",
          mode : "tun",
          device : "tun0",
          bringup_script : "script_start.sh",
          shutdown_script : "script_stop.sh"
        }
    ]
}
```

**How it works:**
When `remote` is `"0.0.0.0"`, the tunnel does not have a predefined remote endpoint. Instead, it listens on the specified `local` address and port, and when the first packet arrives from a new remote IP:port, that peer is automatically added as a dynamic VTEP (Virtual Tunnel Endpoint). Subsequent packets from the same peer are matched against the cached entry.

**Why it's needed:**
- **NAT traversal**: When remote peers are behind NAT, their public IP:port can change unexpectedly. The dynamic mode discovers the actual IP:port from incoming packets.
- **Multiple clients**: A single "server" node can connect to an arbitrary number of clients without knowing their addresses in advance.
- **Simplified client config**: Clients only need to know the server's address; the server discovers them automatically.

The dynamic endpoints are stored in an internal cache with a TTL (time-to-live). If no packets are received from a peer within the TTL period, the entry is removed. You can inspect dynamic endpoints via the [Control Socket](#control-socket) (`get_tunnels` command returns `dynamic: true` for auto-discovered peers).

# Embedded Scripts

In addition to external scripts (`bringup_script`, `shutdown_script`), MineTunnel supports **embedded scripts** written directly inside the configuration file. This eliminates the need for separate script files for common interface setup tasks.

Use `bringup_embed` and `shutdown_embed` fields at both tunnel and global level:

```json
{
    "tunnels": [
        {
          "name": "my-tunnel",
          "remote": "192.168.1.101",
          "local": "192.168.1.100",
          "mode": "tun",
          "device": "tun0",
          "bringup_embed": "interface link up; interface ipv4 addr \"10.10.10.1\" mask \"24\"",
          "shutdown_embed": "interface link down"
        }
    ],
    "bringup_embed": "route add \"10.20.0.0\" mask \"16\" via gateway \"192.168.1.1\"",
    "shutdown_embed": "route del \"10.20.0.0\" mask \"16\" via gateway \"192.168.1.1\""
}
```

Commands are separated by semicolons. Embedded scripts are executed in the following order:
1. Per-tunnel `bringup_embed` (after virtual interface creation)
2. Per-tunnel `bringup_script` (external script)
3. Global `bringup_embed` (after all tunnels are up)
4. Global `bringup_script` (external script)

On shutdown the order is reversed:
1. Global `shutdown_embed`
2. Global `shutdown_script`
3. Per-tunnel `shutdown_embed`
4. Per-tunnel `shutdown_script`

**Available commands:**

| Command | Description |
|---|---|
| `interface link up` | Bring up the virtual interface |
| `interface link down` | Bring down the virtual interface |
| `interface mtu "num"` | Set interface MTU |
| `interface ipv4 addr "ip" mask "num"` | Set IPv4 address and prefix length |
| `interface ipv6 addr "ip6" mask "num"` | Set IPv6 address and prefix length |
| `route add "ip" mask "num" via gateway "ip"` | Add IPv4 route |
| `route del "ip" mask "num" via gateway "ip"` | Delete IPv4 route |
| `route6 add "ip6" mask "num" via gateway "ip"` | Add IPv6 route |
| `route6 del "ip6" mask "num" via gateway "ip"` | Delete IPv6 route |
| `dns add "ip"` | Add IPv4 DNS server |
| `dns6 add "ip6"` | Add IPv6 DNS server |

# Control Socket

MineTunnel includes a built-in TCP control socket for runtime monitoring and management. It starts automatically on `127.0.0.1:9880` (configurable with `--control-port -l`).

**Protocol:** JSON messages, newline-delimited (`\n`). Multiple simultaneous clients are supported.

**Session management:** A client must first `register` to receive a session UID. Sessions expire after 60 seconds of inactivity — send `keep_alive` periodically (recommended every 30 seconds).

**Basic workflow:**

```bash
# Connect and register
echo '{"request":{"cmd":"register"}}' | nc 127.0.0.1 9880

# After receiving UID (e.g., 3), use it in subsequent requests
echo '{"uid":3,"request":{"cmd":"get_tunnels"}}' | nc 127.0.0.1 9880
```

**Available commands:**

| Command | Type | Description |
|---|---|---|
| `register` | `session_open` | Open a session, receive UID |
| `unregister` | `session_close` | Close session and disconnect |
| `keep_alive` | `session_alive` | Extend session lifetime |
| `get_tunnels` | `tunnel_list` | List all tunnels with VTEPs and status |
| `get_tunnels_addr` | `tunnel_addr` | Get IP addresses of virtual interfaces |
| `get_tunnel_cache` | `tunnel_cache` | Get client cache for specified tunnels |
| `clear_tunnel_cache` | `cache_cleared` | Clear cache for specified tunnels |
| `clear_tunnel_cache_all` | `cache_cleared` | Clear cache for all tunnels |

**Example — get tunnel list:**

Request:
```json
{"uid": 3, "request": {"cmd": "get_tunnels"}}
```

Response:
```json
{
  "uid": 3,
  "type": "tunnel_list",
  "status": "OK",
  "data": {
    "tunnels": [
      {
        "device": "tun0",
        "proto": "udp",
        "mode": "tun",
        "local": "192.168.1.100",
        "port": 4880,
        "encryption": "aes",
        "link": "up",
        "remote": [
          {"ip": "1.2.3.4:5001", "dynamic": true},
          {"ip": "5.6.7.8:4880", "dynamic": false}
        ]
      }
    ]
  }
}
```
