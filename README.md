# MineTunnel
Simple application for creating VPN tunnels.  
Supported tun and tap virtual interfaces.  
Supported protocols: udp, icmp.  
The main idea of this app it is the easy configuration and serverless solution (without special server like in the OpenVPN or other popular solutions).

# Supported platforms
Linux Debian based systems is recommended.

# Build and requirements
Just run make in the folder with cloned project. The gcc 12 is recommended but the older versions should work as well.
For running the application requires root privilegies (need for granting acces to /dev/net/tun)

# How to use it
After building the binary you need to write a config file (the example config you can find in examples folder). A config file is a JSON file with the next structure:

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

Where `proto` in root node is tunnel's proto by default, `port` in root node is default port and `encryption_plugins` is array of encryptors (object with name field and path to the encryptor's so; name is unique for encryptor and using as identificator). Available proto's values now: udp, icmp. The array `tunnels` describes all tunnels which have to be created in system. Descriptions of each parameter:

- `remote` - ip address of the remote endpoint. Also available syntax in format "192.168.1.101:5555" where 5555 is port value. If port is not setted then the default port value will be used as a port.
- `local` - ip address of the local interface which have to be used as VTEP (do not recommend use 0.0.0.0 as listening of all interfaces; better to use specific local ip of available network interface). Also available syntax in format "192.168.1.101:5555" (like for remote parameter)
- `proto` - define the protocol for tunneling. This is optional field. If the field is not used here the default tunnel's proto value will be used as the proto.
- `mode` - set tun or tap type of interface for virtual network. Obviously available only 2 values: tun, tap. This parameter is necessary.
- `device` - override the name of created virtual interface in system. This is optional parameter. If it is not setted then new interfaces will have name mine_tun\<num\> or mine_tap\<num\> (depends of the type). \<num\> is the ordered number which begins from 0
- `bringup_script` - path to the script in the OS which will be executed after bringing up the virtual interface.
- `shutdown_script` - path to the script in the OS which will be executed before stopping the interface.
- `icmp_id` - value of icmpid field in icmp header for echo request packets. This filed makes sense only for icmp tunnels. For udp tunnels this parameter will be ignored. This is optional parameter and by default it's equal to 1234
- `encryption` - optional parameter which switches on the encryption for tunnels. If this parameter is setted the `encryption_params` option is necessary. Value must has name from `encryption_plugins` array.
- `encryption_params` - custom paramaeter and has not the constant structure. Value of this parameter depends of the selected `encryption_plugin`. More detailed about encryption texted below.

The config can contain more than one tunnel. For implementing this it needs to add the new tunnel's JSON object into the `tunnels` array. Each tunnel will run within a separate thread (one thread per tunnel). Also it has functionality about the global bringup and shutdown scripts (like for tunnel but for root's JSON node). The global `bringup_script` will be executed AFTER bringing up of the all tunnels and the global `shutdown_script` will be executed BEFORE stopping of the all tunnels.

The next step is just running in console with the next command:

```
sudo ./minetunnel --config config.json
```

The available command line options (or help text by the command `./minetunnel --help`):

```
Usage: ./minetunnel [options]
         --daemon -d  : run in background mode
         --verbose -v : switch on verbose output
         --pid -p     : set path to pid file (for background mode only)
         --config -c  : set config path (by default it is ./config.json)
```

# Examples

Here the basic examples with basic scenarios. The configs for each example are located in "examples" folder.

## Point-to-Point UDP tunnel

The trivial simplest case. This scenario is the gist of tunneling. Let's draw the topo:


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

Here displayed two hosts with ip's on the exeternal interface (or VTEPS) where the virtual network 10.10.10.0/24 have to be created.
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

The last step - run in console (it's command for both hosts):

```
sudo ./minetunnel --config config.json
```

For creating ICMP tunnel just replace `proto` value from udp to icmp and add `icmp_id` value into tunnel's JSON object if it's necessary to replace icmpid inside ICMP header.

## Point-to-Multipoint UDP tunnel (or triangle topology)

This is unusual case where it needs to union more than two nodes into one subnet without server (OpenVPN has special server node and several host can be connected into the one virtual network via this node for this purposes but minetunnel is a serverless solution).


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

Just the same scheme but the Host3 connected to others. In few words any host directly connected to others. The configuration have to be expanded.  
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

And for the Host3 it has the same logic:

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

The app supports encryption. Any encryption is presented as encryption plugins. An encryption pluging is a special `.so` library with specific external functions. More detailed about how to write a custom encryption plugin [here](https://github.com/MastMind/MineTunnel_xor_encryptor "xor encryption example"). The tunnels in encryption mode will be encrypted by plugin's algorythm (it means all packet will be encrypted). It supports only symmetric encyptions (asymetric will be available in future).  
For adding encryption it requires to register an encryption plugin in general section at the first order:
```
encryption_plugins : [
    { name : "xor", path : "./xor_encrypt.so" }
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
The `encryption_params` is a very specific value. It is necessary parameter when added the parameter `encryption`. The value's format depends of the choosen `encryption` and the JSON's object in value will parsing by encryption plugin. Here the xor plugin is using and it requires `key_length` and `key` parameters. See more detailed information about the loaded encryption plugin for correct configuring.