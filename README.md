
# eBPF TCP Port Filter (XDP)

An eBPF-based network filtering project that drops incoming IPv4 TCP packets addressed to a configurable destination port.

## Features

- Uses XDP for packet filtering.
- Defaults to TCP port 4040.
- Allows the port to be configured from userspace.
- Uses a BPF map to share the configured port with the kernel program.
- Passes packets that do not match the filtering rule.

## Requirements

- Linux with XDP and eBPF support
- Clang/LLVM
- libbpf
- libelf
- GCC
- Make

## Build

```bash
make
```

## Usage

Run the program on your network interface using the default port (4040):

```bash
sudo ./loader wlan0
```

Replace `wlan0` with your actual network interface name. Find it using:

```bash
ip -br link
```

To specify a custom TCP destination port, such as 8080:

```bash
sudo ./loader wlan0 8080
```

## How It Works

1. The userspace loader opens and loads the compiled eBPF program.
2. The loader stores the selected port in a BPF map.
3. The XDP program examines incoming packets on the selected interface.
4. If an incoming IPv4 TCP packet has the configured destination port, the program drops it.
5. Packets that do not match the filtering rule are passed through.

## Limitations

- Filters incoming IPv4 TCP packets only.
- Does not filter IPv6 or UDP traffic.
- Requires appropriate privileges and kernel support for XDP.
- XDP support depends on the network interface and its driver.

## Cleanup

Press `Ctrl+C` in the loader terminal to detach the XDP program.
