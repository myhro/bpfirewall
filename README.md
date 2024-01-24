# BPFirewall

A Linux kernel firewall in ~100 lines of C code, powered by [BPF][bpf].

## Dependencies

    $ sudo apt install bpftool build-essential clang libbpf-dev

## Usage

The BPF program needs to be loaded and attached to the `eth0` interface with `make load`.

After that, add a port to be blocked:

    $ sudo ./firewall 8000

Remove a previously blocked port:

    $ sudo ./firewall -8000

## Limitations

- The logic is somewhat inverted compared to a regular firewall: all ports are allowed by default. Each port added to the list will be blocked individually.
- Only handles TCP connections.


[bpf]: https://docs.kernel.org/bpf/
