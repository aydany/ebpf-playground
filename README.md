This repo contains a simple program that shows how use eBPF to capture events of interest in the kernel and deliver them to user space. With a lot more work the program could add enough of functionality to mirror Dependency Agent.

The primary intent behind this has been to learn about eBPF and how to use it to build observability tools. If time allows, my goal is to add more capabilities over time.

The repo is structured following the pattern used by libbpf-bootstrap. It produces portable eBPF code that should work without issued on kernels that support BTF. No attempt has been made to support older systems.

Currently supported:
- process exec and exit
- DNS lookup
- TCP socket state transitions


To build the project:

```
git submodule init
git submodule update
make
```

To run:

```
sudo ./flowmon
```

Open another terminal and run:

```
wget https://www.google.com -O /dev/null
```

You should see something like this:

```
17:42:24 EXEC  wget             5533    29713   /usr/bin/wget
17:42:24 DNS4                   5533    www.google.com [] 142.250.188.36
17:42:24 SOCK4                  5533    4026531992 CLOSE            SYN_SENT         172.29.146.62:0 -> 142.250.188.36:443
17:42:24 SOCK4                  0       4026531992 SYN_SENT         ESTABLISHED      172.29.146.62:39056 -> 142.250.188.36:443
17:42:24 EXIT  wget             5533    29713   [0] (105ms)
17:42:24 SOCK4                  5533    4026531992 ESTABLISHED      FIN_WAIT1        172.29.146.62:39056 -> 142.250.188.36:443
17:42:24 SOCK4                  0       4026531992 FIN_WAIT1        FIN_WAIT2        172.29.146.62:39056 -> 142.250.188.36:443
17:42:24 SOCK4                  0       4026531992 FIN_WAIT2        CLOSE            172.29.146.62:39056 -> 142.250.188.36:443
```

