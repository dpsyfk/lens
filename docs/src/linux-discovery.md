# Linux eBPF discovery

Lens release builds for Linux include an optional metadata-only eBPF probe. It improves short-lived connection identity correlation; it is not packet capture, TLS interception, transparent redirection, or a replacement for the explicit proxy.

## Enable an explicit scope

```sh
lens doctor --check discovery
sudo lens run --ebpf-cgroup /sys/fs/cgroup --listen 127.0.0.1:8888
```

Use the narrowest cgroup v2 directory containing the development processes you intend to observe. Attaching eBPF normally requires root or the relevant Linux capabilities. Lens never attempts to elevate itself, change cgroup membership, mount filesystems, or persist/pin a program.

The probe observes outbound TCP connection tuples, PID, numeric UID, kernel timestamp, and the bounded process name. Payload bytes, command lines, environment variables, files, DNS contents, and credentials are not accessed. Numeric UID is used only in the discovery record and is not copied into normal flow exports.

Connect hooks remember the process against the kernel socket cookie. A socket-operations hook emits the completed local and remote tuple through a bounded ring buffer. Lens consumes the newest exact local tuple match; ambiguous or missing records fall back to the portable process resolver. Lens's own PID is excluded. Kernel links and maps are owned by the process and detach when the session exits or crashes.

## Requirements and limitations

- Linux with cgroup v2 and ring-buffer-capable eBPF support (normally kernel 5.8 or newer).
- Permission to load and attach cgroup BPF programs.
- A Linux binary built with the `ebpf` feature. Official Linux release automation enables it; source builds use `cargo build -p lens-cli --release --features ebpf` and require Clang with the BPF target.
- Only outbound TCP identity discovery is implemented. UDP, DNS attribution, Kubernetes metadata, and kernel-level payload collection are outside this milestone.

If the verifier rejects the probe or the cgroup cannot be opened, Lens fails the requested discovery-enabled startup with a clear diagnostic. Run without `--ebpf-cgroup` to retain the fully rootless portable path.
