# Lens Windows WFP driver

This directory contains the first-party kernel component for Windows transparent TCP capture. It is intentionally small: the driver redirects selected outbound connections to the ordinary Lens process and attaches a fixed-width original-destination context. HTTP, TLS, PostgreSQL, redaction, storage, exports, and rendering remain outside the kernel.

## Security boundary

- The control device grants access only to Local System and built-in administrators.
- Every IOCTL uses `METHOD_BUFFERED`, fixed-width records, explicit size checks, and ABI version 1.
- Records contain no user pointers, command lines, credentials, or payload bytes.
- The configured Lens PID is excluded to prevent its upstream sockets from being redirected recursively.
- An unconfigured driver permits traffic. Allocation or redirect failure also permits the original connection and increments the error counter.
- Loading, configuring, or removing the driver always requires an explicit elevated action.

The runtime callouts alone do not affect traffic. `lens run --mode transparent` opens a dynamic WFP engine session, transactionally registers the provider, sublayer, IPv4/IPv6 callouts, and TCP-only filters, then configures the driver. Closing or crashing the Lens process removes the dynamic policy; the driver also remains fail-open when it has no valid configuration.

## Build

Install Visual Studio 2022 with the Desktop C++ workload and the Windows 11 WDK, then run from a Developer PowerShell:

```powershell
msbuild .\LensWfp.sln /p:Configuration=Release /p:Platform=x64
```

The resulting `.sys`, `.inf`, and generated catalog are development artifacts. Do not distribute or install them as a public Lens release until the catalog has passed Microsoft driver signing and the signed package has passed Driver Verifier and clean-machine install/uninstall tests.

## Install and remove a signed package

Use an Administrator terminal and only a Lens package whose catalog signature you have verified. For a locally built test package, use an isolated test-signing VM rather than a daily-use workstation.

```powershell
pnputil.exe /add-driver .\x64\Release\LensWfp\lens-wfp.inf /install
sc.exe start LensWfp
lens doctor --check transparent
lens run --mode transparent --protocol http --listen 127.0.0.1:8888
```

Windows assigns the INF a host-specific published name. Find it with `pnputil.exe /enum-drivers /class NetService`, then remove the exact Lens package:

```powershell
sc.exe stop LensWfp
pnputil.exe /delete-driver oemNN.inf /uninstall
```

Do not guess or copy `oemNN.inf` from another host. Stopping Lens disables the driver session and removes its dynamic WFP filters; uninstalling is only required to remove the driver package.

## ABI changes

`include/lens_wfp_shared.h` mirrors the records in `lens-platform::transparent`. Any binary layout change must increment `LENS_WFP_ABI_VERSION`, retain a clear mismatch diagnostic, and update both sides in the same pull request.
