# Boot protocol: the kernel image and the user payload

The kernel image and the user payload are separate artifacts. The kernel
binary carries the trusted root keys and nothing of the selected boot
programs; the payload is one file, `helios-bootfs`, produced by
`helios-cli kernel-prebuild` beside `kernel-prebuild.json`. Changing the
boot-program selection rewrites the payload and never recompiles the
kernel.

## The payload file

`helios-bootfs` is the format `artifact/src/bootfs.rs` defines: a fixed
header (magic, version, entry count, string-table and data offsets), an
entry table (kind, path offset/length, data offset/length,
`modified_nanos`), a string table, then the file bytes, every offset
16-byte aligned. The entry table holds every bootfs file and empty
directory plus two distinguished entries: the init component and its
`argv0`. The data section ends exactly where that body ends; a version-2
image is the body followed by a fixed 128-byte signature footer.

The footer holds the magic `HLBFSSIG`, a footer version, the algorithm
(Ed25519), the signer's public key, a 64-byte signature and reserved
zeros. The signature covers `b"helios-bootfs-signature-v1"` followed by
the SHA-256 of the body, so the header is covered too.
`helios-cli kernel-prebuild` signs the finished image once with the
prebuild root key. The init component, the compiler plugin and every
boot program inside it are bare Wasmtime artifacts with no per-artifact
signature trailer: the footer vouches for them as a whole.

The root key never lives in the repository or in an image, and the
inspector's image build enforces the second half: it searches the linked
kernel image for the key's seed and its expanded forms and fails the
build if any is there. A development
build generates it in its own prebuild directory and embeds its public
half in the kernel. A release names its key with `--root-secret-key
<file>` (on `helios-cli kernel-prebuild` and on the inspector's `vm`,
which forwards it): the file is read in place, and the release workflow
writes it from the repository secret `HELIOS_BOOTFS_ROOT_KEY`, the base64
of the 32 raw key bytes, to a file in the runner's temporary directory
and removes it after the upload. The signed payload ships beside the
kernel as the release asset `helios-bootfs-x86-64`, located with
`vm … bootfs-path`.

The kernel reads it with `BootPayload::parse`, the single entry on every
backend. It hashes the body once, verifies the footer against the
trusted root public keys embedded in the kernel image, and only then
parses the shape with `bootfs::Image::parse_signed`, a zero-copy reader
that validates every offset against the slice. The digest stays on the
`BootPayload` for a measurement register to extend. A refusal is a typed
`BootfsError` naming what was wrong: `MissingSignature`,
`UnsupportedSignature`, `UntrustedSigner` (with the signer's and the
trusted keys' fingerprints), `SignatureMismatch`, `TrailingBytes` or a
shape error, and each backend's panic message carries it. A bootfs file
is classified as a precompiled artifact by Wasmtime's own header check,
not by a trailer. A cwasm outside the payload (a file a guest wrote, one
on the host share) still carries the signature trailer and is verified
when it loads against the kernel's compiler-signing key, never against
the trusted roots (`kernel/src/signing_key.rs`).

## How each backend hands it over

- **x86-64 and aarch64** boot the Limine UEFI disk image
  `helios-cli limine-uefi-image` writes. The image places the payload at
  `/boot/helios-bootfs` and the entry's `module_path` names it, so it
  arrives as a Limine module. The backend takes the module whose path
  ends in `helios-bootfs` and panics naming every module present when
  none matches — a kernel without a payload has no init to run.
- **riscv64** boots `-kernel` directly; there is no Limine handoff. QEMU
  delivers the payload as the initrd (`-initrd`), publishes its physical
  range in the device tree's `/chosen` `linux,initrd-start` and
  `linux,initrd-end`, and the backend carves that range out of the
  memory the allocator is primed with before parsing it through the
  identity map.
- **hosted** takes the path on its command line: `helios --bootfs
  <path>`. The file is read once at start-up; absent or malformed is a
  hard error, the same contract the bare-metal paths enforce.

The parsed result is a `BootPayload`, which the backend hands
`RuntimeState::new`. `EmbeddedBootFs`, `EmbeddedBootFile`,
`EmbeddedBootDirectory`, `EmbeddedComponent` and `EmbeddedInit` stay the
kernel's view types — they are views over the payload image now instead
of generated statics.

## Bootloader splash and early framebuffer panic console

On `x86-64` and `aarch64`, `helios-cli limine-uefi-image` rasterises the
Helios emblem from `docs/logo.svg` in memory (`cli/src/splash.rs`) as a
360×360 RGB8 PNG on `#FFFFFF` and writes it to `/boot/limine/splash.png`
inside the FAT32 ESP alongside `limine.conf` — no binary image is committed
to the repository. `cli/templates/limine.conf` configures Limine with
`timeout: 0`, `verbose: no`, `terse: yes`, `wallpaper:
boot():/boot/limine/splash.png`, `wallpaper_style: centered`,
`backdrop: ffffff`, and a transparent zero-margin terminal overlay so the
splash appears immediately whenever firmware exposes a linear GOP
framebuffer, while headless boots with no framebuffer automatically fall
back to UEFI serial output and `measured_boot: yes` continues extending
TPM PCR 9.

Both Limine backends advertise the framebuffer and flanterm-init-params
requests so Limine preserves the rendered splash pixels across kernel
handoff instead of clearing the screen to black, and maps the framebuffer
writable in the higher-half direct map (reserved out of usable RAM and
outside any PAT/MAIR slot the backends reconfigure). Each backend hands
`Option<BootFramebuffer>` (`hal/src/boot.rs`) to
`helios_kernel::attach_panic_framebuffer` right after reading the Limine
handoff without touching any pixel during normal bring-up. If the kernel
panics before a native display driver comes online, `PanicConsole`
(`kernel/src/io/panic_console.rs`) renders the panic report onto the
linear framebuffer alongside serial output using pure integer bitmap
glyphs (zero heap allocation, zero floating-point or vector instructions).
Once `install_display_device` brings `virtio-gpu` under kernel ownership,
it calls `detach_panic_framebuffer` so post-handoff panics never write to
stale firmware GOP memory.

## Booting a CI-built artifact without a rebuild

CI uploads three tiers of prebuilt artifacts on demand — only for the lanes a
run already builds — each carrying a typed `manifest.json` and never any root
secret key:

- **Userspace** (`helios-wasm-{profile}`): architecture-independent guest wasm
  built by `wasm-debug` / `wasm-release`, kept 14 days.
- **Kernel** (`helios-kernel-{arch}-{profile}`): built kernel ELF and its
  embedded `helios-root-public.key`, kept 90 days on the release smoke lanes
  and 14 days on other lanes (`release-linux`, `debug`, `debug-cfi`).
- **Full bootable image** (`helios-image-{arch}-{profile}`): kernel ELF,
  signed `helios-bootfs`, `helios-root-public.key`, prebuilt Limine UEFI disk
  image `kernel.uefi.img` on `x86-64` and `aarch64`, and `compiler_plugin.wasm`
  when built with the compiler plugin; kept 90 days on the release smoke lanes
  and 14 days on other lanes.

`helios-cli artifact-fetch` downloads any tier from the latest green CI run
matching the current `HEAD` (falling back to the default branch, preferring
`release` over `debug` unless `--profile` is specified) into the shared local
cache, and `helios vm --prebuilt` wires it directly into a boot:

```bash
# Boot the latest green full image directly (zero local compilation, no Limine needed)
helios vm --arch x86-64 --prebuilt shell -c 'echo ok'

# Reuse prebuilt guest wasm while building only the local kernel and bootfs
helios vm --arch x86-64 --prebuilt userspace shell -c 'echo ok'

# Fetch a specific tier explicitly (or inspect its cached path as JSON)
helios-cli artifact-fetch --kind image --arch aarch64 --json

# Boot an already-downloaded prebuilt image directory offline (zero network)
helios vm --arch aarch64 --release --prebuilt image --prebuilt-dir /path/to/image shell -c 'echo ok'
```

`--prebuilt kernel` requires either a `--bootfs` signed by the prebuilt
kernel's embedded `helios-root-public.key` or a matching `--root-secret-key`;
the inspector checks key compatibility before launching QEMU and fails fast on
a mismatch.
