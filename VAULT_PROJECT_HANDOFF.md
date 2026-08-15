# Encrypted Vault File Explorer — Project Handoff

**Status:** Pre-implementation. Research and architecture decisions complete; no code written yet.
**Date of handoff:** 2026-08-15
**Purpose of this document:** Give a fresh session everything needed to begin development without relitigating decisions already made. Read it end to end before writing code.

---

## 1. What we are building

A single portable executable that acts as a **gateway to an encrypted directory tree**.

- The executable sits in a directory. Every file in that directory and its subdirectories is encrypted at rest.
- Running the executable, and authenticating, presents a **file-explorer UI** over the decrypted view of that tree.
- Without the executable and the passphrase, the directory is opaque on disk.
- Design goals, in priority order: **correctness of the crypto**, **no data loss**, **launches everywhere**, **lightweight binary**.

Think Cryptomator or gocryptfs, but self-contained and portable, with its own browsing UI instead of mounting a filesystem.

### Non-goals (explicitly out of scope for v1)

- Mounting a virtual filesystem (FUSE / WinFsp / macFUSE). See §9 for why this is the eventual right answer and why we are deferring it.
- Cloud sync, multi-user, key sharing, or any network functionality.
- Desktop integration: MIME associations, trash, thumbnails, D-Bus, mount management.
- Hiding file sizes, directory shape, or modification times. See §6.4.
- Plausible deniability or hidden volumes.

---

## 2. Decisions already made — do not relitigate

These were reached after a lengthy research conversation. Each is recorded with its reasoning so a future session can *revise* them on new evidence, but should not re-derive them from scratch.

### 2.1 GUI toolkit: **Iced with the `tiny-skia` renderer, wgpu compiled out entirely**

**Decision.** Use `iced` 0.14 with default features disabled and `tiny-skia` enabled *instead of* `wgpu` — not the fallback configuration, but with the GPU code path absent from the binary.

**Why.** The requirement is that the tool launches on any machine without shipping a graphics driver alongside it. Every GPU-backed option fails this:

- `iced_tiny_skia` is a pure-Rust CPU rasterizer writing pixels through `softbuffer`. There is no graphics driver dependency and nothing to fail at startup. It is a first-class, actively maintained backend (`iced_tiny_skia` 0.14, >1.2M downloads), not a toy.
- Smaller binary than the wgpu path, which serves the lightweight goal.

**Why not egui.** egui was the initial candidate and was rejected only after establishing the following:

- As of eframe 0.35, **eframe defaults to wgpu**, with glow as an opt-in (`glow` feature + `NativeOptions::renderer = Renderer::Glow`).
- **`egui_glow` does not solve the driver problem.** glow is just OpenGL bindings; it still requires the OS to provide a working GL 3.3 context. This was an error made mid-conversation and later corrected — do not reintroduce it.
  - *Linux:* glow helps. Mesa's llvmpipe provides software GL automatically.
  - *Windows:* glow is **worse** than wgpu. With no vendor GL driver you fall back to GDI Generic OpenGL 1.1, insufficient for `egui_glow`. Meanwhile wgpu on DX12 has WARP, Microsoft's software rasterizer, which ships with the OS.
  - *macOS:* both work; neither has a software fallback if they don't.
- egui has **no maintained CPU rendering backend**. Details in §2.2 — this is the single strongest reason.

**Trade-off accepted.** Iced's Elm architecture is more ceremony than egui's immediate mode for a file browser, and Iced describes itself as experimental software with fast-moving breaking APIs. We accept this in exchange for guaranteed startup.

**Revisit this if** the "runs anywhere with no driver" requirement is relaxed. If ordinary desktop users are the whole audience, egui + wgpu-on-WARP covers essentially all of them with a nicer development experience.

### 2.2 Why egui has no CPU renderer (context, so this isn't re-researched)

epaint tessellates shapes into **indexed triangle meshes** with per-vertex color and UVs into a font atlas, with anti-aliasing baked in as "feathered" geometry. Rendering that on CPU requires a `drawVertices`-style API.

- **Skia has `drawVertices`** — which is why `egui_skia` exists and works. But it is stale: last release 0.4.0, October 2023, ~egui 0.23. The author states he no longer uses it. The `smol_egui_skia` fork tracks egui 0.29 but is explicitly image-rasterization only, not interactive.
- **tiny-skia does not.** Its API is `fill_path` / `stroke_path` / `fill_rect` / `draw_pixmap` with shaders. No mesh primitive. This is why egui issue #3367 ("tiny-skia as renderer") was closed with no implementation, and why the same limitation applies to `vello_cpu`.
- **Iced does not have this problem** because its renderer abstraction sits at the *semantic primitive* level (quads with backgrounds, paths, text, layers, transforms), which maps directly onto tiny-skia's API.
- egui issue #1129 ("epaint software renderer") has been open with a `feature` label since January 2022. A contributor attempted one for `egui_kittest` and reported it "didn't work as well as I hoped"; the project fell back to wgpu-on-lavapipe for CI.

### 2.3 Crypto: do not invent the file format

Use the RustCrypto `aead::stream` STREAM construction. Rationale and full spec in §5.

---

## 3. Technology stack

```toml
[dependencies]
iced = { version = "0.14", default-features = false, features = [
    "tiny-skia",   # CPU renderer — NOT "wgpu"
    "x11",
    "wayland",
    "tokio",       # or "smol"; pick one, see §7.3
    "image",       # only if rendering thumbnails/previews in-app
] }

# Crypto
chacha20poly1305 = "0.10"   # XChaCha20-Poly1305 AEAD
aead             = { version = "0.5", features = ["stream"] }
argon2           = "0.5"    # Argon2id KDF
aes-siv          = "0.7"    # deterministic filename encryption (see §5.3)
zeroize          = { version = "1", features = ["zeroize_derive"] }
rand             = "0.8"    # OsRng only

# Filesystem / misc
walkdir   = "2"
tempfile  = "3"
```

**Verify all versions before use.** Some were confirmed during research (iced 0.14, iced_aw 0.14.1 released 2026-04-27, iced-swdir-tree 0.2 targets iced 0.14); crypto crate versions were not, and RustCrypto pins move.

### Candidate UI helper crates

| Crate | Purpose | Status |
|---|---|---|
| `iced-swdir-tree` 0.2 | Directory tree widget: lazy expand, per-path selection persistence, non-blocking traversal via `Task::perform`, three display filters, optional lucide icon font | Targets iced 0.14. **Strong candidate** — the lazy-expand model matches our need to avoid decrypting unopened subtrees. Needs evaluation against a *virtual* path source rather than the real FS. |
| `modav_widgets` | Table and tree view widgets | Reported as high quality by the unofficial Iced guide. Verify iced 0.14 compatibility. |
| `iced_aw` 0.14.1 | Menus (+ `quad` for separators), cards, sidebar, selection_list, badges | Feature-gated; enable only what's used. |
| `rfd` | Native file dialogs | **Boundary use only** — importing plaintext in, exporting out. Never for browsing inside the vault; native dialogs show the OS view, i.e. encrypted filenames. |

### Core `iced::widget` items that matter here

- `lazy` — takes a data dependency and a closure producing a widget tree. Essential to avoid rebuilding thousands of file rows per frame.
- `keyed::Column` — continuity hints when the list reorders on sort.
- `pop` — fires messages when content enters/leaves view. **More important here than in a normal file manager**: every displayed metadata field may cost a decryption, so defer per-row work to visible rows.
- `pane_grid` (dual pane), `scrollable`, `grid`.

---

## 4. Reference implementation: COSMIC Files

`https://github.com/pop-os/cosmic-files` — System76's file manager, the default on Pop!_OS 24.04+. Built on `libcosmic`, an iced-based toolkit.

**Caveat:** libcosmic is a *soft fork* of Iced, not vanilla Iced. Code cannot be copied directly. The architecture translates; the API calls will not. **Check the license before lifting any code — this was not verified during research.**

Also note cosmic-files is described as pre-alpha software.

### What to take from it

**`Location` enum** (in `src/tab.rs`). Covers `Path`, `Trash`, `Network`, `Desktop`, `Search`, `Recents`. This is the abstraction we need: it generalizes "where am I" beyond a bare `PathBuf`. Our version needs a virtual-path variant, because the explorer browses a decrypted namespace layered over the real filesystem, not the filesystem itself. **Getting this right on day one is the difference between a clean design and `PathBuf` special-cases smeared through every function.**

**Operation system** (`src/operation/mod.rs`). Operations run on dedicated threads for async I/O, with a `Controller` providing pause / resume / cancel and progress tracking; queued in `pending_operations`, moved to `complete_operations` on finish. Bulk encrypt/decrypt of a tree is exactly this shape — long-running, needs progress, needs cancellation, must never block the UI.

**Component split.** `App` (orchestration, windows, message routing) → `Tab` (browsing, item display, selection, history) → `Dialog` (rename, confirm, progress) → `Operation` (async work) → `Config` (persisted settings).

### What to ignore from it

MIME app associations from `.desktop` files, GVFS volume mounting, freedesktop thumbnail spec caching, D-Bus `FileManager1` interface, trash integration, archive handling, i18n infrastructure. That is most of its bulk and all of it serves "be a desktop-integrated file manager," which is the opposite of our lightweight goal.

---

## 5. Vault format specification (draft — needs review before freezing)

**This section is the highest-risk part of the project. Changing it after users have data is extremely painful. Get it reviewed before writing files.**

### 5.1 Key derivation

- Passphrase → **Argon2id**. Not PBKDF2, not raw SHA-256.
- Random 16-byte salt, generated with `OsRng`, stored in the vault header.
- Parameters stored in the header so they can be raised later without breaking old vaults.
- Derive a master key; derive subkeys from it (content key, filename key) via HKDF rather than reusing the master directly.
- **`zeroize` every key on drop.** Derive the `Zeroize`/`ZeroizeOnDrop` traits on key-holding structs.

### 5.2 File content encryption

- **XChaCha20-Poly1305** via the `aead::stream` STREAM construction, 64 KiB chunks.
- STREAM gives us, for free and correctly: streaming encryption without holding files in RAM, per-chunk authentication, correct per-chunk nonce derivation, and last-chunk marking so **truncation attacks fail**.
- **Do not hand-roll the chunking.** Manual chunking is where nonce reuse gets introduced.
- Alternative worth evaluating: the `age` format via the `rage` crate — well-specified, reviewed, and removes format design from our plate entirely. Evaluate this before committing to a bespoke format.

### 5.3 Filenames — the hard design problem

The explorer shows readable names, so names must be recoverable. Two viable approaches:

**(a) Deterministic filename encryption (recommended for v1).** AES-SIV over the filename with a dedicated subkey, base32-encoded for filesystem safety. Roughly Cryptomator's approach.
- Pros: no index to corrupt, stable across runs, no single point of failure, listing a directory is just `readdir` + decrypt each name.
- Cons: leaks name lengths and directory structure. Identical names in different directories produce identical ciphertext unless the parent directory ID is mixed into the SIV associated data — **do mix it in**.

**(b) Encrypted manifest / index.** A single encrypted file mapping virtual paths to on-disk names.
- Pros: faster listing, hides structure and name lengths.
- Cons: single point of catastrophic failure; every mutation requires atomic-write discipline and crash recovery; concurrent access becomes a real problem.

Study how **gocryptfs** and **Cryptomator** solved this. Both have public design docs and have been through security audits. Do not design this from first principles.

### 5.4 On-disk layout

```
<vault dir>/
  vault.exe              # the executable — MUST be excluded from encryption
  .vault-header          # salt, KDF params, format version, key check value
                         #   — MUST be excluded from encryption
  <base32 name>          # encrypted file
  <base32 name>/         # encrypted directory
    <base32 name>
```

- Include a **format version** in the header from v1. Non-negotiable.
- Include a **key check value** so a wrong passphrase fails fast with a clear message rather than producing garbage.

### 5.5 Atomicity — non-negotiable

Every write: **temp file in the same directory → write → fsync → rename over target.** A crash midway through encrypting a file must never destroy that file. Same-directory temp matters because `rename` is only atomic within a filesystem.

Consider a journal or `.partial` marker for multi-file operations so an interrupted bulk encrypt can be resumed or rolled back rather than leaving the vault half-converted.

---

## 6. Security notes

### 6.1 Locating the vault

Use `std::env::current_exe()`, then canonicalize. **Not `current_dir()`** — they diverge constantly, and the difference is "encrypts the right folder" versus "encrypts whatever directory the user happened to launch from."

Explicitly exclude the executable itself and `.vault-header` from encryption, or the program eats itself on first run.

### 6.2 The "open a file" problem — no clean answer

The moment a user double-clicks a PDF, we either built a PDF viewer or we wrote plaintext to disk.

- **v1 approach:** in-app viewers for text and images; everything else goes to a temp file with restrictive permissions, deleted on close.
- **Be honest in the UI and docs** that temp-file extraction is imperfect. On SSDs, "secure delete" is largely fiction due to wear leveling. Do not imply protection we don't provide.
- **The real solution is a virtual filesystem** (FUSE / WinFsp / macFUSE), which is what the mature tools do. That is a much larger project. Deferred, but this is the fork in the road — architect so the vault layer is independent of the UI, in case a VFS front end is added later.

### 6.3 Performance reality check

Crypto is not the bottleneck. AES-GCM with AES-NI runs at multiple GB/s; XChaCha20 is fast without hardware AES. We will be I/O-bound long before CPU-bound.

The efficiency work that actually matters: **do not decrypt file contents just to render a directory listing.** Listing should only require decrypting filenames. This constrains what metadata can be shown cheaply — plan the UI around it.

### 6.4 What leaks regardless (document these for users)

File sizes, file count, directory tree shape, and modification times are all visible to anyone with the drive. Fine for most threat models. Be clear in our own heads — and in the README — which threat model we're defending against.

### 6.5 Consider not building this

Worth stating once for the record: VeraCrypt, Cryptomator, and gocryptfs already exist, are audited, and solve this problem. If the goal is "my files are encrypted at rest," use one of those. If the goal is a portable self-contained vault with a custom UI, or the project is a learning exercise, proceed — but with the humility that the format design in §5 is where audited tools earned their reputation.

---

## 7. Application architecture

### 7.1 Layering

```
┌─────────────────────────────────────┐
│ UI (iced)                           │  App / Tab / Dialog / view fns
├─────────────────────────────────────┤
│ Operations                          │  async encrypt/decrypt/move/rename
│   + Controller (pause/cancel/prog)  │
├─────────────────────────────────────┤
│ Vault                               │  VirtualPath, listing, open/create,
│   (UI-independent, testable)        │  filename codec, atomic writes
├─────────────────────────────────────┤
│ Crypto                              │  KDF, STREAM AEAD, key management
└─────────────────────────────────────┘
```

**The Vault layer must not depend on iced.** It should be usable from a CLI and from unit tests. This also keeps the door open for a FUSE front end later (§6.2).

### 7.2 Suggested module layout

```
src/
  main.rs            # entry; locate vault dir, run unlock flow, launch app
  crypto/
    kdf.rs           # Argon2id, key derivation, zeroize
    stream.rs        # STREAM encrypt/decrypt readers & writers
    names.rs         # filename encode/decode (AES-SIV + base32)
  vault/
    mod.rs           # Vault handle, unlock/lock
    header.rs        # .vault-header read/write, format version
    path.rs          # VirtualPath type
    fs.rs            # listing, atomic write, temp handling
  ops/
    mod.rs           # Operation enum, Controller, progress
    encrypt.rs
    decrypt.rs
    recursive.rs
  ui/
    app.rs           # App state, update(), Message
    tab.rs           # Tab, Location, listing view, selection
    dialog.rs        # unlock, rename, confirm, progress
    viewer.rs        # in-app text/image preview
```

### 7.3 Async executor

Pick one and enable the matching iced feature (`tokio` or `smol`). `iced-swdir-tree` supports plugging in your own executor via `with_executor`, so match whatever we choose. Note cosmic-files uses `compio` for completion-based I/O (io_uring/IOCP) — overkill for v1, but the reason it's there is worth understanding if I/O throughput becomes a problem.

**Rule: no filesystem or crypto work on the UI thread, ever.** All of it goes through `Task::perform` or a worker channel.

---

## 8. Suggested milestones

1. **Crypto core, headless.** STREAM encrypt/decrypt round-trip on a byte stream. Property tests: round-trip fidelity, tamper detection, truncation detection. No UI.
2. **Vault layer, headless.** Header read/write, filename codec, atomic writes, directory listing. CLI harness to init a vault, encrypt a tree, list it, decrypt a file. **Fuzz/crash-test the atomicity here** — kill the process mid-operation and verify no data loss.
3. **Iced shell.** Window, unlock dialog, static listing of a hardcoded directory. Confirm `tiny-skia`-only build works and the binary has no wgpu in it (`cargo tree` to verify).
4. **Browsing.** Wire `Location` + `Tab`, navigation, history, sorting. Evaluate `iced-swdir-tree` against the virtual path source here — adopt or write our own.
5. **Operations.** Encrypt/decrypt with progress, pause, cancel. Bulk directory conversion.
6. **Viewers.** In-app text and image preview; temp-file fallback with the caveats from §6.2.
7. **Hardening.** Wrong-passphrase handling, corrupt-file handling, concurrent-instance detection, zeroization audit.

Milestones 1 and 2 are where the project succeeds or fails. Resist the urge to start at 3 because it's more visible.

---

## 9. Open questions for the next session

1. **`age`/`rage` versus a bespoke STREAM format** — evaluate before freezing §5.2. Using an existing reviewed format is a significant risk reduction.
2. **Filename scheme (a) versus (b)** in §5.3 — needs a decision. Recommend (a) for v1.
3. **`iced-swdir-tree` fit** — it's built on `swdir::scan_dir` against the real filesystem. Determine whether it can be driven from a virtual listing or whether we write our own tree widget.
4. **cosmic-files license** — verify before reading closely enough to be influenced by its code.
5. **Concurrent instances** — two copies of the executable running against one vault. Lockfile? Detect and refuse?
6. **Passphrase change / key rotation** — re-encrypting everything, or a wrapped-master-key design (recommended: wrap a random master key with the passphrase-derived key, so rotation only rewrites the header).
7. **Backup story.** An encrypted vault with a corrupt header is unrecoverable data. What do we tell users?

---

## 10. Verified facts from research (with sources)

These were confirmed during the research conversation and can be relied on without re-checking:

- `eframe` 0.35 defaults to wgpu; glow is opt-in via feature + `NativeOptions::renderer`. Switching to glow reduces binary size. (eframe docs)
- egui issue #1129 (epaint software renderer) — **open**, `feature` label, since Jan 2022.
- egui issue #3367 (tiny-skia as renderer) — **closed**, no implementation.
- `egui_skia` 0.4.0, Oct 2023, last release; author no longer uses it; `cpu_fix` feature required for correct CPU output (a gamma/sRGB issue — egui blends in gamma space and wants sRGB framebuffer conversion off).
- `smol_egui_skia` tracks egui 0.29 but is explicitly not for interactive UI.
- Iced ships `iced_wgpu` and `iced_tiny_skia`; default is wgpu-with-tiny-skia-fallback; `ICED_BACKEND=tiny-skia` forces software at runtime.
- `iced_tiny_skia` unconditionally depends on `softbuffer`, which limits it to winit-supported platforms — **so this is not a path to bare-metal/embedded**, despite being CPU-only.
- tiny-skia's public API has no mesh/`drawVertices` primitive; nor does `vello_cpu`.
- egui/rerun use lavapipe (llvmpipe) for headless CI rendering on all platforms, including a custom static build on macOS.

---

## 11. How to start

Read §2 (decisions), §5 (format), and §7 (architecture) first. Then begin at milestone 1 — the crypto core, headless, with tests. Do not open an iced window until milestones 1 and 2 pass their tests.

If any decision in §2 looks wrong, the reasoning is recorded there; argue against the reasoning rather than re-running the research.
