# fwdonor

Firmware donation drop-box for [zr.ax](https://zr.ax), live at **https://fwdonor.zr.ax**.

1. Visitors drop firmware images (files or folders, up to 512 MiB each) onto the page.
2. The browser classifies each file with the zrax WASM build and dismisses anything zrax doesn't recognize.
3. Recognized images go through a small proof of work and are uploaded in 4 MiB chunks.
4. The server re-classifies them with the **same** zrax commit (`ZRAX_REV`).
5. The server posts each one to Telegram group `-1003917356862` ("fwrepo"; was basic group `-5599544901` before Telegram upgraded it), using a TDLib bot, with a caption holding the zrax metadata and the donor's name.
6. The server keeps a copy of every image it verified in `firmwares/` (see [Stored firmware](#stored-firmware)) and deletes the spooled upload.

The page also shows the corpus live from `/api/stats`: images donated, images per ISA, and a "most wanted" list, all as the current zrax classifies them (unclassified images don't count). That list holds the ISAs zrax's raw-code model can recognize that still have fewer than five images; once every one has five, it shows the ten with the fewest (more on a tie).

The page keeps waiting through server restarts and outages. Each request retries with backoff up to 20 s and never gives up on a transient error. An upload the server lost is sent again from the start. A file that was posted just before a restart is recognized by its hash and marked donated.

## Layout

| Path | What |
|---|---|
| `src/analyze.rs`, `src/policy.rs` | zrax wrapper and the accept rule (mirrored by `web/policy.js`) |
| `src/lib.rs` | zrax verdict, policy lists and proof of work, shared by the server and `fwdonate` |
| `src/bin/fwdonate/` | command-line donation client |
| `src/bulk/` | bulk donations: grants, resumable chunked uploads, the rolling whole-file hash, the store |
| `src/pow.rs`, `web/sha256.js` | file-bound proof of work (shared test vector in both) |
| `pow-wasm/`, `web/pow-wasm.js` | the page's proof-of-work search in WASM with SIMD, 8 nonces per step and about 4× the JS speed; the page falls back to `web/sha256.js` without WASM SIMD |
| `src/uploads.rs`, `src/limits.rs` | chunked upload sessions, per-IP and global limits, spool |
| `src/telegram/` | libtdjson FFI, async client, sequential poster and caption builder |
| `src/ledger.rs` | `runtime/posted.jsonl`, the dedup record of everything posted, plus the corpus statistics |
| `src/firmwares.rs`, `src/telegram/backfill.rs` | the store of every verified donation, and the download of older posts back from the group |
| `src/reclassify.rs`, `src/telegram/caption.rs` | classifying the store again after a zrax update, and the captions (and caption keys) of posts |
| `web/` | the page (vanilla ES modules; zrax's `format.js` and fonts are copied in at build time); `web/corpus.js` is the live statistics panel |
| `src/dashboard/` | the dashboard: the in-memory index of every image (`catalog.rs`), ISA families, firmware or other binaries (`kind.rs`), inspection (entropy, hex, strings), routes, downloads and exports |
| `web/dash.{html,js}`, `web/dash-bulk.{html,js}`, `web/dash-common.js` | the dashboard pages (`/d/<key>`, `/d/<key>/bulk`) |
| `web/bulk.{html,js}`, `web/grant.{html,js}` | the bulk upload page (`/r/<token>`) and the admin page that issues its links (`/g/<key>`); `web/common.js` holds what they share with the main page |
| `scripts/build.sh` | vendor zrax@`ZRAX_REV` → wasm-pack → `dist/` (versioned and precompressed) → `cargo build` |
| `scripts/build-tdlib.sh` | builds `tdlib/lib/libtdjson.so` (same TDLib revision as decidot) |
| `deploy/` | systemd unit, production config, pyx host blocks |

## Donating from the command line

`fwdonate` (src/bin/fwdonate/) does what the page does, for large collections:

1. It takes files and directories, which are searched recursively. Symbolic links inside directories are followed only with `-L`.
2. It classifies each file locally with the server's own zrax code and policy (`src/lib.rs`), so files the server would reject never leave the machine. A rejection would also count towards a ban.
3. It skips files the collection already has, by their SHA-256 (`/api/known`).
4. It solves the proof of work natively and uploads in chunks, two files at a time (the server's per-address limit).
5. It follows each file until it is posted. Like the page, it starts another file only once one of its 2 is posted, so it never has more than 2 files in the Telegram queue and other donors' files don't wait behind a whole collection. `--no-wait` starts the next file as soon as the server has the previous one, which puts everything into the Telegram queue at once.

Transient failures are retried forever, at most 20 s apart. These include the server restarting, limits and pauses. An upload the server lost is sent again. Ctrl-C cancels half-sent uploads; files already with the server still get posted.

```sh
scripts/build.sh                      # vendors zrax at ZRAX_REV, builds everything
target/release/fwdonate -n your_name firmware.bin dumps/ more/
target/release/fwdonate --dry-run ~/firmware   # what would be donated, uploads nothing
cargo install --path . --bin fwdonate --locked # or put it on PATH (after scripts/build.sh)
```

Output is one line per file: `donated`, `known`, `rejected` or `failed`, plus `skipped` with `-v`. A progress line goes to stderr every 15 s.

The exit status is:
- 0 when nothing failed;
- 2 when a file failed or was rejected, or the server stopped accepting this client;
- 130 when interrupted.

`FWDONOR_NAME` and `FWDONOR_SERVER` set the defaults for `-n` and `--server`.

The client has to be built from the same `ZRAX_REV` as the server. After a zrax update, the server keeps accepting the previous build for 7 days, and fwdonate prints a note asking for a rebuild.

## Stored firmware

Every image the server verifies is kept in `firmware_dir` (default `/data/fwdonor/firmwares`) as `<sha256>`, next to `<sha256>.json`.

- **When it's copied:** right after verification and before posting, so an image stays even if posting fails. A copy error is logged, but the donation still goes ahead. The copy goes to a temporary name and is renamed into place, so `<sha256>` is always complete.
- **Why copy, not move:** under the service's sandbox, `spool/`, `runtime/` and `firmwares/` are separate mounts, so a move or hard link between them fails.
- **The record** holds:
  - `name`: the donor name the post credits;
  - `original_name`;
  - `zrax`: the last verdict that accepted the file, with zrax's version;
  - `unclassified`: set when the current zrax rejects the file (see [Reclassification](#reclassification));
  - `checked`: the zrax that last classified the file, and an `error` if it came to no answer;
  - `received_at`;
  - `source`: `upload`, or `telegram` for recovered images;
  - `telegram`: `chat_id`, `message_id`, `posted_at`, added once posted; `shows`, a key of what the caption says, and `edit_failed` when Telegram won't let the post be edited.

  It has no IP address or other trace of the sender.
- **Older posts:** images posted before the store existed are downloaded back from the Telegram group by the bot (`firmware_backfill`, on by default).
  - This runs in the background at every start and skips what the store already has.
  - It fetches each ledger entry by its message id, from the supergroup or, for the first posts, the basic group it was upgraded from. It checks the SHA-256 against the ledger, re-runs zrax for the record, and deletes TDLib's own copy.
  - Progress and anything it couldn't restore go to the journal (`backfill:` lines). Unrestored entries are tried again at the next start.

```sh
ssh root@int journalctl -u fwdonor -g backfill     # progress
ssh root@int 'ls /data/fwdonor/firmwares | grep -vc json'   # images kept
```

### Reclassification

After a zrax update, every stored image is classified again with the new zrax (`src/reclassify.rs`).

- **Trigger:** each record names the zrax that last classified it. At every start, once the dashboard's index is built, the records classified by any other zrax are done again, newest first. Progress lives in the records, so a restart continues where the run stopped. A change to the policy lists alone doesn't start a run, but every run applies the current lists.
- **Pace:** `[reclassify] threads` (3) files at once, on threads at the lowest CPU and I/O priority, and at most `memory_mib` (768) MiB of files in memory. A file zrax needs over 10 minutes for keeps its classification. The whole store (about 54k files, 214 GB) takes about 2 hours.
- **Outcomes:**
  - **Accepted:** the record, the dashboards and the statistics take the new classification.
  - **Rejected** ("unclassified"): the file stays on disk and its record keeps the last classification that accepted it. It disappears from both dashboards, downloads and the main page's statistics, but still counts as already donated. A later zrax that accepts it brings it back.
  - **No answer** (zrax crashed or timed out, the file couldn't be read): the record stays as it was until the next zrax update.
  - **A crash:** `runtime/reclassify.inflight` lists the files being classified. Any still listed after an unclean exit are left as they were, so a file that takes the process down can't do it again at every start.
- **Posts:** the poster edits the caption when what it says would change: format, variant, ISA, bits, byte order, slices or metadata. A different confidence or zrax version alone doesn't count. An unclassified file's post says "no longer classified by zrax …: <reason>", keeps the earlier classification on one line, and is tagged `#unclassified` instead of its ISA and format.
  - Edits share the poster's pace (one Telegram action every 3 s). New donations go first; while both wait, every fifth turn is an edit.
  - Before editing, the bot fetches the post and checks it is this file's post and that Telegram allows the edit. Posts from before the group became a supergroup (432 of them) can't be edited and are noted as such (`edit_failed`). Posts recovered by the backfill still show the zrax they were posted with until their classification next changes.
  - A flood wait pauses edits only; posts continue.
- **Watching it:** the private dashboard shows the run ("reclassify" in the totals: done, changed, unclassified, restored, posts to edit), and the journal has `reclassify:` lines every minute.
- **Off switch:** `[reclassify] enabled = false`, for example before rolling back to an older zrax, which would otherwise classify everything again and edit the posts back.

```sh
ssh root@int journalctl -u fwdonor -g reclassify    # progress
ssh root@int journalctl -u fwdonor -g 'edited the caption' | wc -l
```

## Bulk donations

Some donors have images far too large for the Telegram pipeline (tens of GB each). Bulk links take those out of band. The files stay on this server, and zrax is not involved.

- **Issuing links.** The admin page `/g/<admin key>` issues the links.
  - The key is created in `runtime/admin.key` when the server first starts. `fwdonor admin-url` prints the page's URL (`public_url` in `fwdonor.toml`).
  - Each link `/r/<token>` has a fixed donor name and a storage ceiling, both set when it is issued (stored in `runtime/bulk-grants.json`).
  - The admin page lists every link with its usage and can revoke one. Revoking stops further uploads and discards the link's unfinished uploads; stored files stay.
- **The upload page.** The link's page shows the donor name (filled in and disabled) and a bar of the storage used, reserved by unfinished uploads, and free. It also shows a transfer panel: totals, current and average speed, time left, a throughput graph and an activity log. Each file gets a chunk map. It shows no corpus statistics and loads no zrax.
- **Storage.** Files go to `bulk.dir` (default `/data/fwdonor/bulk`) as `<sha256>`, next to `<sha256>.json`. The record holds the link's token and name, the original file name and path, and the uploader's address (every address, if chunks came from several).
  - A file the store already has is not stored again and doesn't count against the ceiling.
  - `runtime/bulk.jsonl` lists every stored file, for the totals.
- **Uploads.**
  - Files go up in 8 MiB chunks, several in parallel. The number of parallel chunks adapts to how fast they get through.
  - Each chunk carries its SHA-256; the server checks it before writing the chunk into place.
  - The server hashes the whole file as the chunks arrive, following the received part of it, so a 50 GB file is stored a moment after its last chunk.
  - A file's full size is reserved against the ceiling while it uploads.
- **Resuming.**
  - Unfinished uploads are kept in `bulk/.partial/` for `bulk.partial_ttl_days` (14) days, across restarts of the server.
  - When the same file is dropped on the page again, the server resumes the matching upload. The page first checks a few chunks against the server's hashes, so a different file with the same name starts over instead.
  - Requests are retried forever, at most 20 s apart.
- **Durability.**
  - The hash state is checkpointed (`hash.state`) every GiB, when idle, and at shutdown, after the data and the chunk log are fsynced.
  - After a crash, chunks past the checkpoint are hashed again as they are read. One that doesn't match what was received (a write lost to a power failure) is dropped, and the page sends it again.
- **Deploys.** Bulk uploads don't count as activity for `deploy.sh`: a restart costs them at most the chunks in flight. `/api/health` reports `bulk_unfinished` and `bulk_active` separately.
- **Limits** (`[bulk]` in `fwdonor.toml`):
  - 16 chunks in flight per link and 64 in total.
  - Uploads are refused while free disk would drop below `bulk.min_free_bytes` (200 GiB) once every unfinished upload completes.

```sh
ssh root@int /data/fwdonor/target/release/fwdonor --config /data/fwdonor/fwdonor.toml admin-url
ssh root@int ls -la /data/fwdonor/bulk      # stored files and their .json records
```

## Dashboard

A private, read-only view of everything donated: `/d/<dashboard key>` for the firmware, `/d/<dashboard key>/bulk` for bulk uploads.

- **Access.** The key is created in `runtime/dashboard.key` when the server first starts. It is a different key from the bulk admin key, so the dashboard can be shared without the power to issue links. `fwdonor dashboard-url` prints the URL. A wrong key gets 404.
- **Privacy.** No answer contains an address, a bulk link's token or its admin note.
  - A bulk link appears by name, with an 8-digit id (a hash of its token).
  - Donations in progress appear without their session ids.
- **The index.** One row per image:
  - from `runtime/posted.jsonl`, which lists every post, including those not yet back in the store;
  - and from the store's records, which hold everything zrax found.
  - It is built in the background at startup (about 0.2 s for 20,000 images) and follows every record written and every post.
  - Filtering, facet counts, the tree and sorting are one pass over it in memory, on the server.
- **Kinds.** Each image is firmware, or one of the other binaries people donate too: a program, a shared library, an object file or a software package. Everything is still accepted and posted; the dashboard only keeps them apart (`src/dashboard/kind.rs`, from the file's headers, zrax's format and the name):
  - **ELF:**
    - relocatable files are object files;
    - files with an interpreter (`PT_INTERP`) are programs;
    - shared objects (`PT_DYNAMIC` plus a `.so`/`lib…` name, `DT_NEEDED` or `DT_SONAME`) are libraries, except Qualcomm split and signed images (`.mdt`, `.bNN`, `.mbn`), whose TrustZone applications are shared objects too;
    - files with a GNU, Android or BSD ABI tag are programs;
    - the rest is firmware. The OS/ABI byte is ignored: some firmware declares Linux.
  - **PE:**
    - EFI drivers are firmware;
    - EFI applications (boot loaders, UEFI shell tools) are programs;
    - other subsystems are programs or DLLs;
    - plain DOS executables are programs.
  - **Mach-O:** dynamically linked executables are programs, dylibs and bundles are libraries, and static executables are firmware.
  - **Other formats:**
    - DEX, PEF, NE/LE/LX, Xbox, Switch, WebAssembly, Java classes, a.out and other OS formats are programs;
    - RPMs, APK/IPA/JAR archives and OLE compound files (Windows Installer packages, by root class or name) are packages.
  - **Images not in the store** are judged by name.
- **Firmware view:**
  - **Scope:** firmware (the default), other binaries, or all. A URL without `kind` shows firmware; `kind=all` shows everything. The kind is also a facet, a column, a tree level and a matrix dimension, and the detail panel says why.
  - **Totals:**
    - store coverage, with images not in the store yet and failed recoveries (both clickable);
    - backfill progress and rate;
    - reclassification progress, posts still to edit, and how many images are hidden as unclassified;
    - the last 24 h and hour;
    - donors, ISAs and formats;
    - ISAs nobody has donated yet;
    - donations arriving right now, the posting queue, and free disk.
  - **Tree:** keyed by ISA family › ISA › format by default. The levels can be any dimensions, for example donor › ISA, kind › ISA or month › day. Clicking a node filters to its whole path, and only that path is highlighted.
    - Count files or bytes.
    - Count every ISA a file contains (slices included), or only its primary one.
  - **Facets:** kind, donor, format, status, origin, bits, endianness, extension, zrax source, accept basis, variant and zrax version. Click to keep only those, alt-click to leave them out.
  - **Charts:** received over time, size (log₂ buckets) and confidence. Drag across a chart to filter to that range.
  - **Matrix:** any two dimensions, ISA × format by default.
  - **Search:** names, donors, formats, ISAs and metadata values. Six or more hex digits also match SHA-256 prefixes.
  - **Table:**
    - choose columns;
    - sort by any of them (shift-click adds a second key);
    - 50 to 500 rows per page;
    - select rows to copy their hashes or save them as CSV, sha256sum or rsync lists.
  - **Detail panel:**
    - every field of the record, its slices, metadata and Telegram post, and files with the same name;
    - an entropy profile with the slices drawn under it;
    - the first 1 KiB as hex, and printable strings from the first 4 MiB;
    - a download link and the path on the server.
  - **Navigation:**
    - The URL hash keeps the filters, sort, page, tree and open file.
    - Keys: `/` search, `j`/`k` move, Enter open, `[` `]` page or file, `x` select, `L` live, `?` help.
    - UTC or local time.
- **Bulk view:**
  - links with their quota bars (used and reserved);
  - uploads in progress with a chunk map, hashing progress, speed, time left and a stalled flag;
  - every stored bulk file as a tree of link › folder and a sortable table with how long it took and the average speed.
- **Downloads:** firmware and bulk files alike, as attachments with their original names.
  - They support Range requests, so `curl -C -` resumes them. Proxied response bodies aren't cut off by pyx's 120 s limit, which only covers the time until the headers.
- **Exports:** everything the filters match, in their order: CSV, NDJSON (with the full records), `sha256sum` lists (names as stored) and rsync file lists.
- **Public dashboard** at `/dashboard`, linked from the donation page. It is the same firmware view without a key and without anything operational:
  - **Left out:** bulk uploads, origin (uploaded or recovered), store status and backfill, donations in progress, server paths and disk space. Those dimensions can't be filtered, sorted or grouped by either.
  - **Rows:** they say only whether a file can be downloaded (`stored`).
  - **API:** `/api/dashboard/…`. Exports are CSV, NDJSON (one at a time) and sha256sum, without rsync lists. Queries run at most four at a time, and the summary is cached for 2 s.
  - **Downloads** need a proof of work bound to the file. It is as much work as one solution `pow.download_extra_bits` (6) bits harder than an upload's (26 bits by default), split into 16 solutions of 22 bits.
    - That costs the same on average but takes a steady time; one big proof is pure luck.
    - The page finds the solutions on all cores at once (`web/pow-pool-worker.js`): about 0.3 s on a 16-core Mac, about 1.2 s on 4 cores.
    - Scripts use `GET /api/dashboard/challenge` (`bits`, `proofs`), then `GET /api/dashboard/files/<sha256>/download?token=…&nonces=n1,n2,…` with the nonces in increasing order.
    - A proof stays valid for its file until the token expires (`pow.ttl_secs`), so `curl -C -` can resume.

For example, on the private dashboard:

```sh
ssh root@int /data/fwdonor/target/release/fwdonor --config /data/fwdonor/fwdonor.toml dashboard-url
rsync -a --files-from=fwdonor-firmware-2026-11-03.files.txt root@int:/data/fwdonor/firmwares/ ./firmwares/
(cd firmwares && sha256sum -c ../fwdonor-firmware-2026-11-03.sha256)
```

## Accept rule

A file is accepted if zrax resolves a concrete ISA, or if its format is on the firmware allowlist.

- A heuristic ISA guess must have at least 50% confidence.
- Formats on the deny list are rejected even when they have an ISA: dumps, VM disks, game ROMs, chiptunes and app bundles.

Both lists and every limit live in `fwdonor.toml` (see `src/config.rs`), and `/api/policy` publishes them to the page. `fwdonor check <files>` prints the verdict for local files.

## Operations

```sh
./deploy.sh                                   # rsync, build on int, restart when quiet
ssh root@int systemctl status fwdonor
ssh root@int journalctl -u fwdonor -f
ssh root@int touch /data/fwdonor/runtime/paused   # pause donations (rm to resume)
curl https://fwdonor.zr.ax/api/health
```

**Deploys wait for a quiet moment.** `deploy.sh` builds while the old service keeps serving, with the new frontend staged in `dist.next/`. It then waits until `/api/health` reports no active uploads, an empty queue, and at least `IDLE_SECS` (default 10) without donation traffic. Only then does it swap `dist/` and restart. `MAX_WAIT=600 ./deploy.sh` restarts after 10 minutes regardless. The page copes with that, but a file in the middle of an upload has to be sent again. The restart itself takes about 0.1 s. The listener is bound before TDLib connects, so requests arriving in that window are queued rather than refused. For page-only changes, `FRONTEND_ONLY=1 ./deploy.sh` rebuilds and swaps `dist/` without restarting (the server reads it per request), so it needn't wait. Don't use it if the page needs anything new from the server.

**Updating zrax:** put the new commit in `ZRAX_REV`, then run `./deploy.sh`. After the restart the store is classified again and posts are edited where their caption changes (see [Reclassification](#reclassification)). Pages that are already open keep the zrax they loaded. The server still accepts their uploads for 7 days (`src/revisions.rs`, history in `runtime/zrax-revs.json`) and re-verifies every file with its own zrax. Those pages show a notice suggesting a reload once their files are done. A server-side rejection of a file from such a page does not count towards a ban. After the 7 days, an old page is told to reload before donating more.

**Bot login** (run once, or whenever the token changes; the service must be stopped):

```sh
ssh root@int systemctl stop fwdonor
ssh -t root@int runuser -u fwdonor -- /data/fwdonor/target/release/fwdonor --config /data/fwdonor/fwdonor.toml login
ssh root@int systemctl start fwdonor
```

`login` asks for the bot token at a hidden prompt. It stores the token in `runtime/telegram.json` (mode 600) next to the TDLib `api_id`/`api_hash` and checks that the bot can post documents to the group.

## Tests

```sh
cargo test --release                              # unit tests
node tests/pow.test.mjs                           # proof-of-work vector; WASM search = JS search; speed
node tests/agreement.mjs files.txt                # WASM vs native verdicts over a corpus
# with a dry-run server (deploy/fwdonor.dev.toml) on :18090:
node tests/api.e2e.mjs http://127.0.0.1:18090
PLAYWRIGHT=…/playwright/index.mjs node tests/browser.e2e.mjs http://127.0.0.1:18090 DIR expected.json
# runs its own dry-run server and kills it repeatedly mid-donation:
PLAYWRIGHT=…/playwright/index.mjs node tests/restart.e2e.mjs target/debug/fwdonor DIR expected.json
# fwdonate against a dry-run server that crashes and restarts mid-run (DIR as above):
node tests/client.e2e.mjs target/release/fwdonor target/release/fwdonate DIR
# bulk links: API end to end with crashes, a lost write, quota, duplicates, revoking (after scripts/build.sh):
node tests/bulk.e2e.mjs target/release/fwdonor
# bulk pages in a browser: issue a link, upload 600 MB, close the tab midway, resume:
PLAYWRIGHT=…/playwright/index.mjs node tests/bulk.browser.e2e.mjs target/release/fwdonor [screenshot dir]
# dashboard API: queries, facets, tree, details, downloads with Range, exports, bulk view, restart, privacy (DIR as above):
node tests/dashboard.e2e.mjs target/release/fwdonor target/release/fwdonate DIR
# the store classified again after a zrax update: outcomes, hidden files, post edits, a restart:
node tests/reclassify.e2e.mjs target/release/fwdonor
# dashboard pages in a browser (generates its own data):
PLAYWRIGHT=…/playwright/index.mjs node tests/dashboard.browser.e2e.mjs target/release/fwdonor [screenshot dir]
```
