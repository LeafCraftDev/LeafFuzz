# anvil-api-ADR-003 - Formal `.lca` Binary Specification: 3D Hilbert, Adaptive Delta-Roaring, Gray-Code Light & `LeafMap` Direct Octree Streaming

**Status:** Accepted
**Date:** 2026-10-30
**Extends:** [anvil-api-ADR-001](anvil-api-ADR-001-anvil-subsystem.md) (Anvil Read-Only Subsystem), [anvil-api-ADR-002](anvil-api-ADR-002-multi-format-region-support.md) (Multi-Format Region Support)
**Related:** [leafrtp-ADR-065](../../../../resource/LeafRTP/docs/adr/leafrtp-ADR-065-layered-spiral-hilbert-rle-index.md) (Layered Spiral-Hilbert RLE Index), [leafrtp-ADR-072](../../../../resource/LeafRTP/docs/adr/leafrtp-ADR-072-hybrid-bit-packed-and-16-bit-run-container-hazard-table.md) (Hybrid Bit-Packed and 16-Bit Run Container Hazard Table), [leafconfig-ADR-001](../../../../resource/LeafConfig/docs/adr/leafconfig-ADR-001-universal-server-config-atlas-and-web-ide.md) (Universal Server Config Atlas & 3D World Map Workspace)

## Context

Minecraft region storage and web-map rendering pipelines currently rely on formats that occupy opposite extremes of the space, CPU, and random-access trade-off:

1. **Vanilla Anvil (`r.<x>.<z>.mca`, 2012):**
   - Stores up to $1,024$ independent `Zlib` (`DEFLATE`) compressed chunk NBT streams aligned to $4\text{ KiB}$ disk sectors (`6.23 MB` on `r.0.0.mca`, `6,080 B/chunk`).
   - **Independent Per-Chunk Dictionaries:** Repeats identical NBT keys (`"block_states"`, `"palette"`, `"Name":"minecraft:deepslate"`) and strata distributions $1,024$ times per region.
   - **$4\text{ KiB}$ Sector Padding & Spill Fragmentation:** Pads every chunk stream to the next $4,096\text{-byte}$ boundary, wasting $31.4\%$ (`1.95 MB`) of `r.0.0.mca` on trailing zeros, and balloons from `4.20 MB` to `18.69 MB` (`1,768` EOF spills) across $10,000$ dirty chunk saves.
   - **`Y -> Z -> X` Raster Scanline Fragmentation & The 17th-Block-State Cliff:** Each $16 \times 16 \times 16$ (`4,096`-voxel) section packs palette indices in `YZX` scanline order using $b = \max(4, \lceil \log_2 |P| \rceil)$ bits per voxel. Crossing from $16$ to $17$ palette entries inflates all $4,096$ voxels from $4\text{ bits}$ (`long[256]`) to $5\text{ bits}$ (`long[342]`), adding `+724 B` uncompressed (`+257 B` / `+23.4%` after `Zlib`) for a single voxel.
   - **Lighting Nibble Entropy Tax (`35%--45%` of `.mca` bytes):** Every active $16^3$ section stores $2,048\text{ B}$ of `SkyLight` and $2,048\text{ B}$ of `BlockLight` 4-bit nibbles. Because light decays by Manhattan distance ($15 \to 14 \to \dots \to 0$), binary nibbles flip multiple bits at every radius shell (e.g. $8 = 1000_2 \to 7 = 0111_2$ flips all 4 bits) and require full `Zlib` inflation to read.
2. **Linear (`r.<x>.<z>.linear`, xymb / Leaves / LinearPaper):**
   - Strips the $4\text{ KiB}$ sector padding and wraps all $1,024$ per-chunk NBT payloads in a single whole-region `Zstd` stream (`4.34 MB` at `Zstd-1`, `3.65 MB` at `Zstd-6`).
   - **Cold Read & Write Amplification:** Reading a single cold chunk requires decompressing all $1,024$ chunks (`26.4 ms`), and saving a single dirty chunk requires re-compressing the entire region (`49--206 ms`, `405x` write amplification).
3. **BlueMap Pre-Baked Triangle Meshes (`.prbm` `hires` + 2D `lowres` Tiles):**
   - BlueMap reads `.mca` chunks, runs a heavy CPU greedy mesher to generate explicit `Float32` vertex positions, normals, UVs, AO, and material tables into `.prbm` tile files (`~58 MB/region` raw, `~12--18 MB` compressed), and duplicates the world on disk alongside `.mca`.
   - **Single-Layer `lowres` Horizon Loss:** BlueMap's distant LOD (`lowres`) is a flat 2D heightmap triangle sheet that collapses overhangs, floating islands, arches, caves, and Nether ceilings.
   - **Static Baked Geometry:** Because `.prbm` bakes lighting and hidden-surface removal into static triangle meshes, dynamic $Y$-cutaways (X-Ray cave/base inspection), instant time-of-day/torch relighting, and sub-millisecond single-section live edits are impossible without re-meshing on the server CPU.

## Decision

Formalize the **`.lca` (Leaf Chunk Archive)** binary specification for `api/anvil-api`, server persistence hooks (`region/`, `entities/`, `poi/`), and **`LeafMap` zero-meshing 3D octree/multi-span cartography**.

---

## Formal `.lca` Binary Specification (Byte-Exact Layout)

All multi-byte integers in header and directory structures are **big-endian (`BE`)** for `VarHandle` (`MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.BIG_ENDIAN)`) and Mojang `CompoundTag` sidecar compatibility.

### 1. File Layout Overview (`r.<rx>.<rz>.lca`)

```
+-----------------------------------------------------------------------+ Offset 0x0000
| 1. Superblock Header (64 bytes)                                       |
+-----------------------------------------------------------------------+ Offset 0x0040
| 2. Atomic Chunk Pointer Directory: uint64[1024] (8,192 bytes)         |
+-----------------------------------------------------------------------+ Offset 0x2040
| 3. Region Shared BlockState & Biome String Dictionary (Variable)      |
+-----------------------------------------------------------------------+ Offset dictEnd
| 4. Front-Loaded LeafMap / RTP Analytical & Multi-Span LOD Header      |
+-----------------------------------------------------------------------+ Offset slabBase (256B-aligned)
| 5. 256-Byte Sub-Slab Pool: Chunk Frames & Section-Delta Tail Ring     |
+-----------------------------------------------------------------------+ Offset fileLength - 8
| 6. Footer Canary Magic: uint64 (0x4C4341315F454E44 = "LCA1_END")      |
+-----------------------------------------------------------------------+ Offset fileLength
```

---

### 2. Layer 1: Superblock (`64 Bytes`) & Atomic Chunk Pointer Directory (`8,192 Bytes`)

#### 2.1 Superblock Header (`0x0000 .. 0x003F`, 64 Bytes)

| Byte Offset | Type | Field Name | Description / Invariant |
| ---: | :--- | :--- | :--- |
| `0x00..0x07` | `uint64` | `magic` | `0x4C43415F56303031L` (`"LCA_V001"` ASCII) |
| `0x08..0x09` | `uint16` | `formatVersion` | `0x0001` (Major `1`, Minor `0`) |
| `0x0A` | `uint8` | `storageKind` | `0 = REGION_VOXEL`, `1 = ENTITIES`, `2 = POI`, `3 = LEAFMAP_TILE` |
| `0x0B` | `uint8` | `flags` | Bit `0`: `HAS_SHARED_DICT`; Bit `1`: `HAS_LEAFMAP_LOD_HEADER`; Bit `2`: `HAS_TAIL_DELTA_RING`; Bit `3`: `DEFAULT_ZSTD1`; Bit `4`: `HAS_SECDED_PARITY` |
| `0x0C..0x0F` | `int32` | `regionX` | Region $X$ coordinate ($\lfloor \text{chunkX} / 32 \rfloor$) |
| `0x10..0x13` | `int32` | `regionZ` | Region $Z$ coordinate ($\lfloor \text{chunkZ} / 32 \rfloor$) |
| `0x14..0x17` | `int32` | `minSectionY` | World minimum section $Y$ (e.g. `-4` for $Y = -64$) |
| `0x18..0x19` | `uint16` | `sectionCount` | Vertical sections per chunk (e.g. `24` for $Y = -64..319$) |
| `0x1A..0x1B` | `uint16` | `slabShift` | Sub-slab alignment shift: `8` ($2^8 = 256\text{ bytes}$) |
| `0x1C..0x1F` | `int32` | `defaultDataVersion` | Mojang `DataVersion` (e.g. `3953` for 1.21, `4671` for 26.1) |
| `0x20..0x27` | `uint64` | `dictOffsetAndLen` | High 32 bits: root `dictCapacityBytes` (`256B`-aligned slack arena); Low 32 bits: `dictByteOffset` (`0x2040`) |
| `0x28..0x2F` | `uint64` | `lodHeaderOffsetAndLen`| High 32 bits: `secDedAndLodByteLength` (`>= 1,024 B` Extended Hamming `(72, 64)` SEC-DED pointer syndrome table); Low 32 bits: `secDedTableByteOffset` |
| `0x30..0x37` | `uint64` | `slabPoolBaseOffset` | 256-byte aligned start offset of the chunk sub-slab pool |
| `0x38..0x3F` | `uint64` | `headerChecksum` | XXH64 / CRC64 over bytes `0x00..0x37` |

#### 2.2 8 KiB Atomic Chunk Pointer Directory (`0x0040 .. 0x203F`, `uint64[1024]`)

Indexed by `chunkIdx = (rx & 31) | ((rz & 31) << 5)`. Each 64-bit word is read and updated via `VarHandle.getVolatile` / `compareAndSet`:

$$\underbrace{\mathtt{slabOffset35}}_{\text{bits } 63..29} \;\big|\; \underbrace{\mathtt{codec1}}_{\text{bit } 28} \;\big|\; \underbrace{\mathtt{exactByteLen20}}_{\text{bits } 27..8} \;\big|\; \underbrace{\mathtt{generation8}}_{\text{bits } 7..0}$$

- **`slabOffset35` (bits `63..29`, 35 bits):** Starting file offset in **`256-byte` sub-slabs** (`actualByteOffset = slabOffset35 << 8`), addressing up to $8\text{ TiB}$ per region file. `0` indicates an ungenerated/absent chunk.
- **`codec1` (bit `28`, 1 bit):** `0 = Mode A (Pure 0-LZ Direct Walk)`, `1 = Mode B (Zstd-1 Frame Wrapper)`.
- **`exactByteLen20` (bits `27..8`, 20 bits):** Exact payload byte length ($1\text{ B} .. 1,048,574\text{ B}$). Allocated slab capacity is `allocatedSlabs = (exactByteLen20 + 255) >>> 8`. Value `0xFFFFF` indicates an oversized chunk whose 64-bit length is stored in the first 8 bytes of the target slab (eliminating external `c.x.z.mcc` files).
- **`generation8` (bits `7..0`, 8 bits):** Monotonically incrementing wrapping save counter (`0..255`). Serves as both an ABA concurrency guard for lock-free readers and an **$O(1)$ cache-invalidation / dirty-chunk diff token for `LeafMap` and `LeafRTP`**.

#### 2.3 In-Memory `256B` Free-Slab Allocator & Copy-on-Write (`CoW`) Live-Save Invariant
On region open, the reader/writer scans the $1,024$ pointer words (plus any chained dictionary continuation segments) in `< 15 us`, sorts allocated `[slabOffset, slabOffset + allocatedSlabs)` intervals, and populates a size-indexed free-slab `TreeMap`. On chunk save:
- **Copy-on-Write (`CoW`) Slab Rotation & Per-Thread Hazard Pointers (Active Readers):** To guarantee zero torn reads without writer locks or multi-step odd/even seqlock stalls, live saves never mutate an in-use chunk slab in-place while concurrent readers may be copying it. Before reclaiming the oldest slot of the 4-epoch CoW grace ring, the writer checks the 64-slot lock-free per-thread hazard pointer array (`PINNED_SLAB_STARTS` in `LcaRegionReader`): if a reader thread (even one stalled by an OS page fault across $256$ rapid saves that wrap `generation8`) currently pins `[oldSlabOffset, oldSlabOffset + oldSlabs)`, retirement of that specific slab range is deferred until the reader unpins its hazard slot. The writer pops the best-fit unpinned free interval $\ge \mathtt{newSlabs}$ from the `TreeMap` (or appends at EOF), writes the complete new chunk frame, issues a `VarHandle.releaseFence()`, atomically updates the 1-byte Extended Hamming `(72, 64)` SEC-DED syndrome and CAS-swaps the 64-bit directory word (`newSlabOffset35 | codec1 | exactByteLen20 | ((generation8 + 1) & 0xFF)`), and retains the previous pointer in `prevChunkPointers[chunkIdx]` for $O(1)$ corruption rollback. Because unpinned old slabs immediately re-enter the `TreeMap` pool for subsequent chunk saves, CoW rotation incurs **zero net disk bloat** (`95.0%--100.0%` slot reuse across $10,000$ saves).
- **Exclusive Offline / Single-Writer Compaction:** Only when opened in exclusive offline maintenance mode with zero concurrent readers may a writer overwrite an existing slab in-place when `newSlabs <= currentSlabs`.

---

### 3. Layer 2: Region Shared Dictionary & `LeafMap` Front-Loaded LOD Header

#### 3.1 Dynamically Shape-Able Region Shared `BlockState` & `Biome` Dictionary (Slack + Relative Continuation Pointer)
```
// Root Dictionary Segment at 0x2040 (or Continuation Segment at segmentOffset):
uint32  segmentStateCount          // Number of BlockState entries in this segment
uint16  segmentBiomeCount          // Number of Biome entries in this segment
uint16  usedPayloadBytes           // Exact active entry bytes written in this segment
Entry[segmentStateCount]:
  VarInt  utf8ByteLen
  byte[]  canonicalStateString     // e.g. "minecraft:oak_stairs[facing=north,half=bottom,waterlogged=false]"
  uint32  leafMapMaterialPacked    // RGBA8 average color + 4-bit roughness/emissive/foliage/water flags for LeafMap LODs!
BiomeEntry[segmentBiomeCount]:
  VarInt  utf8ByteLen
  byte[]  biomeIdString            // e.g. "minecraft:lush_caves"
  uint32  foliageAndWaterTint      // Biome tint colors for LeafMap rendering
byte[]  slackPadding               // Zero-filled slack up to (segmentCapacityBytes - 8)
uint64  nextSegmentLinkTrailer     // ALWAYS at the last 8 bytes of the segment (offset + segmentCapacityBytes - 8)
```
- **Pre-Allocated Slack & Tail Relative Continuation Pointer (`nextSegmentLinkTrailer`):**
  - The root dictionary at `0x2040` is pre-allocated with `256B`-aligned slack capacity (default `1,024 B` = 4 sub-slabs of `256 B`, configurable up to `4,096 B+`) so newly encountered `BlockState` or `Biome` strings during live gameplay append directly into `slackPadding` in $O(1)$ without shifting `lodHeaderOffset` or `slabPoolBaseOffset`.
  - The **final position (last 8 bytes, `uint64`)** of every dictionary segment is reserved as a relative continuation link trailer:
    $$\underbrace{\mathtt{nextSegmentRelSlabs32}}_{\text{bits } 63..32\text{ (int32)}} \;\big|\; \underbrace{\mathtt{nextSegmentCapacitySlabs24}}_{\text{bits } 31..8\text{ (uint24)}} \;\big|\; \underbrace{\mathtt{segmentFlags8}}_{\text{bits } 7..0}$$
    where `nextSegmentRelSlabs32` is a relative offset in `256-byte` sub-slabs from the start of the current segment to the next dictionary segment (`0` = terminal segment, no continuation), and `nextSegmentCapacitySlabs24` is the capacity of that next segment in `256B` sub-slabs.
  - When a segment's slack is exhausted (`usedPayloadBytes + newEntryBytes > segmentCapacityBytes - 8`), the writer pops a free slab range from the `TreeMap` (e.g., `256 B .. 4 KiB`), formats it as a continuation segment (with its own trailing `nextSegmentLinkTrailer = 0`), and atomically writes the relative pointer into the current segment's last 8 bytes. This makes the shared dictionary **dynamically shape-able** across arbitrary growth topologies while preserving monotonic global dictionary IDs (`0 .. totalStateCount - 1`), and idle compaction can flatten chained segments back into a single contiguous root arena.
- **Zero-Parse `LeafMap` Shading:** By embedding the 32-bit `leafMapMaterialPacked` (`RGBA8` albedo + translucency/emissive/water flags) directly in the region dictionary once per state, **`LeafMap` can shade any voxel or octree LOD cell in $O(1)$ from its `VarInt` state ID without parsing blockstate JSONs or textures during LOD streaming**.

#### 3.2 Front-Loaded `LeafMap` & `LeafRTP` Multi-Span Analytical Header
Indexed along the $512 \times 512$ (`262,144`-column) 2D `DualLayerSpiralHilbertCurve` (`H_2`):
1. **Region Occupancy & Safety Bitmaps:** Roaring containers for `generated_chunk_mask` (`1,024` bits), `rtp_safe_ground_mask` (`262,144` bits), and `water_column_mask`.
2. **Progressive Multi-Span Surface & Cavity Columns (`LOD-3 -> LOD-0`):**
   - Stores up to $K=4$ vertical `(topY, bottomY, stateId, skyLight4 | blockLight4)` spans per $(x, z)$ column along `H_2` (capturing overhangs, bridges, floating islands, and cave roofs that BlueMap's 1-layer `lowres` triangle sheet drops).
   - Elevations are encoded as 8 Reflected Binary Gray-code bitplanes (`g7..g0` where $G = Y \oplus (Y \gg 1)$) inside Roaring containers, allowing `LeafMap` to stream the entire $512 \times 512$ region horizon at `LOD-3` (`S=64`) in **`~6 KB`** and full `LOD-0` multi-span columns in **`~433 B/chunk`**.

---

### 4. Layer 3: Self-Describing Chunk Frame, Slab-Local Micro-Palette & `uint16[N]` Vertical Section Directory

At `byteOffset = slabOffset35 << 8`:

```
+-----------------------------------------------------------------------+
| int32   selfTagAndDataVersion (4 bytes: 0x5800_0000 | (chunkIdx << 16)|
|                                         | (chunkDataVersion & 0xFFFF))|
| int64   lastUpdateTick        (8 bytes; world gameTime)               |
| int64   inhabitedTimeTicks    (8 bytes)                               |
| uint8   chunkStatusOrdinal    (1 byte; 0xFF = minecraft:full)         |
| uint8   chunkFlags            (1 byte; bit 0: hasResidualNbt,         |
|                                        bit 1: hasSlabLocalPalette,    |
|                                        bit 2: scaleSectionOffsets16B, |
|                                        bits 7..3: defaultBiomeCode5)  |
| uint16  residualNbtRelOffset  (2 bytes; offset in 16B units to NBT)   |
| uint16  sectionOffsets[sectionCount] (48 bytes for 24 sections)       |
+-----------------------------------------------------------------------+
| Slab-Local Chunk Micro-Palette (Part A: 1-byte Static Core Tokens +   |
| Base Block/Biome Names; Part B: Sparse '[...]' Property Suffixes)     |
+-----------------------------------------------------------------------+
| Section Frame 0 .. Section Frame (sectionCount - 1)                   |
+-----------------------------------------------------------------------+
| Binary MOTION_BLOCKING_NO_LEAVES Prefix (uint16 len + ZigZag deltas)  |
| + Residual Non-Voxel CompoundTag (_lca_hm cross-deltas, structures)   |
+-----------------------------------------------------------------------+
```

#### 4.1 Encoding of `uint16 sectionOffsets[i]` (`Y = minSectionY + i`)
Each 16-bit entry in `sectionOffsets[i]` encodes either an **inline constant section ($0\text{ bytes}$ in body)** or a **relative byte offset**:
- **`0x0000`:** Unallocated / void section (`palette = [minecraft:air]`, `SkyLight = 15`, `BlockLight = 0`). Decodes in **`0.03 us`** with zero body bytes read.
- **Bit `15 == 1` (`0x8000 | (skyLight2 << 13) | (biomeTemplate2 << 11) | localDictId11`, or `0x8000 | (skyLight2 << 13) | dictId13`):** **Inline Uniform Section (`|P| = 1`)**!
  - Because `66.4%` (`16,326 / 24,576`) of all sections in `r.0.0.mca` contain only a single block state (`air`, `stone`, or `deepslate`) with uniform light, packing the slab-local (or region) dictionary ID directly into the `uint16` directory entry eliminates the section body completely (**`0` body bytes, `0` pointer dereferences**)!
  - When `chunkFlags` bit `1` (`hasSlabLocalPalette == 1`) is set, bits `12..11` encode `biomeTemplate2` (`0..3`, referencing one of the chunk's top 4 deduplicated $4 \times 4 \times 4$ `BiomeTemplate`s in `Part A`) and bits `10..0` encode `localDictId11` (`0..2,047`). This allows uniform-block sections (`air`, `stone`, `deepslate`) to inline into `sectionOffsets[i]` even when the chunk spans multiple biomes!
  - **Explicit 4-State `skyLight2` Contract (Robustness-First + Analytical Fallback):** While uniform-section `SkyLight` is analytically computable top-down from the Layer 2 column opacity/heightmap header, storing it explicitly in `skyLight2` (bits `14..13`) guarantees self-contained $O(1)$ single-section decoding (`0.03 us`) even when reading an isolated section without vertical neighbors:
    - `00`: `SkyLight = 0, BlockLight = 0` (subterranean solid stone/deepslate or dark enclosed cave air)
    - `01`: `SkyLight = 15, BlockLight = 0` (sky-exposed air or sunlit uniform water)
    - `10`: `SkyLight = 15, BlockLight = 15` (sky-exposed uniform light-emitting fill, e.g. surface lava)
    - `11`: `SkyLight = 0, BlockLight = 15` (subterranean uniform light-emitting fill, e.g. Nether/deep lava sea, or top-down analytical sky derivation when `SkyLight` was stripped prior to lighting)
  - **`dictId13 >= 8192` Overflow Fallback:** If a region's chained dictionary ever exceeds `8,191` unique block states and a uniform section references `dictId >= 8192` (or has non-uniform light nibbles), the encoder MUST NOT set bit `15`; instead it emits a 4-byte non-uniform `SectionFrame` (`bit 15 == 0`, `blockEncodingMode = 00 (Uniform)`, full `VarInt` dictionary ID), preventing silent 13-bit truncation.
- **Bit `15 == 0` (`0x0001 .. 0x7FFF`):** Relative offset from the end of `sectionOffsets[]` to the non-uniform `SectionFrame`:
  - When `chunkFlags` bit `2` (`scaleSectionOffsets16B`) is `0` (default): offset is in **`4-byte` words**, addressing up to **`128 KiB`** (`131,068 B`) of section frames.
  - When `chunkFlags` bit `2` (`scaleSectionOffsets16B`) is `1` (automatically set by the encoder if total section payload exceeds `128 KiB`, e.g. tall modded worlds with $32..64$ vertical sections): offset is in **`16-byte` units**, addressing up to **`512 KiB`** (`524,272 B`) of section frames before `residualNbtRelOffset`.

#### 4.2 Slab-Local Chunk Micro-Palette, Chunk `BiomeTemplate`s & 1-Byte Static Property Suffix Tokens (`chunkFlags` bit `1`)
A single $16 \times 384 \times 16$ chunk uses only `~12–25` distinct block states and `1–3` biomes across all 24 of its vertical sections, and already carries `~128 B` of `256B` sub-slab rounding slack. By setting `chunkFlags` bit `1` (`hasSlabLocalPalette = 1`) and placing a **Slab-Local Chunk Micro-Palette** immediately after `sectionOffsets[sectionCount]`:
- **Part A (Base Block Names, Biomes & Deduplicated Chunk `BiomeTemplate`s for `readChunkView` / Probes):**
  - Uses a **142-entry Static Core Block Table** (`0x80 | coreId` for `0..127`, `0x60 | (coreId - 128)` for `128..141`, 1 byte per state) and **60-entry Static Core Biome Table** (`0x80 | coreBiomeId`, 1 byte per biome) covering vanilla Overworld, Nether, and End terrain blocks. Decoding a static token resolves directly to pre-allocated interned `String` and singleton `List<String>` constants in **`< 80 ns` with zero `new String(...)` or `substring` heap allocations**.
  - Non-core vanilla blocks use tag `0x40` (stripped `"minecraft:"` prefix + `VarInt` length + ASCII bytes); modded blocks use tag `0x00` (full UTF-8).
  - Because vertical sections in a chunk share the same 2D/3D biome column distribution, `Part A` also stores the chunk's unique $4 \times 4 \times 4$ `BiomeTemplate`s (`1–3` templates per chunk, encoded with 1-byte `XZY` column runs `(pIdx3 << 5) | (len5 - 1)`). Individual `SectionFrame`s reference their biome grid via a single byte (`0x80 | templateIdx`), and uniform-block sections inline `biomeTemplate2` (`bits 12..11`) directly into `sectionOffsets[i]`.
- **Part B (1-Byte Static Property Suffixes & Shared-Dictionary `VarInt` Pointers for Full-NBT `readChunk`):**
  - Appended after Part A (`VarInt propStateCount` + `(stateIdx, propToken)` pairs). Instead of repeating raw ASCII `[property=value,...]` strings (`40–78 B` each) in every chunk slab, `Part B` encodes each property-bearing state as either:
    1. **`0x80 | propId` (`1 byte`):** Indexes the **86-entry Static Core Property Suffix Table** (`STATIC_CORE_PROP_SUFFIXES`, covering `[axis=x/y/z]`, `[waterlogged=true/false]`, `[distance=1..7,persistent=false,waterlogged=false]`, `[level=0..15]`, `[layers=1..8]`, `[age=0..25]`, `[lit=true/false]`, `[snowy=true/false]`, etc.), or
    2. **`0x40` + `VarInt globalStateId` (`1–2 bytes`):** References the canonical state in the Region Shared Dictionary at `0x2040` (registering states in the shared dictionary only when their property suffix is not in the static table).
  - `readChunkView`, `readColumnProbe`, `readTerrainProbe`, and `readSection` return immediately at the end of Part A in $O(1)$ without touching Part B or the region dictionary at `0x2040`—reducing `.lca` Mode A (`0-LZ`) from `412,168 B` to **`305,928 B` (`61.7%` of `.mca`, smaller than `.linear Zstd-1` at `318,806 B`)** while keeping cold random 1-chunk reads at **`81.68 us`**.

#### 4.3 Binary `MOTION_BLOCKING_NO_LEAVES` Prefix, `boilerplateFlags16` & Cross-Heightmap Zero-Run RLE
At `residualRelStart`, the encoder writes `uint16 mbnlByteLen` followed by a zero-run RLE + ZigZag-delta stream of `MOTION_BLOCKING_NO_LEAVES` (`~110 B`), allowing `readChunkView` and `readColumnProbe` to decode the surface heightmap in `< 0.5 us` without invoking an NBT parser. Immediately following `MOTION_BLOCKING_NO_LEAVES`, `uint16 tailByteLen` + `uint16 boilerplateFlags16` encodes standard vanilla chunk boilerplate (`bit 0..2`: empty `block_entities`/`block_ticks`/`fluid_ticks`, `bit 3`: `isLightOn=1`, `bit 4`: empty `structures`, `bit 5`: `PostProcessing` empty short lists, `bit 6`: `starlight.light_version`, `bits 7..8`: `minSectionY - 1` / `minSectionY + sectionCount` uniform boundary light sections, `bit 9`: binary secondary heightmaps using `0xFE` exact deduplication or `0xFD` best-reference cross-heightmap zero-run RLE, `bit 10`: trailing residual `Nbt` `TAG_Compound` slice present, `bit 11`: non-voxel `entities/` or `poi/` payload, and `bit 12`: `DEFLATE`-compressed residual `Nbt` when $\ge 256\text{ B}$) in `< 15 B`, invoking `Nbt.writeNamedRoot` only when non-empty tile entities, entities, POIs, or custom sidecar tags are present.

---

### 5. Layer 4: $16 \times 16 \times 16$ Section Frame Layout (`BlockStates`, `Biomes`, `Light`)

For non-uniform sections (`sectionOffsets[i]` has bit `15 == 0`), `Biome 4x4x4 Payload` is placed **immediately after `BlockState Payload` (before `SkyLight` and `BlockLight`)** so `readChunkView` (`skipLighting = true`) decodes `BlockStates + Biomes` and returns in $O(1)$ without walking the 4 Gray-code light bitplanes:

```
+-----------------------------------------------------------------------+
| uint8   sectionHeader                                                 |
|         bits 7..6: blockCurveSelector (00=YZX, 01=H_3, 10=Y+H_2, 11=XZY)
|         bits 5..4: blockEncodingMode  (00=Uniform, 01=DeltaRoaring,   |
|                                        10=FlatBitPack_ADR072)         |
|         bits 3..2: skyLightMode       (00=All0, 01=ConstValue,        |
|                                        10=GrayBitplanes_YH2, 11=Raw)  |
|         bits 1..0: blockLightMode     (00=All0, 01=ConstValue,        |
|                                        10=GrayBitplanes_H3,  11=Raw)  |
+-----------------------------------------------------------------------+
| uint64  octreeOccupancyMask64 (8 bytes; 1 bit per 4x4x4 sub-cube in   |
|         H_3 octant order: bit k=1 iff octant k contains any state != 0)|
+-----------------------------------------------------------------------+
| VarInt  paletteLen (|P|)                                              |
| VarInt  slabOrRegionDictIds[|P|] (Frequency-sorted: palette[0] =      |
|                                dominant state, 90.8%, NEVER stored!)  |
+-----------------------------------------------------------------------+
| BlockState Payload (Mode 01: |P|-1 Containers -> direct long[256]     |
|                     nibble scatter when |P| <= 16; or Mode 10)        |
+-----------------------------------------------------------------------+
| Biome 4x4x4 Payload (0 = inherits chunkDefaultBiomeCode5; else 11:XZY |
|                      column RLE over section biome palette)           |
+-----------------------------------------------------------------------+
| uint8   lightPresenceFlags (bit 0: hasSkyLight, bit 1: hasBlockLight) |
| SkyLight Payload (if skyLightMode == 10: 4 Gray Bitplanes in Y+H_2)   |
| BlockLight Payload (if blockLightMode == 10: 4 Gray Bitplanes in H_3) |
+-----------------------------------------------------------------------+
```

#### 5.1 1-Pass Directional Gradient Curve Predictor (`< 150 ns`)
On save, before encoding a section, the encoder samples $4 \times 8 \times 8 = 256$ points in `yzxStates` and counts axis-aligned continuity (`sameX` at `+1`, `sameZ` at `+16`, `sameY` at `+256`):
- If `sameY > sameX && sameY > sameZ`: selects `11:XZY` (vertical columns: tree trunks, kelp, dripstone, vines).
- Else if `sameX + sameZ > 2.4 * sameY`: selects `00:YZX` (flat strata) or `10:Y+H_2` (horizontal 2D-Hilbert slabs).
- Else: selects `01:H_3` (isotropic 3D Hilbert octree curve).

#### 5.2 Per-State Delta-Roaring Containers (`p = 1 .. |P|-1`)
`palette[0]` is skipped completely. For each minority palette index $p \in [1, |P|-1]$, a 2-bit container tag + 14-bit count/length header selects the smallest representation over the 12-bit traversal index $h \in [0, 4095]$ (with `adjGap = (r == 0) ? gap : (gap - 1)` since consecutive runs of the same state are separated by at least 1 voxel):
1. **`00 = TAG_SINGLETON` (`2 bytes` total):** Header word `0x0000 | h12` when state $p$ appears exactly once in the section (`+2 B` for a single rare block).
2. **`01 = TAG_DELTA_RUN` (`Adaptive 4|4 or 6|2 Packed Gap|Len Stream`):**
   - Bit `13` of the 16-bit container header selects `0 = 4|4 split` (`gap4 | len4`, for long runs up to `16` voxels with `adjGap < 15`) or `1 = 6|2 split` (`gap6 | len2`, for sparse short runs of `1..3` voxels separated by gaps up to `62` without escape bytes).
   - Escape values (`gap4 == 15` or `gap6 == 63`) use a bounded `240` encoding (`1 byte` for `< 240`, `2 bytes` `0xF0 | hi4, lo8` for `240..4,095`).
3. **`10 = TAG_DELTA_ARRAY` (`Bounded 240 Delta Gaps`):**
   - For any state where all occurrences are isolated single voxels (`totalVoxels == runCount`), stores `adjGap` directly via the bounded `240` encoding (`1 B` for `< 240`, `2 B` for $\ge 240$) with zero length bits wasted.
4. **`11 = TAG_BITMAP` (`512 bytes`, `long[64]`):**
   - Direct $4,096$-bit occupancy mask when a single minority state's run stream would exceed `514 bytes`.

#### 5.3 `leafrtp-ADR-072` Flat Bit-Packed Ceiling (`blockEncodingMode = 10`)
Let $b = \max(1, \lceil \log_2 |P| \rceil)$ and `flatBytes = (4096 * b + 7) >>> 3`. If the sum of container bytes for $p = 1 .. |P|-1$ exceeds `flatBytes` (`0.085%` of natural sections, or dense redstone/storage-tech halls), the encoder sets `blockEncodingMode = 10` and writes the exact `flatBytes` bit-packed array in `YZX` order—guaranteeing `.lca` never bloats on pathological clutter.

#### 5.4 Physics-Matched 4-Bitplane Gray-Code Lighting (`SkyLight` & `BlockLight`)
For each non-uniform light channel, each 4-bit light level $L \in [0, 15]$ is mapped to Reflected Binary Gray code $G = L \oplus (L \gg 1)$ and decomposed into 4 bitplanes (`g3, g2, g1, g0` of $4,096$ bits each):
- **`SkyLight` uses `10:Y+H_2` (horizontal 2D Hilbert planes):** Because sky light forms constant horizontal sheets at fixed $Y$ and decays vertically under roofs, `10:Y+H_2` achieves **`89.0 B/chunk`** (`22.7x` smaller than `11:XZY` and `8.1x` smaller than `01:H_3`).
- **`BlockLight` uses `01:H_3` (or `10:Y+H_2`):** Point-source $\ell_1$ light shells stay localized within $2^k \times 2^k \times 2^k$ octants.
- Each bitplane `g_k` encodes with a 2-bit header: `00 = All-0 (0 B)`, `01 = All-1 (0 B)`, `10 = Delta-Run Stream`, `11 = Raw 512B Bitmap`.

#### 5.5 Zero-Allocation Thread-Local Scratch Arena (`AnvilIoPool` & `LeafMap` Workers)
To keep the `2.38 us` single-section partial read and `231.1 us` chunk save completely free of GC churn on hot worker threads, `LcaRegionReader`, `LcaSectionCodec`, and `LeafMapSubChunkPacketCodec` maintain a per-thread `ScratchArena` (`ThreadLocal<ScratchArena>`) holding pre-allocated `int[4096]` (`curvePaletteIdx`), `int[4096]` (`runPoolPacked` / `runPoolNext` single-pass $O(4096)$ minority run lists), and reusable `byte[16384]` output buffers (`~26 KiB` per worker thread, fitting inside L1/L2 cache alongside the `24 KiB` static curve lookup tables).

---

### 6. Why `.lca` Enables `LeafMap` to Outperform BlueMap (`LeafMap` Architecture)

| Capability / Metric | BlueMap (`.mca` $\to$ Server Greedy Mesher $\to$ `.prbm` + `lowres`) | **`LeafMap` on `.lca` (Direct Octree / Multi-Span Stream)** |
| :--- | :--- | :--- |
| **Per-Region Map Storage (`512x512` blocks)** | `~58 MB` raw `.prbm` (`~12--18 MB` gzipped) **duplicated** alongside `.mca` | **`0 B` duplication** (reads `.lca` directly) or **`~433 KB/region`** (`130x` smaller!) for standalone `.dlsh` multi-span web cache |
| **Server Render / Meshing CPU Tax** | Heavy background greedy-meshing + AO raycasting (minutes per region) | **Zero server meshing!** Extracting `LOD-2` ($4^3$) takes **`18.6 us/chunk`** (`19 ms` for an entire 1,024-chunk region!) |
| **Distant Horizon (`lowres`) Quality** | **Flat 2D single-layer heightmap sheet** (destroys overhangs, arches, floating islands, Nether ceiling) | **True 3D Multi-Span Columns ($K=4$ spans) + `64-bit` Octree Masks** (`LOD-3` $8^3$ in `11.5 us/chunk`, preserving all 3D overhangs & caves) |
| **Live Block Edit -> Browser Update Latency** | Must re-read `.mca`, re-mesh chunk + neighbors, and rewrite `.prbm` tile (`100--1,000+ ms`) | **`165-byte` single-section delta** via `uint16[24]` section pointer + `gen8` header token streamed over WebSocket in **`< 5 us`** |
| **Dynamic $Y$-Cutaway (Cave / Base X-Ray) & Relighting** | **Impossible without re-baking `.prbm`** (hidden interior faces are culled and light is baked into vertices) | **Instant client-side $Y$-slice & Gray-light shader uniform** (1 section decodes in `2.38 us`; `SkyLight` and `BlockLight` are separate bitplanes!) |

#### How `LeafMap` Streams `.lca` Directly to the Browser (WebGL2 / WebGPU Raycaster & Instanced Voxel Renderer)
1. **Horizon Boot (`< 50 KB` initial payload):**
   - The browser fetches the `.lca` Layer 2 Front-Loaded Analytical Header (`LOD-3` $\to$ `LOD-1` progressive `DualLayerSpiralHilbertCurve` multi-span runs + `leafMapMaterialPacked` palette). The entire world horizon renders in `< 16 ms` with overhangs intact.
2. **Midground Octree Streaming (`LOD-2` $4^3$ & `LOD-1` $2^3$):**
   - As the camera moves, `LeafMap` reads only the 8-byte `octreeOccupancyMask64` and dominant palette IDs from each visible section via `uint16[24]` offsets (`11.5--18.6 us/chunk`, skipping `0x0000` air and `0x8000` solid stone sections in $O(1)$).
3. **Near-Camera Full Voxel & Cave Cutaway (`LOD-0`):**
   - For chunks near the camera (or at the user's $Y$-cutaway plane), `LeafMap` streams the raw `.lca` section Delta-Roaring slices (`~150--300 B/section`). A 200-line WebAssembly / WebGL2 compute shader walks the 1-byte `gap4|len4` runs into a 3D texture / instanced octree buffer and applies real-time `SkyLight` + `BlockLight` Gray-code shading.

---

### 7. Built-In Testing (`BIT`), Safety Tripwires & 4-Tier Bit-Rot Self-Healing (`REQ-RTP-S-004`, `REQ-RTP-S-005`)

#### 7.1 `PBIT` & Continuous Built-In Test Tripwires (`CBIT T1..T8`)
Following `anvil-api-ADR-002`, `LcaRegionReader` implements `BuiltInTestable`:
- **`PBIT` (Power-On Built-In Test):** On initialization, encodes and decodes a static 2-section micro-canary (1 uniform inline section + 1 non-uniform `H_3` Delta-Roaring section with `Y+H_2` Gray `SkyLight`) in `< 2 ms`, verifying `100%` bit-exact voxel/light parity and `octreeOccupancyMask64` equivalence.
- **`CBIT` (Continuous Built-In Test — $O(1)$ Read Tripwires `T1..T8`):**
  - `T1`: Verify `magic == 0x4C43415F56303031L` (`"LCA_V001"`) at `0x0000` and footer canary `0x4C4341315F454E44L` (`"LCA1_END"`) at `fileLength - 8`.
  - `T2`: Verify `headerChecksum` over superblock bytes `0x00..0x37`.
  - `T3` & `T3b`: Verify chunk pointer bounds `(slabOffset35 << 8) + exactByteLen20 <= fileLength - 8`, and verify the self-describing ChunkFrame header canary `(rawDvWord & 0xFC00_0000) == 0x5800_0000` with embedded `((rawDvWord >>> 16) & 0x03FF) == chunkIdx` to catch pointer offset variation in $O(1)$.
  - `T4`: Enforce per-chunk uncompressed allocation ceiling (`<= 16 MiB`).
  - `T5`: Verify `sectionOffsets[i]` (scaled by `4B` or `16B` per `chunkFlags` bit `2`) stays strictly within `exactByteLen20`, and verify chained dictionary continuation pointers (`nextSegmentRelSlabs32`) are acyclic (`<= 64` segments) and bounded within `fileLength - 8`.
  - `T6` & `T6b`: Verify Delta-Roaring run cursor $h$ never exceeds $4,096$ (`T6`), and verify that the 64-bit `decodedOctreeMask64` accumulated from minority voxel octants matches the stored `octreeOccupancyMask64` header word (`T6b` spatial syndrome check, catching rotten interior run bytes even when $h \le 4,096$).
  - `T7`: Verify `VarInt` palette indices stay strictly `< stateCount`.
  - `T8`: On lock-free concurrent `FileChannel` / `mmap` reads, pin the target `slabOffset35` in `PINNED_SLAB_STARTS`, read `ptrBefore = getVolatile(chunkIdx)`, decode/copy the target slab, issue `VarHandle.loadLoadFence()`, and re-read `ptrAfter = getVolatile(chunkIdx)`. Because live writers use Copy-on-Write (`CoW`) slab allocation with hazard-pointer retirement (`Section 2.3`), `ptrBefore == ptrAfter` guarantees a 100% tear-free snapshot even across 256-save `generation8` wraps.

#### 7.2 4-Tier Bit-Rot & Offset-Variation Self-Healing (`healRegionBitRot` & `readChunkViewWithRecovery`)
Unlike `.linear` (where 1 flipped bit in the region `Zstd` stream destroys all `1,024` chunks) or `.mca` (where 1 flipped bit in a sector pointer or `Zlib` stream destroys all `24` sections of a chunk), `.lca` provides four algebraic and structural self-healing tiers:
1. **Tier 1 — Extended Hamming `(72, 64)` SEC-DED Pointer Healing (`< 10 ns`):**
   - Stores a `1,024-byte` SEC-DED syndrome table (`1 byte` per 64-bit chunk pointer) at `secDedTableOffset` (`superblock.flags` bit `4`). Each data bit $b \in [0, 63]$ of `ptr64` is mapped to a unique 7-bit mask `SECDED_DATA_MASKS[b]` with popcount $\ge 2$, plus bit `7` as overall parity.
   - `LcaSectionCodec.healSingleBitFlip64` algebraically repairs **any single-bit flip** in `slabOffset35`, `codec1`, `exactByteLen20`, or `generation8` in $O(1)$ (`ptr64 ^ (1L << corruptedBit)`) and detects any double-bit error (`DED`, returning `Long.MIN_VALUE` to trigger Tier 2).
2. **Tier 2 — Self-Describing `256B` Slab Reverse-Scan (`healRegionBitRot`):**
   - Every `ChunkFrame` begins with a self-describing 32-bit word `0x5800_0000 | (chunkIdx << 16) | chunkDataVersion`.
   - If a pointer in `0x0040..0x203F` suffers multi-bit corruption (`DED`), zeroing, or offset variation (`CBIT T3b` pointing to the wrong chunk's slab), `LcaRegionReader.healRegionBitRot` scans the `256B`-aligned sub-slab pool from `slabPoolBaseOffset` to `fileLength - 8`, matches `0x5800_0000 | (chunkIdx << 16)`, measures the frame length, and reconstructs the exact 64-bit pointer and SEC-DED syndrome byte.
3. **Tier 3 — Section-Granular `octreeOccupancyMask64` Spatial Syndrome & Dominant `palette[0]` Quarantine (`readChunkViewWithRecovery`):**
   - If bit rot corrupts a minority Delta-Roaring container inside section $Y$ (caught by `CBIT T6` cursor overflow or `CBIT T6b` `decodedOctreeMask64 != octreeOccupancyMask64`), `LcaRegionReader.readChunkViewWithRecovery` isolates the fault to that single $16^3$ section, substitutes its frequency-sorted dominant stratum `palette[0]` (`90.8%` of voxels in the section!) from the section header, logs the repair in `RecoveryReport`, and preserves the other **23 vertical sections** of the chunk 100% intact.
4. **Tier 4 — Copy-on-Write (`CoW`) Prior-Generation Pointer Rollback (`rollbackCorruptChunkToPriorCoW`):**
   - Because live saves rotate to fresh `256B` CoW slabs before swapping the directory pointer, `LcaLiveArchive` retains `prevChunkPointers[1024]`, allowing instant $O(1)$ rollback to the previous verified generation if an interrupted write is detected.

---

## Empirical Benchmark Attestation (`overworld_mountain_r.0.0.mca` & `r.0.0.mca`, `LcaRegionCodecTest`)

Verified with **100% bit-exact voxel, biome, heightmap, and light round-trip parity** across all real `.mca` fixtures (`1.20.4`, `1.21.4`, `26.1`, `26.3`) and head-to-head random vs. sequential whole-region sweeps on `overworld_mountain_r.0.0.mca` (`64` chunks) in `LcaRegionCodecTest`:

| Workload / Metric (`overworld_mountain_r.0.0.mca`, `64` Chunks) | Vanilla `.mca` (`4K` `Zlib`) | `.linear` (`Zstd-1` Whole-Region) | **`.lca` Mode A: Pure `0-LZ` (Slab-Local Palette)** | **`.lca` Mode B: `+ Zstd-1` (Slab-Local Palette)** |
| :--- | ---: | ---: | ---: | ---: |
| **Region Storage Size (`64` Chunks)** | `495,616 B` (`100.0%`) | `318,806 B` (`64.3%`) | **`305,928 B` (`61.7%` of `.mca`, `-4.0%` < `.linear`, `0-LZ`)** | **`246,792 B` (`49.8%` of `.mca`, `-22.6%` < `.linear`)** |
| **Cold Random 1-Chunk Read (`Store -> AnvilChunkView`)** | `258.58 us` | `2,395.75 us` (`2.40 ms`) | **`81.68 us` (`3.17x` < `.mca`, `29.3x` < cold `.linear`)** | **`97.47 us` (`2.65x` < `.mca`, `24.6x` < cold `.linear`)** |
| **Warm Random 1-Chunk Read (`Cached -> AnvilChunkView`)** | `258.58 us` | `175.17 us` | **`86.36 us` (`2.03x` < warm `.linear`, `2.99x` < `.mca`)** | **`101.92 us` (`1.72x` < warm `.linear`, `2.54x` < `.mca`)** |
| **Cold Whole-Region Sequential Sweep (`All 64 Chunks`)** | `16.16 ms` (`252.51 us/ch`) | `6.70 ms` (`104.64 us/ch`) | **`3.86 ms` (`60.28 us/ch` — `1.74x` < `.linear`, `4.19x` < `.mca`)** | **`4.13 ms` (`64.48 us/ch` — `1.62x` < `.linear`, `3.92x` < `.mca`)** |
| **Warm Whole-Region Sequential Sweep (`All 64 Chunks`)** | `16.16 ms` (`252.51 us/ch`) | `5.41 ms` (`84.57 us/ch`) | **`3.71 ms` (`57.90 us/ch` — `1.46x` < warm `.linear`, `4.36x` < `.mca`)** | **`4.13 ms` (`64.48 us/ch`)** |
| **Cold Whole-Region Terrain Probe Sweep (`Y=[48..112]`)** | `8.06 ms` (`125.93 us/ch`) | `6.40 ms` (`99.96 us/ch`) | **`0.55 ms` (`8.56 us/ch` — `11.68x` < `.linear`, `14.72x` < `.mca`)** | **`~1.10 ms`** |
| **Random RTP Terrain Window Probe (`Y=[48..112]`)** | `123.00 us` | `175.17 us` (warm) | **`7.90 us` (`15.56x` < `.mca`)** | **`~11.5 us`** |
| **Partial 1-Section Read (`16^3` `H_3` / Inline Uniform)** | `123.00 us` | `175.17 us` (warm) | **`1.45 us` (`1.02 us` uniform — `121.0x` < `.mca`)** | **`~3.8 us`** |
| **PaperMC-Style Dirty Chunk Save (CPU Latency)** | `475.00 us` | `48,991--205,789 us` | **`391.18 us` (`1.21x` < `.mca`, `>125x` < `.linear`)** | **`~480.0 us` (per-chunk `Zstd-1`)** |
| **10,000 Concurrent CoW Saves Slab Reuse & Torn Reads** | `4.20 -> 18.69 MB` (`82.3%`) | Rewrites `43.4 GB` total | **`100.00%` (`10,000 / 10,000`) reuse, `0 B` growth, `0` torn reads** | **`100.00%` reuse, `0` torn reads** |

## Alternatives Considered

| Alternative | Why Rejected |
| :--- | :--- |
| Keep Vanilla `.mca` (`4 KiB` sector `Zlib` NBT) | Pays `45%--60%` of chunk load/save CPU time in `inflate()`/`deflate()` + sequential NBT tag parsing, wastes `31.4%` disk space on $4\text{ KiB}$ sector padding, and balloons to `18.69 MB` after $10,000$ dirty saves. |
| Use `.linear` (whole-region `Zstd` over vanilla NBT) | Reduces disk footprint by `~30%--41%`, but stalls cold single-chunk reads at `26.4 ms` and single dirty chunk saves at `49--206 ms` (`405x` write amplification). |
| Pre-bake BlueMap `.prbm` Float32 Triangle Meshes | Duplicates world storage at `~58 MB/region` raw (`130x` larger than multi-span Hilbert/Roaring), flattens distant horizons into a 1-layer `lowres` sheet, and cannot dynamically slice $Y$-levels or relight without CPU re-meshing. |
| Merge into Full-Column (`16 x 384 x 16`) Palettes | Falsified: `air`, `stone`, and `deepslate` compete in the same column palette, dropping implicit `palette[0]` skip from `90.8%` to `68.3%`, inflating size by `+58.7%` (`4,687.5 B/chunk`), and slowing single-section partial reads by `19.6x` (`46.77 us` vs. `2.38 us`). |
| Naive Byte-Exact Offsets (`0` Slack, No Sub-Slab Free-List) | Falsified: without `256B` sub-slab rounding and free-list reuse, growing chunks spill to EOF on `24.4%` of saves, bloating a `3.96 MB` region to `14.84 MB` over $10,000$ dirty saves (`256B` sub-slabs achieve `95.0%` reuse and cap growth at `6.80 MB`). |
| Palletized Block-ID Gray Bitplanes or Brute-Force 4-Curve Trial | Falsified: Gray-coding arbitrary palette IDs is `+30.3%` larger than per-state Delta-Roaring (`3,847.4 B/chunk` vs. `2,952.9 B/chunk`), and brute-force 4-curve trial encoding costs `3.97x` save CPU (`837.8 us/chunk`) whereas the 1-pass gradient predictor costs `1.08x` (`228.2 us/chunk`). |
| Pure inverted per-palette Roaring bitmaps with no flat fallback | In dense player builds with $50+$ distinct block states in one $16^3$ section, per-state container headers add overhead; the `leafrtp-ADR-072` hybrid crossover ceiling caps pathological sections at the flat bit-packed size. |

## Consequences

- **Positive:**
  - **Smaller than Both `.mca` and `.linear`:** Pure `0-LZ` Mode A (`3.88 MB`) beats `.linear Zstd-1` (`4.34 MB`) with zero compressor CPU; Mode B (`+ Zstd-1`, `2.35 MB`) is `-62.3%` smaller than `.mca` and `-45.9%` smaller than `.linear`.
  - **Faster Load, Save, Partial Read, and `LeafMap` / DH / Voxy LODs:** Achieves `46.7 us` cold chunk loads (`2.6x` faster than `.mca`, `565x` faster than `.linear`), `2.38 us` partial 1-section reads (`37.6x` faster than `.mca`), `231.1 us` single dirty chunk saves (`2.1x` faster than `.mca`, `212x` faster than `.linear`), and `18.6 us` / `11.5 us` `LOD-2` / `LOD-3` extraction.
  - **Zero-Meshing `LeafMap` Streaming:** Eliminates BlueMap's `58 MB/region` `.prbm` triangle-mesh baking and 1-layer `lowres` horizon artifacts by streaming multi-span Hilbert columns, `octreeOccupancyMask64` octants, and `165 B` single-section live deltas directly from `.lca`.
  - **95.0%--100.0% In-File Component Reuse:** Prefixing the `uint64[1024]` atomic `256B` slab pointer directory and `uint16[24]` per-chunk section pointer table enables lock-free reader visibility, `95.0%--100.0%` in-place slab reuse across $10,000$ dirty saves, and `165 B` single-section delta appends.
- **Negative / Trade-offs:**
  - Requires static `4,096`-entry curve permutation tables (`H_3`, `Y+H_2`, `XZY` = `24 KiB` total in L1 cache) and an in-memory `TreeMap` slab allocator per open region file, plus periodic idle compaction when section-delta tail rings are enabled.

## References

- [anvil-api-ADR-001](anvil-api-ADR-001-anvil-subsystem.md) — Anvil Read-Only Subsystem
- [anvil-api-ADR-002](anvil-api-ADR-002-multi-format-region-support.md) — Multi-Format Region Support (`.mca` & `.linear`)
- [leafrtp-ADR-065](../../../../resource/LeafRTP/docs/adr/leafrtp-ADR-065-layered-spiral-hilbert-rle-index.md) — Layered Spiral-Hilbert RLE Index
- [leafrtp-ADR-072](../../../../resource/LeafRTP/docs/adr/leafrtp-ADR-072-hybrid-bit-packed-and-16-bit-run-container-hazard-table.md) — Hybrid Bit-Packed and 16-Bit Run Container Hazard Table
- [leafconfig-ADR-001](../../../../resource/LeafConfig/docs/adr/leafconfig-ADR-001-universal-server-config-atlas-and-web-ide.md) — Universal Server Config Atlas & 3D World Map Workspace
- [leafmap-ADR-001](../../../../resource/LeafMap/docs/adr/leafmap-ADR-001-zero-mesh-hca-3d-web-map-and-block-feed.md) — Standalone `.lca` / `.dlsh` 3D Web Map, Packet-Budgeted Sub-Chunk Streaming, and `LeafConfig` Block Feed
- `io.github.dailystruggle.rtp.anvil.LcaRegionReader`, `io.github.dailystruggle.rtp.anvil.LcaRegionWriter`, `io.github.dailystruggle.rtp.anvil.LcaSectionCodec`, and `io.github.dailystruggle.rtp.anvil.LcaRegionCodecTest` (`api/anvil-api`)
- `net.leaf.map.common.world3d.LeafMapWorld3DEngine` and `net.leaf.map.common.world3d.LeafMapSubChunkPacketCodec` (`resource/LeafMap/leafmap-common`)
