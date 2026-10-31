package io.github.dailystruggle.rtp.anvil;

import io.github.dailystruggle.bit.BitHealth;
import io.github.dailystruggle.bit.PbitResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.io.TempDir;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Differential parity, CBIT/PBIT tripwire verification, Copy-on-Write (`CoW`) concurrency torture test,
 * and empirical benchmark suite for `.lca` ({@link LcaRegionReader} and {@link LcaRegionWriter},
 * `anvil-api-ADR-003`, `REQ-RTP-S-004`, `REQ-RTP-S-005`).
 */
@DisplayName("anvil-api-ADR-003: LcaRegionReader & LcaRegionWriter Parity, CBIT, and Empirical Benchmark")
class LcaRegionCodecTest {

    @BeforeEach
    @AfterEach
    void resetRegistry() {
        RegionFormatRegistry.reset();
    }

    private static byte[] loadFixture(String resourcePath) throws IOException {
        try (InputStream in = LcaRegionCodecTest.class.getResourceAsStream(resourcePath)) {
            if (in == null) {
                fail("Fixture not found on classpath: " + resourcePath);
            }
            return in.readAllBytes();
        }
    }

    private static Stream<Arguments> realFixtures() {
        return Stream.of(
                Arguments.of("1_20_R1", 3465),
                Arguments.of("1_21_R1", 4671),
                Arguments.of("26_1_R1", 4788),
                Arguments.of("26_3_R1", 5023));
    }

    @Test
    @DisplayName("REQ-RTP-S-004: LcaRegionReader PBIT micro-canary passes and .lca registers in RegionFormatRegistry")
    void pbitAndRegistryIntegration() {
        PbitResult pbit = LcaRegionReader.INSTANCE.executePbit();
        assertNotNull(pbit);
        assertTrue(pbit.passed(), () -> "PBIT failed: " + pbit.diagnosticMessage());
        assertEquals(BitHealth.HEALTHY, LcaRegionReader.INSTANCE.getHealthStatus());

        LcaRegionReader.register();
        assertTrue(RegionFormatRegistry.isRegistered(".lca"));
        assertEquals(LcaRegionReader.INSTANCE, RegionFormatRegistry.getReader(".lca"));
    }

    @ParameterizedTest(name = "real fixture {0} (DataVersion={1}) Mode A & Mode B 100% voxel/biome/probe parity")
    @MethodSource("realFixtures")
    @DisplayName("REQ-RTP-S-005: Real .mca fixtures transcoded to .lca Mode A & Mode B match AnvilReader across all voxels")
    void realMcaTranscodeFullParity(String dirName, int expectedDv) throws IOException {
        byte[] mcaBytes = loadFixture("/anvil/real/" + dirName + "/r.0.0.mca");

        for (boolean modeB : new boolean[] {false, true}) {
            if (modeB && !DynamicZstdBinding.isAvailable()) continue;

            byte[] lcaBytes = LcaRegionWriter.transcodeFromMca(mcaBytes, 0, 0, modeB);
            assertTrue(LcaRegionReader.INSTANCE.isChunkGenerated(lcaBytes, 0, 0));
            assertFalse(LcaRegionReader.INSTANCE.isChunkGenerated(lcaBytes, 1, 0));
            assertFalse(LcaRegionReader.INSTANCE.isChunkGenerated(lcaBytes, 31, 31));
            assertNull(LcaRegionReader.INSTANCE.readChunk(lcaBytes, 1, 0));
            assertEquals(1, LcaRegionReader.readGenerationToken(lcaBytes, 0, 0));
            assertEquals(-1, LcaRegionReader.readGenerationToken(lcaBytes, 1, 0));

            AnvilReader.ChunkEntry mcaEntry = AnvilReader.readChunkEntry(mcaBytes, 0, 0);
            AnvilReader.ChunkEntry lcaEntry = LcaRegionReader.INSTANCE.readChunk(lcaBytes, 0, 0);
            assertNotNull(mcaEntry);
            assertNotNull(lcaEntry);

            assertEquals(expectedDv, AnvilReader.getDataVersion(lcaEntry.root));
            assertEquals(AnvilReader.getDataVersion(mcaEntry.root), AnvilReader.getDataVersion(lcaEntry.root));
            assertEquals(mcaEntry.root.get("xPos"), lcaEntry.root.get("xPos"));
            assertEquals(mcaEntry.root.get("zPos"), lcaEntry.root.get("zPos"));

            Nbt.NbtList mcaSections = AnvilReader.getSections(mcaEntry.root);
            Nbt.NbtList lcaSections = AnvilReader.getSections(lcaEntry.root);
            assertEquals(mcaSections.items.size(), lcaSections.items.size(), "NBT sections list count parity");

            // Compare both NBT-derived AnvilChunkView and direct zero-NBT LcaRegionReader.readChunkView
            AnvilChunkView mcaView = AnvilReader.toView(mcaEntry.root);
            AnvilChunkView lcaNbtView = AnvilReader.toView(lcaEntry.root);
            AnvilChunkView lcaDirectView = LcaRegionReader.readChunkView(lcaBytes, 0, 0);

            assertNotNull(lcaDirectView);
            assertEquals(mcaView.minHeight(), lcaNbtView.minHeight());
            assertEquals(mcaView.minHeight(), lcaDirectView.minHeight());
            assertEquals(mcaView.sections().size(), lcaNbtView.sections().size());
            assertEquals(mcaView.sections().size(), lcaDirectView.sections().size());
            assertEquals(mcaView.getBiomesPresent(), lcaNbtView.getBiomesPresent());
            assertEquals(mcaView.getBiomesPresent(), lcaDirectView.getBiomesPresent());

            // Verify every single (x, y, z) voxel across all sections + single-section partial reader
            for (PaletteSection mcaSec : mcaView.sections()) {
                int sy = mcaSec.sectionY();
                PaletteSection partialSec = LcaRegionReader.readSection(lcaBytes, lcaBytes.length, 0, 0, sy);
                assertNotNull(partialSec, "Partial section read must not be null for sy=" + sy);
                for (int ly = 0; ly < 16; ly++) {
                    int worldY = (sy << 4) + ly;
                    for (int lz = 0; lz < 16; lz++) {
                        for (int lx = 0; lx < 16; lx++) {
                            String expectedBlock = mcaSec.blockIdAt(lx, ly, lz);
                            assertEquals(expectedBlock, partialSec.blockIdAt(lx, ly, lz),
                                    "Partial section mismatch at (" + lx + "," + worldY + "," + lz + ")");
                            assertEquals(expectedBlock, lcaDirectView.blockIdAt(lx, worldY, lz),
                                    "Direct ChunkView mismatch at (" + lx + "," + worldY + "," + lz + ")");
                            assertEquals(expectedBlock, lcaNbtView.blockIdAt(lx, worldY, lz),
                                    "NBT ChunkView mismatch at (" + lx + "," + worldY + "," + lz + ")");
                        }
                    }
                }
            }

            // Verify ColumnProbe and TerrainProbe parity
            ColumnProbe mcaProbe = AnvilReader.readColumnProbe(mcaBytes, 0, 0, -64, 319);
            ColumnProbe lcaProbe = LcaRegionReader.readColumnProbe(lcaBytes, 0, 0, -64, 319);
            ColumnProbe lcaTerrain = LcaRegionReader.readTerrainProbe(lcaBytes, lcaBytes.length, 0, 0, 20, 120);
            assertNotNull(mcaProbe);
            assertNotNull(lcaProbe);
            assertNotNull(lcaTerrain);
            assertEquals(mcaProbe.heightmapTopY(), lcaProbe.heightmapTopY());
            for (int y = -64; y <= 319; y++) {
                assertEquals(mcaProbe.blockAt(y), lcaProbe.blockAt(y), "ColumnProbe blockAt mismatch at y=" + y);
                assertEquals(mcaProbe.biomeAt(y), lcaProbe.biomeAt(y), "ColumnProbe biomeAt mismatch at y=" + y);
                if (y >= 20 && y <= 120) {
                    assertEquals(mcaProbe.blockAt(y), lcaTerrain.blockAt(y), "TerrainProbe blockAt mismatch at y=" + y);
                }
            }
        }
    }

    @Test
    @DisplayName("anvil-api-ADR-003 Section 3.1: Dynamically shape-able chained dictionary links overflow segments via nextSegmentLinkTrailer")
    void dynamicallyChainedDictionaryOverflowAndReopen() throws IOException {
        LcaRegionWriter.LcaLiveArchive archive =
                LcaRegionWriter.createEmptyLiveArchive(0, 0, -4, 24, 4671, false, 256);

        List<String> customStates = new ArrayList<>();
        for (int i = 0; i < 45; i++) {
            String state = "minecraft:custom_block_" + i + "[facing=north,waterlogged=false,power=" + (i % 16) + "]";
            customStates.add(state);
        }

        LinkedHashMap<String, Object> root = new LinkedHashMap<>();
        root.put("DataVersion", 4671);
        root.put("xPos", 3);
        root.put("zPos", 5);
        root.put("Status", "minecraft:full");

        LinkedHashMap<String, Object> sec = new LinkedHashMap<>();
        sec.put("Y", (byte) 4);
        List<Object> palItems = new ArrayList<>();
        for (String s : customStates) {
            palItems.add(LcaRegionReader.parseCanonicalStateToNbtCompound(s));
        }
        int[] yzx = new int[4096];
        for (int i = 0; i < 4096; i++) {
            yzx[i] = i % customStates.size();
        }
        LinkedHashMap<String, Object> bs = new LinkedHashMap<>();
        bs.put("palette", new Nbt.NbtList(Nbt.TAG_COMPOUND, palItems));
        bs.put("data", LcaSectionCodec.packBlockLongs(yzx, customStates.size()));
        sec.put("block_states", bs);
        root.put("sections", new Nbt.NbtList(Nbt.TAG_COMPOUND, List.of(sec)));

        archive.saveChunkCoW(3, 5, root);
        assertTrue(archive.dictionarySegmentCount() >= 3,
                "Expected chained dictionary to allocate >= 3 continuation segments, got " + archive.dictionarySegmentCount());

        byte[] serialized = archive.toByteArray();
        LcaRegionWriter.LcaLiveArchive reopened = LcaRegionWriter.openLiveArchive(serialized);
        assertEquals(archive.dictionarySegmentCount(), reopened.dictionarySegmentCount());
        assertEquals(archive.totalDictionaryStates(), reopened.totalDictionaryStates());

        AnvilReader.ChunkEntry decoded = LcaRegionReader.INSTANCE.readChunk(serialized, 3, 5);
        assertNotNull(decoded);
        AnvilChunkView view = AnvilReader.toView(decoded.root);
        for (int i = 0; i < 64; i++) {
            int lx = i & 15;
            int lz = (i >>> 4) & 15;
            String expectedBase = LcaRegionReader.stripBlockProperties(customStates.get(i % customStates.size()));
            assertEquals(expectedBase, view.blockIdAt(lx, 64, lz));
        }
    }

    @Test
    @DisplayName("anvil-api-ADR-003 Section 4.1: Inline uniform section skyLight2 4-state contract & globalDictId >= 8192 overflow fallback")
    void inlineUniformSkyLightStatesAndDictId8192OverflowFallback() throws IOException {
        LcaRegionWriter.LcaLiveArchive archive =
                LcaRegionWriter.createEmptyLiveArchive(0, 0, -4, 24, 4671, false, 4096);

        // Register 8,200 unique block states to cross the 13-bit (8192) inline uniform threshold
        String highDictBlock = "minecraft:high_dict_block_8195";
        int highId = -1;
        for (int i = 0; i < 8200; i++) {
            String s = (i == 8195) ? highDictBlock : ("minecraft:state_" + i);
            int id = archive.registerOrGetBlockStateId(s);
            if (i == 8195) highId = id;
        }
        assertTrue(highId >= 8192, "High dictionary ID must be >= 8192, got " + highId);
        assertTrue(archive.dictionarySegmentCount() <= LcaRegionReader.MAX_DICT_CHAIN_SEGMENTS,
                "Geometric segment growth must stay within MAX_DICT_CHAIN_SEGMENTS, got " + archive.dictionarySegmentCount());

        List<Object> sections = new ArrayList<>();
        sections.add(buildUniformSectionNbt(-4, "minecraft:stone", 0, 0));
        sections.add(buildUniformSectionNbt(-3, "minecraft:air", 15, 0));
        sections.add(buildUniformSectionNbt(-2, "minecraft:glowstone", 15, 15));
        sections.add(buildUniformSectionNbt(-1, "minecraft:lava", 0, 15));
        sections.add(buildUniformSectionNbt(0, highDictBlock, 0, 0));

        LinkedHashMap<String, Object> root = new LinkedHashMap<>();
        root.put("DataVersion", 4671);
        root.put("xPos", 0);
        root.put("zPos", 0);
        root.put("Status", "minecraft:full");
        root.put("sections", new Nbt.NbtList(Nbt.TAG_COMPOUND, sections));

        archive.saveChunkCoW(0, 0, root);
        byte[] lcaBytes = archive.toByteArray();

        AnvilChunkView view = LcaRegionReader.readChunkView(lcaBytes, 0, 0);
        assertNotNull(view);
        assertEquals("minecraft:stone", view.blockIdAt(0, -64, 0));
        assertEquals("minecraft:air", view.blockIdAt(0, -48, 0));
        assertEquals("minecraft:glowstone", view.blockIdAt(0, -32, 0));
        assertEquals("minecraft:lava", view.blockIdAt(0, -16, 0));
        assertEquals(highDictBlock, view.blockIdAt(0, 0, 0));

        AnvilReader.ChunkEntry entry = LcaRegionReader.INSTANCE.readChunk(lcaBytes, 0, 0);
        Nbt.NbtList decSecs = AnvilReader.getSections(entry.root);
        assertEquals(5, decSecs.items.size());
    }

    private static LinkedHashMap<String, Object> buildUniformSectionNbt(int sy, String blockName, int skyVal, int blkVal) {
        LinkedHashMap<String, Object> sec = new LinkedHashMap<>();
        sec.put("Y", (byte) sy);
        LinkedHashMap<String, Object> bs = new LinkedHashMap<>();
        LinkedHashMap<String, Object> palEntry = new LinkedHashMap<>();
        palEntry.put("Name", blockName);
        bs.put("palette", new Nbt.NbtList(Nbt.TAG_COMPOUND, List.of(palEntry)));
        sec.put("block_states", bs);
        if (skyVal > 0) {
            byte[] sky = new byte[2048];
            Arrays.fill(sky, (byte) ((skyVal << 4) | skyVal));
            sec.put("SkyLight", sky);
        }
        if (blkVal > 0) {
            byte[] blk = new byte[2048];
            Arrays.fill(blk, (byte) ((blkVal << 4) | blkVal));
            sec.put("BlockLight", blk);
        }
        return sec;
    }

    @Test
    @DisplayName("REQ-RTP-S-004: CBIT tripwires T1..T7 reject corrupted .lca headers, pointers, and section payloads")
    void cbitTripwiresRejectCorruptInputs() throws IOException {
        byte[] mcaBytes = loadFixture("/anvil/real/1_21_R1/r.0.0.mca");
        byte[] validLca = LcaRegionWriter.transcodeFromMca(mcaBytes, 0, 0, false);
        LcaRegionReader reader = LcaRegionReader.INSTANCE;

        // T1: Bad superblock magic
        byte[] badMagic = Arrays.copyOf(validLca, validLca.length);
        badMagic[0] ^= (byte) 0xFF;
        assertThrows(CorruptRegionEntryException.class, () -> reader.readChunk(badMagic, 0, 0));
        assertFalse(reader.isChunkGenerated(badMagic, 0, 0));

        // T1: Bad footer canary
        byte[] badFooter = Arrays.copyOf(validLca, validLca.length);
        badFooter[badFooter.length - 1] ^= (byte) 0xFF;
        assertThrows(CorruptRegionEntryException.class, () -> reader.readChunk(badFooter, 0, 0));
        assertFalse(reader.isChunkGenerated(badFooter, 0, 0));

        // T2: Superblock checksum mismatch
        byte[] badChecksum = Arrays.copyOf(validLca, validLca.length);
        badChecksum[0x0C] ^= 0x01;
        assertThrows(CorruptRegionEntryException.class, () -> reader.readChunk(badChecksum, 0, 0));

        // T3: Out-of-bounds chunk slab pointer
        byte[] badPtr = Arrays.copyOf(validLca, validLca.length);
        long hugePtr = LcaRegionWriter.packChunkPointer64(999_999L, false, 1024, 1);
        ByteBuffer.wrap(badPtr).putLong(LcaRegionReader.POINTER_DIRECTORY_OFFSET, hugePtr);
        assertThrows(CorruptRegionEntryException.class, () -> reader.readChunk(badPtr, 0, 0));
        assertFalse(reader.isChunkGenerated(badPtr, 0, 0));

        // T5: Cyclic dictionary continuation link
        byte[] cyclicDict = Arrays.copyOf(validLca, validLca.length);
        int rootDictCap = ByteBuffer.wrap(cyclicDict).getInt(0x20);
        int trailerPos = LcaRegionReader.DICT_ROOT_OFFSET + rootDictCap - 8;
        long loopForward = (1L << 32) | (1L << 8) | 1L;
        long loopBackward = (((long) -1 & 0xFFFF_FFFFL) << 32) | (16L << 8) | 1L;
        ByteBuffer.wrap(cyclicDict).putLong(trailerPos, loopForward);
        int secondSegTrailer = (LcaRegionReader.DICT_ROOT_OFFSET & ~0xFF) + 256 + 256 - 8;
        ByteBuffer.wrap(cyclicDict).putLong(secondSegTrailer, loopBackward);
        assertThrows(CorruptRegionEntryException.class, () -> reader.readChunk(cyclicDict, 0, 0));
    }

    @Test
    @DisplayName("anvil-api-ADR-003 Section 7.2: Multi-tier bit-rot & offset-variation self-healing (SEC-DED, Slab Reverse-Scan, Octree Syndrome, CoW Rollback)")
    void multiTierBitRotAndOffsetVariationSelfHealing() throws IOException {
        byte[] mcaBytes = loadFixture("/anvil/real/1_21_R1/r.0.0.mca");
        AnvilReader.ChunkEntry origin = AnvilReader.readChunkEntry(mcaBytes, 0, 0);
        assertNotNull(origin);

        LcaRegionWriter.LcaLiveArchive archive =
                LcaRegionWriter.createEmptyLiveArchive(0, 0, -4, 24, 4671, false, 4096);
        LinkedHashMap<String, Object> c00 = new LinkedHashMap<>(origin.root);
        c00.put("xPos", 0);
        c00.put("zPos", 0);
        LinkedHashMap<String, Object> c10 = new LinkedHashMap<>(origin.root);
        c10.put("xPos", 1);
        c10.put("zPos", 0);
        archive.saveChunkInitial(0, 0, c00);
        archive.saveChunkInitial(1, 0, c10);

        byte[] cleanLca = archive.toByteArray();
        AnvilChunkView baselineView = LcaRegionReader.readChunkView(cleanLca, 0, 0);
        assertNotNull(baselineView);

        // Tier 1: Extended Hamming (72, 64) SEC-DED heals a single-bit flip in the 64-bit pointer directory
        for (int bit = 0; bit < 64; bit += 9) {
            byte[] singleBitRot = Arrays.copyOf(cleanLca, cleanLca.length);
            int ptrOff = LcaRegionReader.POINTER_DIRECTORY_OFFSET;
            long origPtr = ByteBuffer.wrap(singleBitRot).getLong(ptrOff);
            ByteBuffer.wrap(singleBitRot).putLong(ptrOff, origPtr ^ (1L << bit));

            LcaRegionReader.RecoveryReport report = LcaRegionReader.healRegionBitRot(singleBitRot);
            assertEquals(1, report.secDedHealedPointers(), "SEC-DED must heal 1-bit flip at bit " + bit);
            assertFalse(report.diagnostics().isEmpty());
            assertEquals(origPtr, ByteBuffer.wrap(singleBitRot).getLong(ptrOff));
            AnvilChunkView healedView = LcaRegionReader.readChunkView(singleBitRot, singleBitRot.length, 0, 0);
            assertEquals(baselineView.blockIdAt(8, 64, 8), healedView.blockIdAt(8, 64, 8));
        }

        // Tier 1b: 1-bit flip inside the stored syndrome byte itself (data word already clean)
        byte[] synBitRot = Arrays.copyOf(cleanLca, cleanLca.length);
        int secDedOff = (int) (ByteBuffer.wrap(synBitRot).getLong(0x28) & 0xFFFF_FFFFL);
        synBitRot[secDedOff] ^= 0x01;
        LcaRegionReader.RecoveryReport synReport = LcaRegionReader.healRegionBitRot(synBitRot);
        assertEquals(0, synReport.secDedHealedPointers());

        // Tier 1c -> Tier 2: Double-bit flip (DED) in pointer word detected by SEC-DED and healed by Slab Reverse-Scan
        byte[] doubleBitRot = Arrays.copyOf(cleanLca, cleanLca.length);
        long origPtr0 = ByteBuffer.wrap(doubleBitRot).getLong(LcaRegionReader.POINTER_DIRECTORY_OFFSET);
        ByteBuffer.wrap(doubleBitRot).putLong(LcaRegionReader.POINTER_DIRECTORY_OFFSET, origPtr0 ^ 0b11L);
        LcaRegionReader.RecoveryReport dedReport = LcaRegionReader.healRegionBitRot(doubleBitRot);
        assertEquals(1, dedReport.slabScanReconstructedPointers());
        assertEquals(origPtr0, ByteBuffer.wrap(doubleBitRot).getLong(LcaRegionReader.POINTER_DIRECTORY_OFFSET));

        // Tier 2: Offset variation (chunk (0,0) pointer overwritten to point to chunk (1,0)'s slab or wiped)
        byte[] offsetVariation = Arrays.copyOf(cleanLca, cleanLca.length);
        long ptr10 = ByteBuffer.wrap(offsetVariation).getLong(LcaRegionReader.POINTER_DIRECTORY_OFFSET + 8);
        // Point chunk (0,0) at chunk (1,0)'s slab -> CBIT T3b detects self-describing chunkIdx mismatch!
        ByteBuffer.wrap(offsetVariation).putLong(LcaRegionReader.POINTER_DIRECTORY_OFFSET, ptr10);
        assertThrows(CorruptRegionEntryException.class, () -> LcaRegionReader.readChunkView(offsetVariation, 0, 0));
        // Update syndrome byte to match ptr10 so Tier 1 passes and Tier 1's CBIT T3b self-describing check triggers Tier 2
        offsetVariation[secDedOff] = offsetVariation[secDedOff + 1];

        // Now run healRegionBitRot -> Tier-2 Slab Pool Reverse-Scan finds self-describing 0x5800_0000 | (0 << 16) slab!
        LcaRegionReader.RecoveryReport scanReport = LcaRegionReader.healRegionBitRot(offsetVariation);
        assertEquals(1, scanReport.slabScanReconstructedPointers());
        AnvilChunkView recoveredFromSlabScan = LcaRegionReader.readChunkView(offsetVariation, 0, 0);
        assertNotNull(recoveredFromSlabScan);
        assertEquals(baselineView.blockIdAt(8, 64, 8), recoveredFromSlabScan.blockIdAt(8, 64, 8));

        // Tier 3: Section-level octreeOccupancyMask64 syndrome mismatch (CBIT T6b) + dominant palette[0] quarantine
        byte[] sectionBitRot = Arrays.copyOf(cleanLca, cleanLca.length);
        long ptr00 = ByteBuffer.wrap(sectionBitRot).getLong(LcaRegionReader.POINTER_DIRECTORY_OFFSET);
        int frameStart = (int) ((ptr00 >>> 29) << LcaRegionReader.SLAB_SHIFT);
        // Find first non-uniform section in chunk (0,0) and flip its octreeOccupancyMask64 syndrome
        int targetSecIdx = -1;
        int targetRelStart = -1;
        int sectionDirEnd = 24 + (24 << 1);
        for (int i = 0; i < 24; i++) {
            int entry16 = ByteBuffer.wrap(sectionBitRot).getShort(frameStart + 24 + (i << 1)) & 0xFFFF;
            if (entry16 != 0 && (entry16 & 0x8000) == 0) {
                targetSecIdx = i;
                targetRelStart = sectionDirEnd + ((entry16 - 1) << 2);
                break;
            }
        }
        assertTrue(targetSecIdx >= 0);
        // Flip octreeOccupancyMask64 at (frameStart + targetRelStart + 1..8) to trigger CBIT T6b syndrome mismatch
        sectionBitRot[frameStart + targetRelStart + 1] ^= (byte) 0xFF;
        assertThrows(CorruptRegionEntryException.class, () -> LcaRegionReader.readChunkView(sectionBitRot, 0, 0));

        LcaRegionReader.RecoveryReport secReport = new LcaRegionReader.RecoveryReport();
        AnvilChunkView partialHealed = LcaRegionReader.readChunkViewWithRecovery(sectionBitRot, 0, 0, secReport);
        assertNotNull(partialHealed);
        assertEquals(1, secReport.quarantinedSections(), "Only the 1 corrupted section should be quarantined");
        assertEquals(baselineView.sections().size(), partialHealed.sections().size(),
                "All other 23 sections remain intact and the damaged section falls back to dominant palette[0]");

        // Tier 4: Copy-on-Write (CoW) prior-generation slab rollback
        c00.put("InhabitedTime", 999L);
        archive.saveChunkCoW(0, 0, c00);
        assertTrue(archive.rollbackCorruptChunkToPriorCoW(0, 0));
        AnvilChunkView rolledBack = LcaRegionReader.readChunkView(archive.toByteArray(), 0, 0);
        assertEquals(baselineView.blockIdAt(8, 64, 8), rolledBack.blockIdAt(8, 64, 8));
    }

    @Test
    @DisplayName("anvil-api-ADR-003 Sections 4-5: FlatBitPack ceiling, TAG_BITMAP, TAG_DELTA_ARRAY escape, light modes, curves, Mode B readSection, and slab coalescing")
    void exhaustiveBranchAndContainerModeCoverage() throws IOException {
        LcaRegionWriter.LcaLiveArchive archive =
                LcaRegionWriter.createEmptyLiveArchive(0, 0, -4, 24, 4671, false, 4096);

        // 1. Section Y=-4: High-entropy 2-state checkerboard (> 256 runs -> TAG_BITMAP + FlatBitPack ceiling!)
        LinkedHashMap<String, Object> secChecker = new LinkedHashMap<>();
        secChecker.put("Y", (byte) -4);
        LinkedHashMap<String, Object> bsChecker = new LinkedHashMap<>();
        bsChecker.put("palette", new Nbt.NbtList(Nbt.TAG_COMPOUND, List.of(
                LcaRegionReader.parseCanonicalStateToNbtCompound("minecraft:stone"),
                LcaRegionReader.parseCanonicalStateToNbtCompound("minecraft:cobblestone"),
                LcaRegionReader.parseCanonicalStateToNbtCompound("minecraft:granite"),
                LcaRegionReader.parseCanonicalStateToNbtCompound("minecraft:diorite"))));
        int[] yzxChecker = new int[4096];
        for (int i = 0; i < 4096; i++) {
            yzxChecker[i] = (i * 7 + (i >>> 4) * 3 + (i >>> 8) * 5) & 3;
        }
        bsChecker.put("data", LcaSectionCodec.packBlockLongs(yzxChecker, 4));
        secChecker.put("block_states", bsChecker);
        // Constant non-0/non-15 SkyLight (7) and BlockLight (9) -> LIGHT_MODE_CONST
        byte[] constSky7 = new byte[2048];
        Arrays.fill(constSky7, (byte) 0x77);
        byte[] constBlk9 = new byte[2048];
        Arrays.fill(constBlk9, (byte) 0x99);
        secChecker.put("SkyLight", constSky7);
        secChecker.put("BlockLight", constBlk9);

        // 2. Section Y=-3: Sparse singletons with gap >= 255 -> TAG_DELTA_ARRAY with 0xFF escape + TAG_BITMAP for state 2
        LinkedHashMap<String, Object> secSparse = new LinkedHashMap<>();
        secSparse.put("Y", (byte) -3);
        LinkedHashMap<String, Object> bsSparse = new LinkedHashMap<>();
        bsSparse.put("palette", new Nbt.NbtList(Nbt.TAG_COMPOUND, List.of(
                LcaRegionReader.parseCanonicalStateToNbtCompound("minecraft:stone"),
                LcaRegionReader.parseCanonicalStateToNbtCompound("minecraft:emerald_ore"),
                LcaRegionReader.parseCanonicalStateToNbtCompound("minecraft:gold_ore"))));
        int[] yzxSparse = new int[4096];
        // State 1 (emerald_ore): 4 isolated singletons separated by huge gaps in curve order -> TAG_DELTA_ARRAY with 0xFF escape
        yzxSparse[0] = 1;
        yzxSparse[1024] = 1;
        yzxSparse[2048] = 1;
        yzxSparse[3500] = 1;
        // State 2 (gold_ore): 300 isolated singletons -> > 256 runs -> TAG_BITMAP (while total roaring < flatBytes)
        for (int r = 0; r < 300; r++) {
            int pos = 10 + r * 3;
            if (pos < 4096 && yzxSparse[pos] == 0) {
                yzxSparse[pos] = 2;
            }
        }
        bsSparse.put("data", LcaSectionCodec.packBlockLongs(yzxSparse, 3));
        secSparse.put("block_states", bsSparse);
        // High-entropy incompressible light -> LIGHT_MODE_RAW fallback (>= 2048 bytes in Gray planes)
        byte[] noisySky = new byte[2048];
        byte[] noisyBlk = new byte[2048];
        Random lightRnd = new Random(99);
        lightRnd.nextBytes(noisySky);
        lightRnd.nextBytes(noisyBlk);
        secSparse.put("SkyLight", noisySky);
        secSparse.put("BlockLight", noisyBlk);

        // 3. Section Y=-2: Vertical columns -> CURVE_XZY + multi-biome RLE (3 biomes) + long delta-run escape (>= 15)
        LinkedHashMap<String, Object> secVertical = new LinkedHashMap<>();
        secVertical.put("Y", (byte) -2);
        LinkedHashMap<String, Object> bsVertical = new LinkedHashMap<>();
        bsVertical.put("palette", new Nbt.NbtList(Nbt.TAG_COMPOUND, List.of(
                LcaRegionReader.parseCanonicalStateToNbtCompound("minecraft:air"),
                LcaRegionReader.parseCanonicalStateToNbtCompound("custommod:kelp_column[age=12]"),
                LcaRegionReader.parseCanonicalStateToNbtCompound("minecraft:magma_block[custom=1]"))));
        int[] yzxVertical = new int[4096];
        for (int y = 0; y < 16; y++) {
            yzxVertical[(y << 8) | (2 << 4) | 2] = 1;
            yzxVertical[(y << 8) | (10 << 4) | 10] = 1;
        }
        // State 2: short 2-voxel runs separated by medium/large gaps -> triggers 6|2 run mode (gap < 63, gap >= 63 < 303, gap >= 303, len >= 4)
        int[] curveToYzxXzy = LcaSectionCodec.CURVE_TO_YZX[LcaSectionCodec.CURVE_XZY];
        yzxVertical[curveToYzxXzy[20]] = 2;
        yzxVertical[curveToYzxXzy[21]] = 2;
        yzxVertical[curveToYzxXzy[60]] = 2;
        yzxVertical[curveToYzxXzy[61]] = 2;
        yzxVertical[curveToYzxXzy[150]] = 2;
        yzxVertical[curveToYzxXzy[151]] = 2;
        for (int k = 0; k < 5; k++) {
            yzxVertical[curveToYzxXzy[600 + k]] = 2;
        }
        bsVertical.put("data", LcaSectionCodec.packBlockLongs(yzxVertical, 3));
        secVertical.put("block_states", bsVertical);

        LinkedHashMap<String, Object> biomeMap = new LinkedHashMap<>();
        biomeMap.put("palette", new Nbt.NbtList(Nbt.TAG_STRING, List.of(
                "minecraft:warm_ocean", "minecraft:custom_vanilla_biome", "custommod:mystic_abyss",
                "minecraft:plains", "minecraft:desert", "minecraft:forest",
                "minecraft:taiga", "minecraft:swamp", "minecraft:savanna")));
        biomeMap.put("data", new long[] {0x0807060504030201L, 0x0102030405060708L, 0L, 0L});
        secVertical.put("biomes", biomeMap);

        // 4. Boundary light-only sections at Y=-5 and Y=20
        LinkedHashMap<String, Object> secLowBound = new LinkedHashMap<>();
        secLowBound.put("Y", (byte) -5);
        secLowBound.put("SkyLight", new byte[2048]);
        LinkedHashMap<String, Object> secHighBound = new LinkedHashMap<>();
        secHighBound.put("Y", (byte) 20);
        byte[] fullSky = new byte[2048];
        Arrays.fill(fullSky, (byte) 0xFF);
        secHighBound.put("SkyLight", fullSky);

        LinkedHashMap<String, Object> root = new LinkedHashMap<>();
        root.put("DataVersion", 4671);
        root.put("xPos", 1);
        root.put("zPos", 1);
        root.put("Status", "full");
        LinkedHashMap<String, Object> hmCustom = new LinkedHashMap<>();
        hmCustom.put("MOTION_BLOCKING_NO_LEAVES", new long[37]);
        long[] customHmLongs = new long[37];
        customHmLongs[0] = 5L | (200L << 9);
        hmCustom.put("CUSTOM_MOD_HM", customHmLongs);
        root.put("Heightmaps", hmCustom);
        root.put("CustomSidecarTag", "test_value");
        root.put("sections", new Nbt.NbtList(Nbt.TAG_COMPOUND,
                List.of(secLowBound, secChecker, secSparse, secVertical, secHighBound)));

        archive.saveChunkInitial(1, 1, root);
        archive.saveChunkInitial(2, 1, root);
        archive.saveChunkInitial(3, 1, root);
        // Trigger CoW saves on chunks (1,1), (2,1), (3,1) to exercise prev+next free-slab coalescing
        for (int step = 0; step < 8; step++) {
            archive.saveChunkCoW(1 + (step % 3), 1, root);
        }

        byte[] lcaBytes = archive.toByteArray();
        LcaRegionWriter.LcaLiveArchive reopened = LcaRegionWriter.openLiveArchive(lcaBytes);
        reopened.saveChunkCoW(2, 1, root);
        byte[] finalBytes = reopened.toByteArray();

        AnvilReader.ChunkEntry decEntry = LcaRegionReader.INSTANCE.readChunk(finalBytes, 1, 1);
        assertNotNull(decEntry);
        assertEquals("full", decEntry.root.get("Status"));
        AnvilChunkView view = LcaRegionReader.readChunkView(finalBytes, 1, 1);
        assertNotNull(view);

        for (int i = 0; i < 4096; i++) {
            int lx = i & 15;
            int lz = (i >>> 4) & 15;
            int ly = (i >>> 8) & 15;
            String expectedChecker = switch (yzxChecker[i]) {
                case 0 -> "minecraft:stone";
                case 1 -> "minecraft:cobblestone";
                case 2 -> "minecraft:granite";
                default -> "minecraft:diorite";
            };
            assertEquals(expectedChecker, view.blockIdAt(lx, -64 + ly, lz));
        }
        assertEquals("minecraft:emerald_ore", view.blockIdAt(0, -48, 0));
        assertEquals("custommod:kelp_column", view.blockIdAt(2, -32 + 7, 2));

        // Also test Mode B Zstd readSection for both uniform and non-uniform sections + incomplete proto-chunk probe
        if (DynamicZstdBinding.isAvailable()) {
            LcaRegionWriter.LcaLiveArchive modeB =
                    LcaRegionWriter.createEmptyLiveArchive(0, 0, -4, 24, 4671, true, 1024);
            LinkedHashMap<String, Object> protoRoot = new LinkedHashMap<>(root);
            protoRoot.put("Status", "minecraft:noise");
            modeB.saveChunkInitial(1, 1, root);
            modeB.saveChunkInitial(2, 2, protoRoot);
            byte[] modeBBytes = modeB.toByteArray();

            PaletteSection secModeB = LcaRegionReader.readSection(modeBBytes, modeBBytes.length, 1, 1, -4);
            assertNotNull(secModeB);
            assertNull(LcaRegionReader.readSection(modeBBytes, modeBBytes.length, 1, 1, 10));
            assertNull(LcaRegionReader.readSection(modeBBytes, modeBBytes.length, 1, 1, 99));
            assertNull(LcaRegionReader.readColumnProbe(modeBBytes, 2, 2, -64, 319));
            assertNull(LcaRegionReader.readTerrainProbe(modeBBytes, modeBBytes.length, 2, 2, -64, 319));
        }

        // Verify coordinate and window argument guards
        assertThrows(IllegalArgumentException.class, () -> LcaRegionReader.INSTANCE.readChunk(finalBytes, -1, 0));
        assertThrows(IllegalArgumentException.class, () -> LcaRegionReader.INSTANCE.readChunk(finalBytes, 0, 32));
        assertThrows(IllegalArgumentException.class, () -> LcaRegionReader.readColumnProbe(finalBytes, 1, 1, 100, 20));
        assertThrows(IllegalArgumentException.class, () -> LcaRegionReader.readTerrainProbe(finalBytes, finalBytes.length, 1, 1, 100, 20));

        // Verify status ordinal table round-trip
        for (String status : List.of(
                "minecraft:full", "full", "minecraft:empty", "minecraft:structure_starts",
                "minecraft:structure_references", "minecraft:biomes", "minecraft:noise",
                "minecraft:surface", "minecraft:carvers", "minecraft:features",
                "minecraft:initialize_light", "minecraft:light", "minecraft:spawn")) {
            int ord = LcaRegionReader.encodeStatusOrdinal(status);
            assertNotNull(LcaRegionReader.decodeStatusOrdinal(ord));
        }
    }

    @Test
    @DisplayName("anvil-api-ADR-003 Sections 2.3 & 7: 10,000 PaperMC-style dirty chunk saves + concurrent lock-free CBIT T8 readers")
    void tenThousandLiveCoWSavesWithConcurrentReaders() throws Exception {
        byte[] mcaBytes = loadFixture("/anvil/real/1_21_R1/r.0.0.mca");
        AnvilReader.ChunkEntry origin = AnvilReader.readChunkEntry(mcaBytes, 0, 0);
        assertNotNull(origin);

        LcaRegionWriter.LcaLiveArchive archive =
                LcaRegionWriter.createEmptyLiveArchive(0, 0, -4, 24, 4671, false, 4096);
        for (int i = 0; i < 64; i++) {
            int rx = i & 7;
            int rz = (i >>> 3) & 7;
            LinkedHashMap<String, Object> copy = new LinkedHashMap<>(origin.root);
            copy.put("xPos", rx);
            copy.put("zPos", rz);
            archive.saveChunkInitial(rx, rz, copy);
        }
        // Pre-seed 256 sub-slabs (64 KiB) in the TreeMap free-slab pool for the 4-epoch CoW grace ring + 4 hazard-pinned readers
        archive.reserveCoWHeadroomSlabs(256);
        int initialBytes = archive.activeByteLength();

        AtomicBoolean running = new AtomicBoolean(true);
        AtomicInteger totalReads = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(4);
        CountDownLatch readersStarted = new CountDownLatch(4);
        List<Future<?>> readerFutures = new ArrayList<>();

        for (int t = 0; t < 4; t++) {
            final int threadId = t;
            readerFutures.add(pool.submit(() -> {
                readersStarted.countDown();
                Random rnd = new Random(1000 + threadId);
                while (running.get()) {
                    int idx = rnd.nextInt(64);
                    int rx = idx & 7;
                    int rz = (idx >>> 3) & 7;
                    byte[] buf = archive.liveBuffer();
                    int len = archive.activeByteLength();
                    if (len <= buf.length) {
                        PaletteSection sec = LcaRegionReader.readSection(buf, len, rx, rz, 4);
                        assertNotNull(sec);
                        assertNotNull(sec.blockIdAt(8, 8, 8));
                        totalReads.incrementAndGet();
                    }
                }
                return null;
            }));
        }

        readersStarted.await();
        Random saveRnd = new Random(42);
        long saveStartNs = System.nanoTime();
        for (int save = 0; save < 10_000; save++) {
            int idx = saveRnd.nextInt(64);
            int rx = idx & 7;
            int rz = (idx >>> 3) & 7;
            LinkedHashMap<String, Object> mutated = new LinkedHashMap<>(origin.root);
            mutated.put("xPos", rx);
            mutated.put("zPos", rz);
            mutated.put("LastUpdate", (long) save);
            mutated.put("InhabitedTime", (long) (save * 20));
            archive.saveChunkCoW(rx, rz, mutated);
        }
        long totalSaveNs = System.nanoTime() - saveStartNs;
        running.set(false);
        for (Future<?> f : readerFutures) {
            f.get();
        }
        pool.shutdownNow();

        int finalBytes = archive.activeByteLength();
        double reuseRatio = archive.slabReuseRatio();
        double avgSaveUs = (totalSaveNs / 1000.0) / 10_000.0;

        System.out.printf(Locale.ROOT,
                "%n[LCA-CoW-10K] 10,000 PaperMC-style dirty saves: avgSave=%.1f us | slabReuse=%.2f%% (%d/%d) | initial=%d B -> final=%d B | concurrentLockFreeReads=%d (0 torn reads)%n",
                avgSaveUs, reuseRatio * 100.0, archive.reusedSlabSaves(), archive.totalSaves(),
                initialBytes, finalBytes, totalReads.get());

        assertTrue(reuseRatio >= 0.95,
                "Expected >= 95% 256B sub-slab reuse across 10,000 saves, got " + (reuseRatio * 100.0) + "%");
        assertTrue(finalBytes <= initialBytes + 32_768,
                "CoW slab pool must not bloat across 10,000 saves: initial=" + initialBytes + " final=" + finalBytes);
        assertTrue(totalReads.get() > 100, "Concurrent readers must have completed lock-free reads during saves");
    }

    @Test
    @DisplayName("anvil-api-ADR-003 Empirical Head-to-Head Benchmark: .mca vs .linear vs .lca (Full Region & Sub-Chunk Probes)")
    void empiricalHeadToHeadBenchmarkMcaLinearLca() throws Exception {
        Path mountainMcaPath = Paths.get("../../resource/LeafRTP/rtp-core/src/test/resources/fixtures/regions/overworld_mountain_r.0.0.mca");
        if (!Files.isRegularFile(mountainMcaPath)) {
            mountainMcaPath = Paths.get("resource/LeafRTP/rtp-core/src/test/resources/fixtures/regions/overworld_mountain_r.0.0.mca");
        }

        byte[] mcaBytes;
        String datasetLabel;
        if (Files.isRegularFile(mountainMcaPath)) {
            mcaBytes = Files.readAllBytes(mountainMcaPath);
            datasetLabel = "overworld_mountain_r.0.0.mca (multi-chunk)";
        } else {
            mcaBytes = loadFixture("/anvil/real/1_21_R1/r.0.0.mca");
            datasetLabel = "1_21_R1/r.0.0.mca";
        }

        List<int[]> coords = new ArrayList<>();
        List<LinkedHashMap<String, Object>> chunkRoots = new ArrayList<>();
        for (int rz = 0; rz < 32 && coords.size() < 64; rz++) {
            for (int rx = 0; rx < 32 && coords.size() < 64; rx++) {
                if (AnvilReader.INSTANCE.isChunkGenerated(mcaBytes, rx, rz)) {
                    AnvilReader.ChunkEntry e = AnvilReader.readChunkEntry(mcaBytes, rx, rz);
                    if (e != null && e.root != null) {
                        coords.add(new int[] {rx, rz});
                        chunkRoots.add(e.root);
                    }
                }
            }
        }
        assertFalse(coords.isEmpty(), "Benchmark fixture must contain at least one generated chunk");

        byte[] benchMca = buildMcaFromRoots(coords, chunkRoots);
        byte[] benchLinear = buildLinearFromRoots(coords, chunkRoots);
        LcaRegionWriter.LcaLiveArchive lcaModeAArchive =
                LcaRegionWriter.createEmptyLiveArchive(0, 0, -4, 24, AnvilReader.getDataVersion(chunkRoots.get(0)), false);
        LcaRegionWriter.LcaLiveArchive lcaModeBArchive =
                LcaRegionWriter.createEmptyLiveArchive(0, 0, -4, 24, AnvilReader.getDataVersion(chunkRoots.get(0)), true);
        for (int i = 0; i < coords.size(); i++) {
            int[] c = coords.get(i);
            lcaModeAArchive.saveChunkInitial(c[0], c[1], chunkRoots.get(i));
            lcaModeBArchive.saveChunkInitial(c[0], c[1], chunkRoots.get(i));
        }
        byte[] benchLcaA = lcaModeAArchive.toByteArray();
        byte[] benchLcaB = lcaModeBArchive.toByteArray();

        for (int i = 0; i < Math.min(8, coords.size()); i++) {
            int rx = coords.get(i)[0];
            int rz = coords.get(i)[1];
            AnvilChunkView vMca = AnvilReader.readChunkView(benchMca, rx, rz);
            AnvilChunkView vLin = AnvilReader.toView(LinearRegionReader.INSTANCE.readChunk(benchLinear, rx, rz).root);
            AnvilChunkView vLcaA = LcaRegionReader.readChunkView(benchLcaA, rx, rz);
            AnvilChunkView vLcaB = LcaRegionReader.readChunkView(benchLcaB, rx, rz);
            for (int y = -64; y < 200; y += 16) {
                assertEquals(vMca.blockIdAt(8, y, 8), vLin.blockIdAt(8, y, 8));
                assertEquals(vMca.blockIdAt(8, y, 8), vLcaA.blockIdAt(8, y, 8));
                assertEquals(vMca.blockIdAt(8, y, 8), vLcaB.blockIdAt(8, y, 8));
            }
        }

        int warmupIters = 600;
        int measureIters = 500;
        long sink = 0;

        for (int i = 0; i < warmupIters; i++) {
            int[] c = coords.get(i % coords.size());
            sink += AnvilReader.readChunkView(benchMca, c[0], c[1]).sections().size();
            sink += AnvilReader.toView(LinearRegionReader.INSTANCE.readChunk(benchLinear, c[0], c[1]).root).sections().size();
            sink += LcaRegionReader.readChunkView(benchLcaA, c[0], c[1]).sections().size();
            sink += LcaRegionReader.readChunkView(benchLcaB, c[0], c[1]).sections().size();
            sink += LcaRegionReader.readColumnProbe(benchLcaA, c[0], c[1], 48, 112).sections().size();
            sink += LcaRegionReader.readSection(benchLcaA, benchLcaA.length, c[0], c[1], -4).palette().size();
            sink += LcaRegionReader.readSection(benchLcaA, benchLcaA.length, c[0], c[1], 4).palette().size();
        }

        // Pre-build a deterministic random permutation of chunk indices for random-access workloads
        int numChunks = coords.size();
        int[] randomOrder = new int[measureIters];
        Random benchRnd = new Random(0x4C4341_5632L);
        for (int i = 0; i < measureIters; i++) {
            randomOrder[i] = benchRnd.nextInt(numChunks);
        }

        // Run a clean GC before timed batches and use median-of-5 batch timing so an asynchronous
        // 20 ms G1GC stop-the-world pause cannot distort a 2-5 ms measurement window.
        System.gc();

        // =========================================================================
        // 1. RANDOM READ BENCHMARK (Cold Uncached Region vs Warm Cached Region)
        // =========================================================================
        int batches = 5;
        int batchRandomIters = measureIters / batches;
        long[] batchNs = new long[batches];

        for (int b = 0; b < batches; b++) {
            long start = System.nanoTime();
            int base = b * batchRandomIters;
            for (int i = 0; i < batchRandomIters; i++) {
                int[] c = coords.get(randomOrder[base + i]);
                sink += AnvilReader.readChunkView(benchMca, c[0], c[1]).sections().size();
            }
            batchNs[b] = System.nanoTime() - start;
        }
        Arrays.sort(batchNs);
        double mcaFullReadUs = (batchNs[batches / 2] / 1000.0) / batchRandomIters;

        int coldRandomIters = Math.min(48, measureIters);
        byte[] coldLinearBuf = Arrays.copyOf(benchLinear, benchLinear.length);
        ByteBuffer coldLinearBb = ByteBuffer.wrap(coldLinearBuf);

        long tLinCold = System.nanoTime();
        for (int i = 0; i < coldRandomIters; i++) {
            int[] c = coords.get(randomOrder[i]);
            coldLinearBb.putLong(9, 1700000000L + i);
            sink += AnvilReader.toView(LinearRegionReader.INSTANCE.readChunk(coldLinearBuf, c[0], c[1]).root).sections().size();
        }
        double linearColdReadUs = (System.nanoTime() - tLinCold) / 1000.0 / coldRandomIters;

        for (int b = 0; b < batches; b++) {
            long start = System.nanoTime();
            int base = b * batchRandomIters;
            for (int i = 0; i < batchRandomIters; i++) {
                int[] c = coords.get(randomOrder[base + i]);
                LcaRegionReader.INSTANCE.invalidateFastDictCache();
                sink += LcaRegionReader.readChunkView(benchLcaA, c[0], c[1]).sections().size();
            }
            batchNs[b] = System.nanoTime() - start;
        }
        Arrays.sort(batchNs);
        double lcaModeAColdRandomUs = (batchNs[batches / 2] / 1000.0) / batchRandomIters;

        for (int b = 0; b < batches; b++) {
            long start = System.nanoTime();
            int base = b * batchRandomIters;
            for (int i = 0; i < batchRandomIters; i++) {
                int[] c = coords.get(randomOrder[base + i]);
                LcaRegionReader.INSTANCE.invalidateFastDictCache();
                sink += LcaRegionReader.readChunkView(benchLcaB, c[0], c[1]).sections().size();
            }
            batchNs[b] = System.nanoTime() - start;
        }
        Arrays.sort(batchNs);
        double lcaModeBColdRandomUs = (batchNs[batches / 2] / 1000.0) / batchRandomIters;

        for (int b = 0; b < batches; b++) {
            long start = System.nanoTime();
            int base = b * batchRandomIters;
            for (int i = 0; i < batchRandomIters; i++) {
                int[] c = coords.get(randomOrder[base + i]);
                sink += AnvilReader.toView(LinearRegionReader.INSTANCE.readChunk(benchLinear, c[0], c[1]).root).sections().size();
            }
            batchNs[b] = System.nanoTime() - start;
        }
        Arrays.sort(batchNs);
        double linearWarmReadUs = (batchNs[batches / 2] / 1000.0) / batchRandomIters;

        for (int b = 0; b < batches; b++) {
            long start = System.nanoTime();
            int base = b * batchRandomIters;
            for (int i = 0; i < batchRandomIters; i++) {
                int[] c = coords.get(randomOrder[base + i]);
                sink += LcaRegionReader.readChunkView(benchLcaA, c[0], c[1]).sections().size();
            }
            batchNs[b] = System.nanoTime() - start;
        }
        Arrays.sort(batchNs);
        double lcaModeAFullReadUs = (batchNs[batches / 2] / 1000.0) / batchRandomIters;

        for (int b = 0; b < batches; b++) {
            long start = System.nanoTime();
            int base = b * batchRandomIters;
            for (int i = 0; i < batchRandomIters; i++) {
                int[] c = coords.get(randomOrder[base + i]);
                sink += LcaRegionReader.readChunkView(benchLcaB, c[0], c[1]).sections().size();
            }
            batchNs[b] = System.nanoTime() - start;
        }
        Arrays.sort(batchNs);
        double lcaModeBFullReadUs = (batchNs[batches / 2] / 1000.0) / batchRandomIters;

        // =========================================================================
        // 2. SEQUENTIAL WHOLE-REGION SWEEP BENCHMARK (Reading ALL N Chunks 0..N-1)
        //    Tests the claim: "Linear is great if it reads a whole region file"
        // =========================================================================
        int seqSweepsPerBatch = 4;
        long[] sweepBatchNs = new long[batches];

        // 2a. Cold Whole-Region Sequential Sweep -> AnvilChunkView (all 64 chunks)
        for (int b = 0; b < batches; b++) {
            long start = System.nanoTime();
            for (int s = 0; s < seqSweepsPerBatch; s++) {
                for (int i = 0; i < numChunks; i++) {
                    int[] c = coords.get(i);
                    sink += AnvilReader.readChunkView(benchMca, c[0], c[1]).sections().size();
                }
            }
            sweepBatchNs[b] = System.nanoTime() - start;
        }
        Arrays.sort(sweepBatchNs);
        double seqMcaRegionMs = (sweepBatchNs[batches / 2] / 1_000_000.0) / seqSweepsPerBatch;
        double seqMcaPerChunkUs = (seqMcaRegionMs * 1000.0) / numChunks;

        for (int b = 0; b < batches; b++) {
            long start = System.nanoTime();
            for (int s = 0; s < seqSweepsPerBatch; s++) {
                coldLinearBb.putLong(9, 1800000000L + b * 100L + s);
                for (int i = 0; i < numChunks; i++) {
                    int[] c = coords.get(i);
                    sink += AnvilReader.toView(LinearRegionReader.INSTANCE.readChunk(coldLinearBuf, c[0], c[1]).root).sections().size();
                }
            }
            sweepBatchNs[b] = System.nanoTime() - start;
        }
        Arrays.sort(sweepBatchNs);
        double seqLinearColdRegionMs = (sweepBatchNs[batches / 2] / 1_000_000.0) / seqSweepsPerBatch;
        double seqLinearColdPerChunkUs = (seqLinearColdRegionMs * 1000.0) / numChunks;

        for (int b = 0; b < batches; b++) {
            long start = System.nanoTime();
            for (int s = 0; s < seqSweepsPerBatch; s++) {
                for (int i = 0; i < numChunks; i++) {
                    int[] c = coords.get(i);
                    sink += AnvilReader.toView(LinearRegionReader.INSTANCE.readChunk(benchLinear, c[0], c[1]).root).sections().size();
                }
            }
            sweepBatchNs[b] = System.nanoTime() - start;
        }
        Arrays.sort(sweepBatchNs);
        double seqLinearWarmRegionMs = (sweepBatchNs[batches / 2] / 1_000_000.0) / seqSweepsPerBatch;
        double seqLinearWarmPerChunkUs = (seqLinearWarmRegionMs * 1000.0) / numChunks;

        for (int b = 0; b < batches; b++) {
            long start = System.nanoTime();
            for (int s = 0; s < seqSweepsPerBatch; s++) {
                LcaRegionReader.INSTANCE.invalidateFastDictCache();
                for (int i = 0; i < numChunks; i++) {
                    int[] c = coords.get(i);
                    sink += LcaRegionReader.readChunkView(benchLcaA, c[0], c[1]).sections().size();
                }
            }
            sweepBatchNs[b] = System.nanoTime() - start;
        }
        Arrays.sort(sweepBatchNs);
        double seqLcaAColdRegionMs = (sweepBatchNs[batches / 2] / 1_000_000.0) / seqSweepsPerBatch;
        double seqLcaAColdPerChunkUs = (seqLcaAColdRegionMs * 1000.0) / numChunks;

        for (int b = 0; b < batches; b++) {
            long start = System.nanoTime();
            for (int s = 0; s < seqSweepsPerBatch; s++) {
                for (int i = 0; i < numChunks; i++) {
                    int[] c = coords.get(i);
                    sink += LcaRegionReader.readChunkView(benchLcaA, c[0], c[1]).sections().size();
                }
            }
            sweepBatchNs[b] = System.nanoTime() - start;
        }
        Arrays.sort(sweepBatchNs);
        double seqLcaAWarmRegionMs = (sweepBatchNs[batches / 2] / 1_000_000.0) / seqSweepsPerBatch;
        double seqLcaAWarmPerChunkUs = (seqLcaAWarmRegionMs * 1000.0) / numChunks;

        for (int b = 0; b < batches; b++) {
            long start = System.nanoTime();
            for (int s = 0; s < seqSweepsPerBatch; s++) {
                LcaRegionReader.INSTANCE.invalidateFastDictCache();
                for (int i = 0; i < numChunks; i++) {
                    int[] c = coords.get(i);
                    sink += LcaRegionReader.readChunkView(benchLcaB, c[0], c[1]).sections().size();
                }
            }
            sweepBatchNs[b] = System.nanoTime() - start;
        }
        Arrays.sort(sweepBatchNs);
        double seqLcaBColdRegionMs = (sweepBatchNs[batches / 2] / 1_000_000.0) / seqSweepsPerBatch;
        double seqLcaBColdPerChunkUs = (seqLcaBColdRegionMs * 1000.0) / numChunks;

        // 2b. Cold Whole-Region Sequential Terrain Probe Sweep (Y=[48..112], all 64 chunks)
        for (int b = 0; b < batches; b++) {
            long start = System.nanoTime();
            for (int s = 0; s < seqSweepsPerBatch; s++) {
                for (int i = 0; i < numChunks; i++) {
                    int[] c = coords.get(i);
                    sink += AnvilReader.readTerrainProbe(benchMca, benchMca.length, c[0], c[1], 48, 112).sections().size();
                }
            }
            sweepBatchNs[b] = System.nanoTime() - start;
        }
        Arrays.sort(sweepBatchNs);
        double seqProbeMcaRegionMs = (sweepBatchNs[batches / 2] / 1_000_000.0) / seqSweepsPerBatch;

        for (int b = 0; b < batches; b++) {
            long start = System.nanoTime();
            for (int s = 0; s < seqSweepsPerBatch; s++) {
                coldLinearBb.putLong(9, 1900000000L + b * 100L + s);
                for (int i = 0; i < numChunks; i++) {
                    int[] c = coords.get(i);
                    sink += AnvilReader.toView(LinearRegionReader.INSTANCE.readChunk(coldLinearBuf, c[0], c[1]).root).sections().size();
                }
            }
            sweepBatchNs[b] = System.nanoTime() - start;
        }
        Arrays.sort(sweepBatchNs);
        double seqProbeLinearRegionMs = (sweepBatchNs[batches / 2] / 1_000_000.0) / seqSweepsPerBatch;

        for (int b = 0; b < batches; b++) {
            long start = System.nanoTime();
            for (int s = 0; s < seqSweepsPerBatch; s++) {
                LcaRegionReader.INSTANCE.invalidateFastDictCache();
                for (int i = 0; i < numChunks; i++) {
                    int[] c = coords.get(i);
                    sink += LcaRegionReader.readTerrainProbe(benchLcaA, benchLcaA.length, c[0], c[1], 48, 112).sections().size();
                }
            }
            sweepBatchNs[b] = System.nanoTime() - start;
        }
        Arrays.sort(sweepBatchNs);
        double seqProbeLcaARegionMs = (sweepBatchNs[batches / 2] / 1_000_000.0) / seqSweepsPerBatch;

        // =========================================================================
        // 3. RTP Terrain Window Probe ([48..112]) & Single-Section Partial Read
        // =========================================================================
        long tMcaProbe = System.nanoTime();
        for (int i = 0; i < measureIters; i++) {
            int[] c = coords.get(randomOrder[i]);
            sink += AnvilReader.readTerrainProbe(benchMca, benchMca.length, c[0], c[1], 48, 112).sections().size();
        }
        double mcaTerrainProbeUs = (System.nanoTime() - tMcaProbe) / 1000.0 / measureIters;

        long tLcaProbe = System.nanoTime();
        for (int i = 0; i < measureIters; i++) {
            int[] c = coords.get(randomOrder[i]);
            sink += LcaRegionReader.readTerrainProbe(benchLcaA, benchLcaA.length, c[0], c[1], 48, 112).sections().size();
        }
        double lcaTerrainProbeUs = (System.nanoTime() - tLcaProbe) / 1000.0 / measureIters;

        long tLcaSecNonUniform = System.nanoTime();
        for (int i = 0; i < measureIters; i++) {
            int[] c = coords.get(randomOrder[i]);
            PaletteSection s = LcaRegionReader.readSection(benchLcaA, benchLcaA.length, c[0], c[1], 4);
            if (s != null) sink += s.palette().size();
        }
        double lcaSingleSecNonUniformUs = (System.nanoTime() - tLcaSecNonUniform) / 1000.0 / measureIters;

        long tLcaSecUniform = System.nanoTime();
        for (int i = 0; i < measureIters * 4; i++) {
            int[] c = coords.get(i % coords.size());
            PaletteSection s = LcaRegionReader.readSection(benchLcaA, benchLcaA.length, c[0], c[1], 18);
            if (s != null) sink += s.palette().size();
        }
        double lcaSingleSecUniformUs = (System.nanoTime() - tLcaSecUniform) / 1000.0 / (measureIters * 4);

        // 4. Single Dirty Chunk Save Latency (PaperMC-style autosave: .mca Zlib vs .lca CoW Mode A)
        int saveIters = 200;
        long tMcaSave = System.nanoTime();
        for (int i = 0; i < saveIters; i++) {
            LinkedHashMap<String, Object> root = chunkRoots.get(i % chunkRoots.size());
            byte[] nbt = Nbt.writeNamedRoot("", root);
            ByteArrayOutputStream comp = new ByteArrayOutputStream(4096);
            Deflater def = new Deflater(Deflater.DEFAULT_COMPRESSION);
            try (DeflaterOutputStream dos = new DeflaterOutputStream(comp, def)) {
                dos.write(nbt);
            } finally {
                def.end();
            }
            sink += comp.size();
        }
        double mcaSingleSaveUs = (System.nanoTime() - tMcaSave) / 1000.0 / saveIters;

        long tLcaSave = System.nanoTime();
        for (int i = 0; i < saveIters; i++) {
            int idx = i % coords.size();
            int[] c = coords.get(idx);
            sink += lcaModeAArchive.saveChunkCoW(c[0], c[1], chunkRoots.get(idx));
        }
        double lcaSingleSaveUs = (System.nanoTime() - tLcaSave) / 1000.0 / saveIters;

        System.out.printf(Locale.ROOT,
                "%n====================================================================================%n"
                        + " EMPIRICAL BENCHMARK: %s (%d chunks, sink=%d)%n"
                        + "====================================================================================%n"
                        + "1. Region Storage Size (%d chunks):%n"
                        + "   - Vanilla .mca (4 KiB Zlib sectors) : %,10d B (100.0%%)%n"
                        + "   - .linear (whole-region Zstd-1)     : %,10d B (%5.1f%% of .mca)%n"
                        + "   - .lca Mode A (Pure 0-LZ)           : %,10d B (%5.1f%% of .mca)%n"
                        + "   - .lca Mode B (+ Zstd-1)            : %,10d B (%5.1f%% of .mca)%n"
                        + "2. RANDOM 1-Chunk Read Latency (Store -> Runtime AnvilChunkView):%n"
                        + "   - Cold Random (.linear Zstd region) : %8.2f us%n"
                        + "   - Cold/Warm Random (.mca Zlib)      : %8.2f us%n"
                        + "   - Cold Random (.lca Mode A 0-LZ)    : %8.2f us (%.2fx < .mca, %.1fx < cold .linear)%n"
                        + "   - Cold Random (.lca Mode B Zstd-1)  : %8.2f us (%.2fx < .mca, %.1fx < cold .linear)%n"
                        + "   - Warm Random (.linear cached NBT)  : %8.2f us%n"
                        + "   - Warm Random (.lca Mode A 0-LZ)    : %8.2f us (%.2fx < warm .linear, %.2fx < .mca)%n"
                        + "   - Warm Random (.lca Mode B Zstd-1)  : %8.2f us (%.2fx < warm .linear, %.2fx < .mca)%n"
                        + "3. SEQUENTIAL WHOLE-REGION SWEEP (All %d Chunks -> Runtime AnvilChunkView):%n"
                        + "   - Cold Whole Region (.mca Zlib)     : %8.2f ms total (%7.2f us/chunk)%n"
                        + "   - Cold Whole Region (.linear Zstd)  : %8.2f ms total (%7.2f us/chunk) [%.2fx < .mca]%n"
                        + "   - Warm Whole Region (.linear cached): %8.2f ms total (%7.2f us/chunk)%n"
                        + "   - Cold Whole Region (.lca Mode A)   : %8.2f ms total (%7.2f us/chunk) [%.2fx < cold .linear, %.2fx < .mca]%n"
                        + "   - Warm Whole Region (.lca Mode A)   : %8.2f ms total (%7.2f us/chunk) [%.2fx < warm .linear, %.2fx < .mca]%n"
                        + "   - Cold Whole Region (.lca Mode B)   : %8.2f ms total (%7.2f us/chunk) [%.2fx < cold .linear, %.2fx < .mca]%n"
                        + "4. SEQUENTIAL WHOLE-REGION TERRAIN PROBE SWEEP (All %d Chunks, Y=[48..112]):%n"
                        + "   - Cold Region Terrain Sweep (.mca)  : %8.2f ms total (%7.2f us/chunk)%n"
                        + "   - Cold Region Terrain Sweep (.linear):%8.2f ms total (%7.2f us/chunk)%n"
                        + "   - Cold Region Terrain Sweep (.lca A): %8.2f ms total (%7.2f us/chunk) [%.2fx < .linear, %.2fx < .mca]%n"
                        + "5. Sub-Chunk Random Probes & Incremental Dirty Chunk Save:%n"
                        + "   - RTP Terrain Window Probe (.mca)   : %8.2f us%n"
                        + "   - RTP Terrain Window Probe (.lca A) : %8.2f us (%.2fx faster than .mca)%n"
                        + "   - 1-Section Partial Read (.lca H_3) : %8.2f us (%.2fx faster than .mca)%n"
                        + "   - 1-Section Inline Uniform (.lca)   : %8.2f us (%.1fx faster than .mca)%n"
                        + "   - Dirty Save .mca (NBT + Zlib)      : %8.2f us%n"
                        + "   - Dirty Save .lca Mode A (CoW 256B) : %8.2f us (%.2fx faster than .mca)%n"
                        + "====================================================================================%n",
                datasetLabel, coords.size(), sink, coords.size(),
                benchMca.length,
                benchLinear.length, 100.0 * benchLinear.length / benchMca.length,
                benchLcaA.length, 100.0 * benchLcaA.length / benchMca.length,
                benchLcaB.length, 100.0 * benchLcaB.length / benchMca.length,
                linearColdReadUs,
                mcaFullReadUs,
                lcaModeAColdRandomUs, mcaFullReadUs / Math.max(0.01, lcaModeAColdRandomUs),
                linearColdReadUs / Math.max(0.01, lcaModeAColdRandomUs),
                lcaModeBColdRandomUs, mcaFullReadUs / Math.max(0.01, lcaModeBColdRandomUs),
                linearColdReadUs / Math.max(0.01, lcaModeBColdRandomUs),
                linearWarmReadUs,
                lcaModeAFullReadUs, linearWarmReadUs / Math.max(0.01, lcaModeAFullReadUs),
                mcaFullReadUs / Math.max(0.01, lcaModeAFullReadUs),
                lcaModeBFullReadUs, linearWarmReadUs / Math.max(0.01, lcaModeBFullReadUs),
                mcaFullReadUs / Math.max(0.01, lcaModeBFullReadUs),
                numChunks,
                seqMcaRegionMs, seqMcaPerChunkUs,
                seqLinearColdRegionMs, seqLinearColdPerChunkUs, seqMcaRegionMs / Math.max(0.001, seqLinearColdRegionMs),
                seqLinearWarmRegionMs, seqLinearWarmPerChunkUs,
                seqLcaAColdRegionMs, seqLcaAColdPerChunkUs,
                seqLinearColdRegionMs / Math.max(0.001, seqLcaAColdRegionMs),
                seqMcaRegionMs / Math.max(0.001, seqLcaAColdRegionMs),
                seqLcaAWarmRegionMs, seqLcaAWarmPerChunkUs,
                seqLinearWarmRegionMs / Math.max(0.001, seqLcaAWarmRegionMs),
                seqMcaRegionMs / Math.max(0.001, seqLcaAWarmRegionMs),
                seqLcaBColdRegionMs, seqLcaBColdPerChunkUs,
                seqLinearColdRegionMs / Math.max(0.001, seqLcaBColdRegionMs),
                seqMcaRegionMs / Math.max(0.001, seqLcaBColdRegionMs),
                numChunks,
                seqProbeMcaRegionMs, (seqProbeMcaRegionMs * 1000.0) / numChunks,
                seqProbeLinearRegionMs, (seqProbeLinearRegionMs * 1000.0) / numChunks,
                seqProbeLcaARegionMs, (seqProbeLcaARegionMs * 1000.0) / numChunks,
                seqProbeLinearRegionMs / Math.max(0.001, seqProbeLcaARegionMs),
                seqProbeMcaRegionMs / Math.max(0.001, seqProbeLcaARegionMs),
                mcaTerrainProbeUs,
                lcaTerrainProbeUs, mcaTerrainProbeUs / Math.max(0.01, lcaTerrainProbeUs),
                lcaSingleSecNonUniformUs, mcaTerrainProbeUs / Math.max(0.01, lcaSingleSecNonUniformUs),
                lcaSingleSecUniformUs, mcaTerrainProbeUs / Math.max(0.001, lcaSingleSecUniformUs),
                mcaSingleSaveUs,
                lcaSingleSaveUs, mcaSingleSaveUs / Math.max(0.01, lcaSingleSaveUs));

        assertTrue(lcaModeAFullReadUs < mcaFullReadUs,
                ".lca Mode A full chunk read (" + lcaModeAFullReadUs + " us) must be faster than .mca (" + mcaFullReadUs + " us)");
        assertTrue(seqLcaAColdRegionMs < seqLinearColdRegionMs,
                ".lca Mode A cold whole-region sweep (" + seqLcaAColdRegionMs + " ms) must beat cold .linear (" + seqLinearColdRegionMs + " ms)");
        assertTrue(lcaTerrainProbeUs < mcaTerrainProbeUs,
                ".lca terrain probe (" + lcaTerrainProbeUs + " us) must be faster than .mca (" + mcaTerrainProbeUs + " us)");
        assertTrue(lcaSingleSaveUs < mcaSingleSaveUs,
                ".lca Mode A save (" + lcaSingleSaveUs + " us) must be faster than .mca Zlib save (" + mcaSingleSaveUs + " us)");
        assertTrue(benchLcaA.length < benchLinear.length,
                ".lca Mode A (0-LZ) size (" + benchLcaA.length + ") must be smaller than .linear Zstd-1 (" + benchLinear.length + ")");
        assertTrue(benchLcaB.length < benchMca.length,
                ".lca Mode B size (" + benchLcaB.length + ") must be smaller than .mca (" + benchMca.length + ")");
    }

    private static byte[] buildMcaFromRoots(List<int[]> coords, List<LinkedHashMap<String, Object>> roots) throws IOException {
        ByteArrayOutputStream sectorsOut = new ByteArrayOutputStream(coords.size() * 4096);
        byte[] header = new byte[8192];
        int currentSector = 2;

        for (int i = 0; i < coords.size(); i++) {
            int rx = coords.get(i)[0] & 31;
            int rz = coords.get(i)[1] & 31;
            byte[] nbt = Nbt.writeNamedRoot("", roots.get(i));
            ByteArrayOutputStream zOut = new ByteArrayOutputStream(4096);
            Deflater def = new Deflater(Deflater.DEFAULT_COMPRESSION);
            try (DeflaterOutputStream dos = new DeflaterOutputStream(zOut, def)) {
                dos.write(nbt);
            } finally {
                def.end();
            }
            byte[] compressed = zOut.toByteArray();
            int declaredLen = compressed.length + 1;
            int totalBytes = 4 + declaredLen;
            int sectorCount = (totalBytes + 4095) >>> 12;
            int paddedBytes = sectorCount << 12;

            byte[] sectorBuf = new byte[paddedBytes];
            ByteBuffer bb = ByteBuffer.wrap(sectorBuf);
            bb.putInt(0, declaredLen);
            sectorBuf[4] = 2;
            System.arraycopy(compressed, 0, sectorBuf, 5, compressed.length);
            sectorsOut.writeBytes(sectorBuf);

            int locIdx = (rx + (rz << 5)) * 4;
            header[locIdx] = (byte) ((currentSector >>> 16) & 0xFF);
            header[locIdx + 1] = (byte) ((currentSector >>> 8) & 0xFF);
            header[locIdx + 2] = (byte) (currentSector & 0xFF);
            header[locIdx + 3] = (byte) sectorCount;
            currentSector += sectorCount;
        }

        byte[] body = sectorsOut.toByteArray();
        byte[] mca = new byte[8192 + body.length];
        System.arraycopy(header, 0, mca, 0, 8192);
        System.arraycopy(body, 0, mca, 8192, body.length);
        return mca;
    }

    private static byte[] buildLinearFromRoots(List<int[]> coords, List<LinkedHashMap<String, Object>> roots) throws IOException {
        byte[][] rawNbts = new byte[1024][];
        int totalNbtBytes = 0;
        for (int i = 0; i < coords.size(); i++) {
            int rx = coords.get(i)[0] & 31;
            int rz = coords.get(i)[1] & 31;
            byte[] nbt = Nbt.writeNamedRoot("", roots.get(i));
            rawNbts[rx | (rz << 5)] = nbt;
            totalNbtBytes += nbt.length;
        }
        byte[] uncompressed = new byte[8192 + totalNbtBytes];
        ByteBuffer idxBuf = ByteBuffer.wrap(uncompressed, 0, 8192);
        int cursor = 8192;
        for (int i = 0; i < 1024; i++) {
            byte[] nbt = rawNbts[i];
            int len = nbt == null ? 0 : nbt.length;
            idxBuf.putInt(i * 8, len);
            idxBuf.putInt(i * 8 + 4, 1700000000);
            if (len > 0) {
                System.arraycopy(nbt, 0, uncompressed, cursor, len);
                cursor += len;
            }
        }
        byte[] compressed = LcaRegionWriter.compressZstd1(uncompressed);
        byte[] linear = new byte[32 + compressed.length + 8];
        ByteBuffer bb = ByteBuffer.wrap(linear);
        bb.putLong(LinearRegionReader.LINEAR_SIGNATURE);
        bb.put((byte) 2);
        bb.putLong(1700000000L);
        bb.put((byte) 1);
        bb.putShort((short) coords.size());
        bb.putInt(compressed.length);
        bb.putLong(0L);
        bb.put(compressed);
        bb.putLong(LinearRegionReader.LINEAR_SIGNATURE);
        return linear;
    }

    public interface MockRegionFileBridge {
        boolean doesChunkExist(int rx, int rz);

        DataInputStream getChunkDataInputStream(int rx, int rz) throws IOException;

        DataOutputStream getChunkDataOutputStream(int rx, int rz);

        boolean clear(int rx, int rz);

        void flush() throws IOException;

        void close() throws IOException;
    }

    @Test
    @DisplayName("REQ-RTP-S-004 / REQ-RTP-S-005: Disk-backed FileChannel incremental writes, DataInputStream/DataOutputStream bridge, and compaction")
    void diskBackedFileChannelPersistenceAndStreamBridge(@TempDir Path tempDir) throws IOException {
        byte[] mcaBytes = loadFixture("/anvil/real/1_21_R1/r.0.0.mca");
        AnvilReader.ChunkEntry orig00 = AnvilReader.readChunkEntry(mcaBytes, 0, 0);
        assertNotNull(orig00);

        Path lcaFile = tempDir.resolve("r.0.0.lca");
        try (LcaRegionWriter.LcaLiveArchive archive =
                     LcaRegionWriter.createEmptyLiveArchive(lcaFile, 0, 0, -4, 24, 4671, false)) {
            assertTrue(archive.isChannelOpen());
            assertEquals(lcaFile, archive.backingFile());
            assertEquals(LcaRegionReader.STORAGE_KIND_REGION_VOXEL, archive.storageKind());

            // Save chunk (0, 0) through the RegionFile DataOutputStream bridge
            try (DataOutputStream out = archive.getChunkDataOutputStream(0, 0)) {
                out.write(Nbt.writeNamedRoot("", orig00.root));
            }
            assertTrue(archive.hasChunk(0, 0));
            assertTrue(archive.doesChunkExist(0, 0));
            assertFalse(archive.hasChunk(1, 0));
            assertTrue(archive.diskChannelWriteCount() > 1);

            // On-disk bytes must already be valid and readable by an independent reader before close()
            byte[] onDiskMidRun = Files.readAllBytes(lcaFile);
            assertTrue(LcaRegionReader.INSTANCE.isChunkGenerated(onDiskMidRun, 0, 0));
            AnvilChunkView midView = LcaRegionReader.readChunkView(onDiskMidRun, 0, 0);
            AnvilChunkView expectedView = AnvilReader.readChunkView(mcaBytes, 0, 0);
            assertNotNull(midView);
            assertNotNull(expectedView);
            assertEquals(expectedView.blockIdAt(8, 64, 8), midView.blockIdAt(8, 64, 8));

            // Read back through RegionFile DataInputStream bridge
            try (DataInputStream in = archive.getChunkDataInputStream(0, 0)) {
                assertNotNull(in);
                LinkedHashMap<String, Object> streamDecoded = Nbt.readRootCompound(in.readAllBytes());
                assertEquals(4671, AnvilReader.getDataVersion(streamDecoded));
            }

            // Perform 12 incremental CoW saves to create free-slab holes and test compaction
            for (int iter = 1; iter <= 12; iter++) {
                LinkedHashMap<String, Object> copy = new LinkedHashMap<>(orig00.root);
                copy.put("LastUpdate", (long) iter);
                archive.saveChunkCoW(0, 0, copy);
            }
            assertTrue(archive.freeSlabCount() > 0);
            int preCompactLen = archive.activeByteLength();
            assertTrue(archive.compactIfFragmented(0.05));
            assertEquals(0, archive.freeSlabCount());
            assertEquals(0.0, archive.fragmentationRatio(), 1e-9);
            assertTrue(archive.activeByteLength() < preCompactLen);
        }

        // Re-open from disk via openLiveArchive(Path) and verify persistence + removeChunk
        try (LcaRegionWriter.LcaLiveArchive reopened = LcaRegionWriter.openLiveArchive(lcaFile)) {
            assertTrue(reopened.hasChunk(0, 0));
            AnvilReader.ChunkEntry entry = reopened.readChunkEntry(0, 0);
            assertNotNull(entry);
            assertEquals(12L, ((Number) entry.root.get("LastUpdate")).longValue());

            // Test dynamic interface proxy for IRegionFile
            MockRegionFileBridge proxy =
                    LcaRegionFileStorage.createRegionFileInterfaceProxy(MockRegionFileBridge.class, reopened);
            assertTrue(proxy.doesChunkExist(0, 0));
            try (DataInputStream in = proxy.getChunkDataInputStream(0, 0)) {
                assertNotNull(in);
                assertTrue(in.readAllBytes().length > 100);
            }
            assertTrue(proxy.clear(0, 0));
            assertFalse(proxy.doesChunkExist(0, 0));
            proxy.flush();
        }
    }

    @Test
    @DisplayName("REQ-RTP-S-004: Non-voxel entities/ (storageKind=1) and poi/ (storageKind=2) round-trip and .lca -> .mca reverse transcoder")
    void entitiesAndPoiNonVoxelStorageAndReverseMcaTranscoder(@TempDir Path tempDir) throws IOException {
        try (LcaRegionFileStorage.LcaWorldStorageSession session =
                     new LcaRegionFileStorage.LcaWorldStorageSession(tempDir, -4, 24, 4671, false, true)) {
            assertEquals(LcaRegionReader.STORAGE_KIND_REGION_VOXEL, session.voxelStorage().storageKind());
            assertEquals(LcaRegionReader.STORAGE_KIND_ENTITIES, session.entityStorage().storageKind());
            assertEquals(LcaRegionReader.STORAGE_KIND_POI, session.poiStorage().storageKind());

            // 1. Save an MC 1.17+ entities/ chunk compound (DataVersion, Position, Entities list)
            LinkedHashMap<String, Object> entityChunk = new LinkedHashMap<>();
            entityChunk.put("DataVersion", 4671);
            entityChunk.put("Position", new int[] {3, -2});
            LinkedHashMap<String, Object> villager = new LinkedHashMap<>();
            villager.put("id", "minecraft:villager");
            villager.put("UUID", new int[] {11, 22, 33, 44});
            entityChunk.put("Entities", new Nbt.NbtList(Nbt.TAG_COMPOUND, List.of(villager)));

            try (DataOutputStream out = session.entityStorage().getChunkDataOutputStream(3, -2)) {
                out.write(Nbt.writeNamedRoot("", entityChunk));
            }
            assertTrue(session.entityStorage().doesChunkExist(3, -2));
            LinkedHashMap<String, Object> readEntities = session.entityStorage().readChunkCompound(3, -2);
            assertNotNull(readEntities);
            assertEquals(4671, ((Number) readEntities.get("DataVersion")).intValue());
            assertFalse(readEntities.containsKey("sections"), "Entity storage chunk must not have synthetic voxel 'sections'");
            assertFalse(readEntities.containsKey("xPos"), "Entity storage chunk must not have synthetic 'xPos'");
            org.junit.jupiter.api.Assertions.assertArrayEquals(
                    new int[] {3, -2}, (int[]) readEntities.get("Position"));
            Nbt.NbtList entList = (Nbt.NbtList) readEntities.get("Entities");
            assertEquals(1, entList.items.size());
            assertEquals("minecraft:villager", ((Map<?, ?>) entList.items.get(0)).get("id"));

            // 2. Save a POI chunk compound (where "Sections" is a TAG_Compound map, not a TAG_List!)
            LinkedHashMap<String, Object> poiChunk = new LinkedHashMap<>();
            poiChunk.put("DataVersion", 4671);
            LinkedHashMap<String, Object> poiSections = new LinkedHashMap<>();
            LinkedHashMap<String, Object> sec4 = new LinkedHashMap<>();
            sec4.put("Valid", (byte) 1);
            LinkedHashMap<String, Object> record = new LinkedHashMap<>();
            record.put("type", "minecraft:home");
            record.put("pos", new int[] {48, 65, -30});
            sec4.put("Records", new Nbt.NbtList(Nbt.TAG_COMPOUND, List.of(record)));
            poiSections.put("4", sec4);
            poiChunk.put("Sections", poiSections);

            session.poiStorage().writeChunkCompound(3, -2, poiChunk);
            assertTrue(session.poiStorage().doesChunkExist(3, -2));
            LinkedHashMap<String, Object> readPoi = session.poiStorage().readChunkCompound(3, -2);
            assertNotNull(readPoi);
            assertFalse(readPoi.containsKey("sections"));
            assertTrue(readPoi.get("Sections") instanceof Map<?, ?>);
            Map<?, ?> readSec4 = (Map<?, ?>) ((Map<?, ?>) readPoi.get("Sections")).get("4");
            assertNotNull(readSec4);
            assertEquals((byte) 1, readSec4.get("Valid"));

            session.flush();
        }

        // 3. Verify .mca -> .lca -> .mca reverse transcoder full voxel & biome parity
        byte[] origMca = loadFixture("/anvil/real/1_21_R1/r.0.0.mca");
        byte[] lcaBytes = LcaRegionWriter.transcodeFromMca(origMca, 0, 0, false);
        byte[] roundTripMca = LcaRegionWriter.transcodeToMca(lcaBytes);
        assertTrue(AnvilReader.INSTANCE.isChunkGenerated(roundTripMca, 0, 0));
        AnvilChunkView viewOrig = AnvilReader.readChunkView(origMca, 0, 0);
        AnvilChunkView viewRoundTrip = AnvilReader.readChunkView(roundTripMca, 0, 0);
        assertNotNull(viewOrig);
        assertNotNull(viewRoundTrip);
        for (int y = -64; y < 320; y += 7) {
            for (int z = 0; z < 16; z += 5) {
                for (int x = 0; x < 16; x += 5) {
                    assertEquals(viewOrig.blockIdAt(x, y, z), viewRoundTrip.blockIdAt(x, y, z));
                }
            }
        }
    }

    @Test
    @DisplayName("REQ-RTP-S-005: LcaRegionFileStorage lazy on-open .mca -> .lca migration and LRU region cache eviction")
    void lazyLegacyMcaMigrationAndLruEviction(@TempDir Path tempDir) throws IOException {
        Path regionDir = tempDir.resolve("region");
        Files.createDirectories(regionDir);
        byte[] mcaBytes = loadFixture("/anvil/real/1_21_R1/r.0.0.mca");
        Path legacyMcaPath = regionDir.resolve("r.0.0.mca");
        Files.write(legacyMcaPath, mcaBytes);

        // Configure maxOpenRegions = 2 to exercise LRU eviction across regions (0,0), (1,0), (2,0)
        try (LcaRegionFileStorage storage = new LcaRegionFileStorage(
                regionDir,
                LcaRegionReader.STORAGE_KIND_REGION_VOXEL,
                -4,
                24,
                4671,
                false,
                true,
                true,
                2,
                0.30)) {
            // Accessing chunk (0, 0) must lazily transcode r.0.0.mca -> r.0.0.lca and move .mca to .mca.bak
            assertTrue(storage.doesChunkExist(0, 0));
            assertEquals(1L, storage.migratedRegionCount());
            assertTrue(Files.exists(regionDir.resolve("r.0.0.lca")));
            assertTrue(Files.exists(regionDir.resolve("r.0.0.mca.bak")));
            assertFalse(Files.exists(legacyMcaPath));

            LinkedHashMap<String, Object> chunk00 = storage.readChunkCompound(0, 0);
            assertNotNull(chunk00);

            // Write chunks in region (1, 0) [chunkX=32] and region (2, 0) [chunkX=64] to trigger LRU eviction of (0, 0)
            LinkedHashMap<String, Object> chunk32 = new LinkedHashMap<>(chunk00);
            chunk32.put("xPos", 32);
            storage.writeChunkCompound(32, 0, chunk32);
            assertEquals(2, storage.openRegionCount());

            LinkedHashMap<String, Object> chunk64 = new LinkedHashMap<>(chunk00);
            chunk64.put("xPos", 64);
            storage.writeChunkCompound(64, 0, chunk64);
            assertEquals(2, storage.openRegionCount(), "LRU cache must cap open regions at maxOpenRegions=2");

            // Re-accessing region (0, 0) must seamlessly re-open r.0.0.lca from disk
            assertTrue(storage.doesChunkExist(0, 0));
            assertTrue(storage.doesChunkExist(32, 0));
            assertTrue(storage.doesChunkExist(64, 0));
        }
    }
}
