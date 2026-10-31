package io.github.dailystruggle.rtp.anvil;

import java.io.Closeable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Disk-backed `.lca` region-folder storage manager and `RegionFile` stream hook
 * (`anvil-api-ADR-003` Sections 2.1, 2.3, 4; `anvil-api-ADR-002`).
 *
 * <p>Mirrors Mojang's `net.minecraft.world.level.chunk.storage.RegionFileStorage` and `RegionFile`
 * stream contract (`getChunkDataInputStream`, `getChunkDataOutputStream`, `doesChunkExist`, `flush`,
 * `close`) over a bounded LRU cache of open {@link LcaRegionWriter.LcaLiveArchive} handles,
 * supporting `region/` (`STORAGE_KIND_REGION_VOXEL`), `entities/` (`STORAGE_KIND_ENTITIES`), and
 * `poi/` (`STORAGE_KIND_POI`) folders as well as lazy on-open `.mca` / `.linear` -> `.lca`
 * atomic region migration.</p>
 *
 * @governedBy anvil-api-ADR-003
 * @governedBy anvil-api-ADR-002
 * @governedBy ADR-115
 * @trace REQ-RTP-S-004
 * @trace REQ-RTP-S-005
 */
public final class LcaRegionFileStorage implements Closeable, AutoCloseable {

    /** Default maximum open `.lca` region handles per storage folder, matching vanilla `RegionFileStorage` (256). */
    public static final int DEFAULT_MAX_OPEN_REGIONS = 256;

    /** Default free-slab fragmentation ratio threshold (`35%`) triggering compaction on region eviction/close. */
    public static final double DEFAULT_COMPACT_FRAGMENTATION_THRESHOLD = 0.35;

    private final Path storageDirectory;
    private final int storageKind;
    private final int minSectionY;
    private final int sectionCount;
    private final int defaultDataVersion;
    private final boolean modeBZstd;
    private final boolean autoMigrateLegacy;
    private final boolean backupMigratedLegacyFiles;
    private final int maxOpenRegions;
    private final double compactFragmentationThreshold;

    private final LinkedHashMap<Long, LcaRegionWriter.LcaLiveArchive> regionCache =
            new LinkedHashMap<>(64, 0.75f, true);
    private final LinkedHashMap<Long, FileChannel> readChannelCache =
            new LinkedHashMap<>(64, 0.75f, true);
    private final ConcurrentHashMap<Long, Object> regionLocks = new ConcurrentHashMap<>();
    private final AtomicLong migratedRegionCount = new AtomicLong();
    private volatile boolean closed = false;

    public LcaRegionFileStorage(Path storageDirectory) {
        this(
                storageDirectory,
                inferStorageKindFromPath(storageDirectory),
                -4,
                24,
                4671,
                false,
                true,
                true,
                DEFAULT_MAX_OPEN_REGIONS,
                DEFAULT_COMPACT_FRAGMENTATION_THRESHOLD);
    }

    public LcaRegionFileStorage(
            Path storageDirectory,
            int storageKind,
            int minSectionY,
            int sectionCount,
            int defaultDataVersion,
            boolean modeBZstd,
            boolean autoMigrateLegacy,
            boolean backupMigratedLegacyFiles,
            int maxOpenRegions,
            double compactFragmentationThreshold
    ) {
        if (storageDirectory == null) {
            throw new IllegalArgumentException("storageDirectory must not be null");
        }
        this.storageDirectory = storageDirectory;
        this.storageKind = storageKind & 0xFF;
        this.minSectionY = minSectionY;
        this.sectionCount = Math.max(1, sectionCount);
        this.defaultDataVersion = defaultDataVersion;
        this.modeBZstd = modeBZstd;
        this.autoMigrateLegacy = autoMigrateLegacy;
        this.backupMigratedLegacyFiles = backupMigratedLegacyFiles;
        this.maxOpenRegions = Math.max(1, maxOpenRegions);
        this.compactFragmentationThreshold = compactFragmentationThreshold;
    }

    /**
     * Infers the `.lca` superblock `storageKind` from a region folder name
     * (`"entities"` -> `1`, `"poi"` -> `2`, otherwise `0 = REGION_VOXEL`).
     */
    public static int inferStorageKindFromPath(Path directory) {
        if (directory == null || directory.getFileName() == null) {
            return LcaRegionReader.STORAGE_KIND_REGION_VOXEL;
        }
        String folderName = directory.getFileName().toString().toLowerCase(Locale.ROOT);
        if ("entities".equals(folderName)) {
            return LcaRegionReader.STORAGE_KIND_ENTITIES;
        }
        if ("poi".equals(folderName)) {
            return LcaRegionReader.STORAGE_KIND_POI;
        }
        return LcaRegionReader.STORAGE_KIND_REGION_VOXEL;
    }

    public static long packRegionKey(int regionX, int regionZ) {
        return ((long) regionX << 32) | (regionZ & 0xFFFF_FFFFL);
    }

    public Path storageDirectory() {
        return storageDirectory;
    }

    public int storageKind() {
        return storageKind;
    }

    public int openRegionCount() {
        synchronized (regionCache) {
            return regionCache.size();
        }
    }

    public long migratedRegionCount() {
        return migratedRegionCount.get();
    }

    private LcaRegionWriter.LcaLiveArchive getOpenRegionIfCached(int regionX, int regionZ) {
        synchronized (regionCache) {
            return regionCache.get(packRegionKey(regionX, regionZ));
        }
    }

    private FileChannel getOrOpenReadChannel(int regionX, int regionZ, Path lcaFile) throws IOException {
        long key = packRegionKey(regionX, regionZ);
        synchronized (readChannelCache) {
            FileChannel cached = readChannelCache.get(key);
            if (cached != null && cached.isOpen()) {
                return cached;
            }
            readChannelCache.remove(key);
        }
        Object lock = regionLocks.computeIfAbsent(key, k -> new Object());
        synchronized (lock) {
            synchronized (readChannelCache) {
                FileChannel cached = readChannelCache.get(key);
                if (cached != null && cached.isOpen()) {
                    return cached;
                }
                readChannelCache.remove(key);
            }
            if (!Files.exists(lcaFile)) {
                return null;
            }
            FileChannel ch = FileChannel.open(lcaFile, StandardOpenOption.READ);
            List<FileChannel> toClose = null;
            synchronized (readChannelCache) {
                while (readChannelCache.size() >= maxOpenRegions) {
                    Iterator<Map.Entry<Long, FileChannel>> it = readChannelCache.entrySet().iterator();
                    if (!it.hasNext()) {
                        break;
                    }
                    Map.Entry<Long, FileChannel> eldest = it.next();
                    it.remove();
                    if (toClose == null) {
                        toClose = new ArrayList<>(2);
                    }
                    toClose.add(eldest.getValue());
                }
                readChannelCache.put(key, ch);
            }
            if (toClose != null) {
                for (FileChannel evicted : toClose) {
                    if (evicted != null) {
                        evicted.close();
                    }
                }
            }
            return ch;
        }
    }

    private void closeReadChannel(long key) throws IOException {
        FileChannel ch;
        synchronized (readChannelCache) {
            ch = readChannelCache.remove(key);
        }
        if (ch != null) {
            ch.close();
        }
    }

    /**
     * Returns whether chunk `(chunkX, chunkZ)` exists and is generated.
     */
    public boolean doesChunkExist(int chunkX, int chunkZ) throws IOException {
        int regionX = chunkX >> 5;
        int regionZ = chunkZ >> 5;
        int rx = chunkX & 31;
        int rz = chunkZ & 31;
        LcaRegionWriter.LcaLiveArchive cached = getOpenRegionIfCached(regionX, regionZ);
        if (cached != null) {
            return cached.hasChunk(rx, rz);
        }
        Path lcaFile = storageDirectory.resolve("r." + regionX + "." + regionZ + ".lca");
        if (LcaRegionReader.hasValidFileHeader(lcaFile)) {
            return LcaRegionReader.isChunkGeneratedInFile(lcaFile, rx, rz);
        }
        LcaRegionWriter.LcaLiveArchive archive = getOrOpenRegion(regionX, regionZ, false);
        if (archive == null) {
            return false;
        }
        return archive.hasChunk(rx, rz);
    }

    /**
     * `RegionFile#getChunkDataInputStream(ChunkPos)` equivalent at world chunk coordinates `(chunkX, chunkZ)`.
     */
    public DataInputStream getChunkDataInputStream(int chunkX, int chunkZ) throws IOException {
        int regionX = chunkX >> 5;
        int regionZ = chunkZ >> 5;
        int rx = chunkX & 31;
        int rz = chunkZ & 31;
        LcaRegionWriter.LcaLiveArchive cached = getOpenRegionIfCached(regionX, regionZ);
        if (cached != null) {
            return cached.getChunkDataInputStream(rx, rz);
        }
        Path lcaFile = storageDirectory.resolve("r." + regionX + "." + regionZ + ".lca");
        if (LcaRegionReader.hasValidFileHeader(lcaFile)) {
            if (!LcaRegionReader.isChunkGeneratedInFile(lcaFile, rx, rz)) {
                return null;
            }
            FileChannel ch = getOrOpenReadChannel(regionX, regionZ, lcaFile);
            byte[] rawNbt = LcaRegionReader.readChunkNbtBytesFromChannel(lcaFile, ch, rx, rz);
            return rawNbt == null ? null : new DataInputStream(new java.io.ByteArrayInputStream(rawNbt));
        }
        LcaRegionWriter.LcaLiveArchive archive = getOrOpenRegion(regionX, regionZ, false);
        if (archive == null) {
            return null;
        }
        return archive.getChunkDataInputStream(rx, rz);
    }

    /**
     * `RegionFile#getChunkDataOutputStream(ChunkPos)` equivalent at world chunk coordinates `(chunkX, chunkZ)`.
     * Closing the returned {@link DataOutputStream} parses the written Mojang binary NBT compound and
     * commits it to the backing `.lca` region file via Copy-on-Write (`CoW`) `256B` slab rotation.
     */
    public DataOutputStream getChunkDataOutputStream(int chunkX, int chunkZ) throws IOException {
        int regionX = chunkX >> 5;
        int regionZ = chunkZ >> 5;
        LcaRegionWriter.LcaLiveArchive archive = getOrOpenRegion(regionX, regionZ, true);
        return archive.getChunkDataOutputStream(chunkX & 31, chunkZ & 31);
    }

    /**
     * Reads and decodes the chunk NBT compound at world chunk coordinates `(chunkX, chunkZ)`, or `null` if absent.
     */
    public LinkedHashMap<String, Object> readChunkCompound(int chunkX, int chunkZ) throws IOException {
        int regionX = chunkX >> 5;
        int regionZ = chunkZ >> 5;
        int rx = chunkX & 31;
        int rz = chunkZ & 31;
        LcaRegionWriter.LcaLiveArchive cached = getOpenRegionIfCached(regionX, regionZ);
        if (cached != null) {
            AnvilReader.ChunkEntry entry = cached.readChunkEntry(rx, rz);
            return entry == null ? null : entry.root;
        }
        Path lcaFile = storageDirectory.resolve("r." + regionX + "." + regionZ + ".lca");
        if (LcaRegionReader.hasValidFileHeader(lcaFile)) {
            if (!LcaRegionReader.isChunkGeneratedInFile(lcaFile, rx, rz)) {
                return null;
            }
            FileChannel ch = getOrOpenReadChannel(regionX, regionZ, lcaFile);
            AnvilReader.ChunkEntry entry = LcaRegionReader.readChunkFromChannel(lcaFile, ch, rx, rz);
            return entry == null ? null : entry.root;
        }
        LcaRegionWriter.LcaLiveArchive archive = getOrOpenRegion(regionX, regionZ, false);
        if (archive == null) {
            return null;
        }
        AnvilReader.ChunkEntry entry = archive.readChunkEntry(rx, rz);
        return entry == null ? null : entry.root;
    }

    /**
     * Reads and serializes the chunk at world chunk coordinates `(chunkX, chunkZ)` into uncompressed
     * Mojang binary NBT bytes, or returns `null` if absent.
     */
    public byte[] readChunkNbtBytes(int chunkX, int chunkZ) throws IOException {
        int regionX = chunkX >> 5;
        int regionZ = chunkZ >> 5;
        int rx = chunkX & 31;
        int rz = chunkZ & 31;
        LcaRegionWriter.LcaLiveArchive cached = getOpenRegionIfCached(regionX, regionZ);
        if (cached != null) {
            return cached.readChunkNbtBytes(rx, rz);
        }
        Path lcaFile = storageDirectory.resolve("r." + regionX + "." + regionZ + ".lca");
        if (LcaRegionReader.hasValidFileHeader(lcaFile)) {
            if (!LcaRegionReader.isChunkGeneratedInFile(lcaFile, rx, rz)) {
                return null;
            }
            FileChannel ch = getOrOpenReadChannel(regionX, regionZ, lcaFile);
            return LcaRegionReader.readChunkNbtBytesFromChannel(lcaFile, ch, rx, rz);
        }
        LcaRegionWriter.LcaLiveArchive archive = getOrOpenRegion(regionX, regionZ, false);
        if (archive == null) {
            return null;
        }
        return archive.readChunkNbtBytes(rx, rz);
    }

    /**
     * Writes a decoded chunk NBT compound map at world chunk coordinates `(chunkX, chunkZ)` using
     * Copy-on-Write (`CoW`) `256B` sub-slab persistence.
     */
    public int writeChunkCompound(int chunkX, int chunkZ, Map<String, Object> chunkRoot) throws IOException {
        if (chunkRoot == null) {
            removeChunk(chunkX, chunkZ);
            return 0;
        }
        int regionX = chunkX >> 5;
        int regionZ = chunkZ >> 5;
        LcaRegionWriter.LcaLiveArchive archive = getOrOpenRegion(regionX, regionZ, true);
        return archive.saveChunkCoW(chunkX & 31, chunkZ & 31, chunkRoot);
    }

    /**
     * Writes an uncompressed Mojang binary NBT root `TAG_Compound` byte array at world chunk coordinates `(chunkX, chunkZ)`.
     */
    public int writeChunkNbtBytes(int chunkX, int chunkZ, byte[] uncompressedNbtBytes) throws IOException {
        if (uncompressedNbtBytes == null || uncompressedNbtBytes.length == 0) {
            removeChunk(chunkX, chunkZ);
            return 0;
        }
        int regionX = chunkX >> 5;
        int regionZ = chunkZ >> 5;
        LcaRegionWriter.LcaLiveArchive archive = getOrOpenRegion(regionX, regionZ, true);
        return archive.saveChunkNbtBytes(chunkX & 31, chunkZ & 31, uncompressedNbtBytes);
    }

    /**
     * Removes the chunk at `(chunkX, chunkZ)` if present.
     */
    public boolean removeChunk(int chunkX, int chunkZ) throws IOException {
        int regionX = chunkX >> 5;
        int regionZ = chunkZ >> 5;
        LcaRegionWriter.LcaLiveArchive archive = getOrOpenRegion(regionX, regionZ, false);
        if (archive == null) {
            return false;
        }
        return archive.removeChunk(chunkX & 31, chunkZ & 31);
    }

    /**
     * Retrieves or opens the disk-backed {@link LcaRegionWriter.LcaLiveArchive} for `(regionX, regionZ)`.
     */
    public LcaRegionWriter.LcaLiveArchive getOrOpenRegion(
            int regionX, int regionZ, boolean createIfAbsent
    ) throws IOException {
        long key = packRegionKey(regionX, regionZ);
        synchronized (regionCache) {
            if (closed) {
                closed = false;
            }
            LcaRegionWriter.LcaLiveArchive cached = regionCache.get(key);
            if (cached != null) {
                return cached;
            }
        }

        Object lock = regionLocks.computeIfAbsent(key, k -> new Object());
        synchronized (lock) {
            synchronized (regionCache) {
                if (closed) {
                    closed = false;
                }
                LcaRegionWriter.LcaLiveArchive cached = regionCache.get(key);
                if (cached != null) {
                    return cached;
                }
            }

            closeReadChannel(key);
            LcaRegionWriter.LcaLiveArchive result = null;
            Path lcaFile = storageDirectory.resolve("r." + regionX + "." + regionZ + ".lca");
            if (Files.exists(lcaFile) && Files.size(lcaFile) >= LcaRegionReader.SUPERBLOCK_SIZE
                    + LcaRegionReader.POINTER_DIRECTORY_SIZE + LcaRegionReader.FOOTER_SIZE) {
                result = LcaRegionWriter.openLiveArchive(lcaFile);
            } else if (autoMigrateLegacy) {
                LcaRegionWriter.LcaLiveArchive migrated = tryMigrateLegacyRegion(regionX, regionZ, lcaFile);
                if (migrated != null) {
                    migratedRegionCount.incrementAndGet();
                    result = migrated;
                }
            }

            if (result == null) {
                if (!createIfAbsent) {
                    return null;
                }
                result = LcaRegionWriter.createEmptyLiveArchive(
                        lcaFile, regionX, regionZ, minSectionY, sectionCount, defaultDataVersion,
                        modeBZstd, storageKind, LcaRegionWriter.DEFAULT_ROOT_DICT_CAPACITY_BYTES);
            }

            List<LcaRegionWriter.LcaLiveArchive> toClose = null;
            synchronized (regionCache) {
                if (closed) {
                    closed = false;
                }
                while (regionCache.size() >= maxOpenRegions) {
                    Iterator<Map.Entry<Long, LcaRegionWriter.LcaLiveArchive>> it = regionCache.entrySet().iterator();
                    if (!it.hasNext()) {
                        break;
                    }
                    Map.Entry<Long, LcaRegionWriter.LcaLiveArchive> eldest = it.next();
                    it.remove();
                    if (toClose == null) {
                        toClose = new ArrayList<>(2);
                    }
                    toClose.add(eldest.getValue());
                }
                regionCache.put(key, result);
            }
            if (toClose != null) {
                for (LcaRegionWriter.LcaLiveArchive evicted : toClose) {
                    if (evicted != null) {
                        evicted.closeWithoutForce();
                    }
                }
            }
            return result;
        }
    }

    private LcaRegionWriter.LcaLiveArchive tryMigrateLegacyRegion(
            int regionX, int regionZ, Path targetLcaFile
    ) throws IOException {
        Path mcaFile = storageDirectory.resolve("r." + regionX + "." + regionZ + ".mca");
        Path legacyFile = null;
        RegionFileReader legacyReader = null;
        if (Files.exists(mcaFile) && Files.size(mcaFile) >= 8192) {
            legacyFile = mcaFile;
            legacyReader = AnvilReader.INSTANCE;
        } else {
            Path linearFile = storageDirectory.resolve("r." + regionX + "." + regionZ + ".linear");
            if (Files.exists(linearFile) && Files.size(linearFile) > 32
                    && RegionFormatRegistry.isRegistered(".linear")) {
                legacyFile = linearFile;
                legacyReader = RegionFormatRegistry.getReader(".linear");
            }
        }
        if (legacyFile == null || legacyReader == null) {
            return null;
        }

        byte[] srcBytes = Files.readAllBytes(legacyFile);
        byte[] lcaBytes = LcaRegionWriter.transcodeFromReader(
                legacyReader, srcBytes, regionX, regionZ, modeBZstd, storageKind);

        Files.createDirectories(storageDirectory);
        Path tmpFile = storageDirectory.resolve("r." + regionX + "." + regionZ + ".lca.tmp");
        Files.write(tmpFile, lcaBytes);
        Files.move(tmpFile, targetLcaFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);

        if (backupMigratedLegacyFiles) {
            Path bakFile = storageDirectory.resolve(legacyFile.getFileName().toString() + ".bak");
            if (!Files.exists(bakFile)) {
                Files.move(legacyFile, bakFile, StandardCopyOption.REPLACE_EXISTING);
            }
        }
        return LcaRegionWriter.openLiveArchive(targetLcaFile);
    }

    private void closeArchiveQuietlyWithCompaction(LcaRegionWriter.LcaLiveArchive archive) throws IOException {
        if (archive == null) {
            return;
        }
        archive.closeWithoutForce();
    }

    /**
     * Flushes a single open `.lca` region `(regionX, regionZ)` if currently cached.
     */
    public void flushRegion(int regionX, int regionZ) throws IOException {
        LcaRegionWriter.LcaLiveArchive archive;
        synchronized (regionCache) {
            archive = regionCache.get(packRegionKey(regionX, regionZ));
        }
        if (archive != null) {
            archive.flush();
        }
    }

    /**
     * Compacts (when above threshold), flushes, and closes a single open `.lca` region `(regionX, regionZ)`.
     */
    public void closeRegion(int regionX, int regionZ) throws IOException {
        long key = packRegionKey(regionX, regionZ);
        closeReadChannel(key);
        LcaRegionWriter.LcaLiveArchive archive;
        synchronized (regionCache) {
            archive = regionCache.remove(key);
        }
        if (archive != null) {
            closeArchiveQuietlyWithCompaction(archive);
        }
    }

    /**
     * Compacts all currently open `.lca` region handles whose free-slab ratio exceeds `maxFreeRatio`.
     *
     * @return number of open regions that were compacted
     */
    public int compactOpenRegions(double maxFreeRatio) throws IOException {
        List<LcaRegionWriter.LcaLiveArchive> archives;
        synchronized (regionCache) {
            archives = new ArrayList<>(regionCache.values());
        }
        int compacted = 0;
        for (LcaRegionWriter.LcaLiveArchive archive : archives) {
            if (archive.compactIfFragmented(maxFreeRatio)) {
                compacted++;
            }
        }
        return compacted;
    }

    /**
     * Flushes all open `.lca` region files in this storage directory to disk.
     */
    public void flush() throws IOException {
        List<LcaRegionWriter.LcaLiveArchive> archives;
        synchronized (regionCache) {
            archives = new ArrayList<>(regionCache.values());
        }
        IOException firstEx = null;
        for (LcaRegionWriter.LcaLiveArchive archive : archives) {
            try {
                archive.flush();
            } catch (IOException e) {
                if (firstEx == null) firstEx = e;
            }
        }
        if (firstEx != null) {
            throw firstEx;
        }
    }

    /**
     * Compacts (when above the fragmentation threshold), flushes, and closes all open `.lca`
     * region handles in this storage directory.
     */
    @Override
    public void close() throws IOException {
        List<LcaRegionWriter.LcaLiveArchive> archives;
        synchronized (regionCache) {
            if (closed) {
                return;
            }
            closed = true;
            archives = new ArrayList<>(regionCache.values());
            regionCache.clear();
        }
        List<FileChannel> readChannels;
        synchronized (readChannelCache) {
            readChannels = new ArrayList<>(readChannelCache.values());
            readChannelCache.clear();
        }
        IOException firstEx = null;
        for (FileChannel ch : readChannels) {
            if (ch != null) {
                try {
                    ch.close();
                } catch (IOException e) {
                    if (firstEx == null) firstEx = e;
                }
            }
        }
        for (LcaRegionWriter.LcaLiveArchive archive : archives) {
            try {
                closeArchiveQuietlyWithCompaction(archive);
            } catch (IOException e) {
                if (firstEx == null) firstEx = e;
            }
        }
        if (firstEx != null) {
            throw firstEx;
        }
    }

    private void ensureOpen() throws IOException {
        if (closed) {
            throw new IOException("LcaRegionFileStorage for " + storageDirectory + " is already closed");
        }
    }

    /**
     * Dynamic proxy / reflective stream adapter for `IRegionFile` or custom region interfaces that
     * expose `getChunkDataInputStream`, `getChunkDataOutputStream`, `doesChunkExist` / `hasChunk`,
     * `flush`, and `close`.
     */
    public static <T> T createRegionFileInterfaceProxy(
            Class<T> regionFileInterface, LcaRegionWriter.LcaLiveArchive archive
    ) {
        if (regionFileInterface == null || !regionFileInterface.isInterface()) {
            throw new IllegalArgumentException("regionFileInterface must be a valid interface");
        }
        InvocationHandler handler = (Object proxy, Method method, Object[] args) -> {
            String name = method.getName();
            if ("flush".equals(name) || "sync".equals(name)) {
                archive.flush();
                return null;
            }
            if ("close".equals(name)) {
                archive.close();
                return null;
            }
            if ("getPath".equals(name) || "getRegionFile".equals(name)) {
                return archive.backingFile();
            }
            if (args != null && args.length >= 1) {
                int rx;
                int rz;
                if (args.length >= 2 && args[0] instanceof Number nx && args[1] instanceof Number nz) {
                    rx = nx.intValue() & 31;
                    rz = nz.intValue() & 31;
                } else {
                    int[] pos = extractChunkPosCoords(args[0]);
                    rx = pos[0] & 31;
                    rz = pos[1] & 31;
                }
                if ("getChunkDataInputStream".equals(name)) {
                    return archive.getChunkDataInputStream(rx, rz);
                }
                if ("getChunkDataOutputStream".equals(name)) {
                    return archive.getChunkDataOutputStream(rx, rz);
                }
                if ("doesChunkExist".equals(name) || "hasChunk".equals(name) || "isChunkGenerated".equals(name)) {
                    return archive.hasChunk(rx, rz);
                }
                if ("clear".equals(name) || "removeChunk".equals(name)) {
                    return archive.removeChunk(rx, rz);
                }
            }
            if (method.getReturnType() == boolean.class) {
                return false;
            }
            return null;
        };
        return regionFileInterface.cast(Proxy.newProxyInstance(
                regionFileInterface.getClassLoader(),
                new Class<?>[] {regionFileInterface},
                handler));
    }

    public static int[] extractChunkPosCoords(Object chunkPosObj) {
        if (chunkPosObj == null) {
            throw new IllegalArgumentException("ChunkPos argument must not be null");
        }
        Class<?> cls = chunkPosObj.getClass();
        try {
            java.lang.reflect.Field xField = cls.getField("x");
            java.lang.reflect.Field zField = cls.getField("z");
            return new int[] {xField.getInt(chunkPosObj), zField.getInt(chunkPosObj)};
        } catch (ReflectiveOperationException ignored) {
            try {
                Method xMethod = cls.getMethod("x");
                Method zMethod = cls.getMethod("z");
                return new int[] {((Number) xMethod.invoke(chunkPosObj)).intValue(),
                        ((Number) zMethod.invoke(chunkPosObj)).intValue()};
            } catch (ReflectiveOperationException e) {
                throw new IllegalArgumentException("Cannot extract (x, z) from ChunkPos object: " + cls.getName(), e);
            }
        }
    }

    /**
     * Multi-folder world storage bundle managing all three dimension persistence folders:
     * `region/` (`STORAGE_KIND_REGION_VOXEL`), `entities/` (`STORAGE_KIND_ENTITIES`), and
     * `poi/` (`STORAGE_KIND_POI`).
     */
    public static final class LcaWorldStorageSession implements Closeable, AutoCloseable {
        private final Path dimensionDirectory;
        private final LcaRegionFileStorage voxelStorage;
        private final LcaRegionFileStorage entityStorage;
        private final LcaRegionFileStorage poiStorage;

        public LcaWorldStorageSession(
                Path dimensionDirectory,
                int minSectionY,
                int sectionCount,
                int defaultDataVersion,
                boolean modeBZstd,
                boolean autoMigrateLegacy
        ) {
            this.dimensionDirectory = dimensionDirectory;
            this.voxelStorage = new LcaRegionFileStorage(
                    dimensionDirectory.resolve("region"),
                    LcaRegionReader.STORAGE_KIND_REGION_VOXEL,
                    minSectionY,
                    sectionCount,
                    defaultDataVersion,
                    modeBZstd,
                    autoMigrateLegacy,
                    true,
                    DEFAULT_MAX_OPEN_REGIONS,
                    DEFAULT_COMPACT_FRAGMENTATION_THRESHOLD);
            this.entityStorage = new LcaRegionFileStorage(
                    dimensionDirectory.resolve("entities"),
                    LcaRegionReader.STORAGE_KIND_ENTITIES,
                    minSectionY,
                    sectionCount,
                    defaultDataVersion,
                    modeBZstd,
                    autoMigrateLegacy,
                    true,
                    DEFAULT_MAX_OPEN_REGIONS,
                    DEFAULT_COMPACT_FRAGMENTATION_THRESHOLD);
            this.poiStorage = new LcaRegionFileStorage(
                    dimensionDirectory.resolve("poi"),
                    LcaRegionReader.STORAGE_KIND_POI,
                    minSectionY,
                    sectionCount,
                    defaultDataVersion,
                    modeBZstd,
                    autoMigrateLegacy,
                    true,
                    DEFAULT_MAX_OPEN_REGIONS,
                    DEFAULT_COMPACT_FRAGMENTATION_THRESHOLD);
        }

        public Path dimensionDirectory() {
            return dimensionDirectory;
        }

        public LcaRegionFileStorage voxelStorage() {
            return voxelStorage;
        }

        public LcaRegionFileStorage entityStorage() {
            return entityStorage;
        }

        public LcaRegionFileStorage poiStorage() {
            return poiStorage;
        }

        /**
         * Resolves the {@link LcaRegionFileStorage} (`region/`, `entities/`, or `poi/`) matching the
         * given NMS `RegionFileStorage` folder path.
         */
        public LcaRegionFileStorage storageForFolder(Path folderPath) {
            int kind = inferStorageKindFromPath(folderPath);
            if (kind == LcaRegionReader.STORAGE_KIND_ENTITIES) {
                return entityStorage;
            }
            if (kind == LcaRegionReader.STORAGE_KIND_POI) {
                return poiStorage;
            }
            return voxelStorage;
        }

        public int totalOpenRegionCount() {
            return voxelStorage.openRegionCount()
                    + entityStorage.openRegionCount()
                    + poiStorage.openRegionCount();
        }

        public long totalMigratedRegionCount() {
            return voxelStorage.migratedRegionCount()
                    + entityStorage.migratedRegionCount()
                    + poiStorage.migratedRegionCount();
        }

        public int compactOpenRegions(double maxFreeRatio) throws IOException {
            return voxelStorage.compactOpenRegions(maxFreeRatio)
                    + entityStorage.compactOpenRegions(maxFreeRatio)
                    + poiStorage.compactOpenRegions(maxFreeRatio);
        }

        public void flush() throws IOException {
            voxelStorage.flush();
            entityStorage.flush();
            poiStorage.flush();
        }

        @Override
        public void close() throws IOException {
            IOException first = null;
            for (LcaRegionFileStorage s : List.of(voxelStorage, entityStorage, poiStorage)) {
                try {
                    s.close();
                } catch (IOException e) {
                    if (first == null) first = e;
                }
            }
            if (first != null) {
                throw first;
            }
        }
    }
}
