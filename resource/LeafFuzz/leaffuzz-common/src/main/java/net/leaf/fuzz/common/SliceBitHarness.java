package net.leaf.fuzz.common;

import io.github.dailystruggle.bit.BitHealth;
import io.github.dailystruggle.bit.BuiltInTestable;
import io.github.dailystruggle.bit.PbitResult;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.CausalChainSlice;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.CausalFinding;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.CausalGraphReport;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.EntryPointKind;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.FindingKind;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.ListenerRegistrationMode;
import net.leaf.fuzz.common.LeafFuzzBitSuite.CheckResult;
import net.leaf.sleuth.common.fuzz.JarClassOwnershipIndex;
import net.leaf.sleuth.common.fuzz.LogAndStallSignatureOracle;
import net.leaf.sleuth.common.fuzz.LogAndStallSignatureOracle.FaultSignature;
import net.leaf.sleuth.common.resource.ClassRetentionFinding;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Per-slice Built-In Test ({@code PBIT} / {@code CBIT} / {@code IBIT}) harness for auditing
 * compiled {@link CausalChainSlice}s strictly in memory without modifying {@code .jar} archives on
 * disk ({@code ADR-125}, {@code leaffuzz-ADR-001}).
 *
 * <p>Provides three formal verification tiers per causal chain:
 * <ol>
 *   <li><b>Causal-Chain {@code PBIT} (Startup / Structural &amp; Bytecode Contract BIT):</b> Verifies
 *       listener registration wiring, config key existence, and bytecode descriptor invariants
 *       ({@code S-004} swallowed exceptions / popped {@code CompletableFuture}s, {@code S-005}
 *       synchronous chunk loads, and Folia regional scheduler compatibility) and validates
 *       in-memory class definitions inside a disposable {@link EphemeralSliceClassLoader}.</li>
 *   <li><b>Causal-Chain {@code CBIT} (Continuous Conservation &amp; Causal Sink Delivery BIT):</b>
 *       Monitors post-episode zero-sum resource conservation ({@code S-002} class retention slopes),
 *       main-thread stall attribution ({@code S-005}), and runtime sink delivery vs. hollow command
 *       no-ops ({@code S-004}).</li>
 *   <li><b>Causal-Chain {@code IBIT} (Initiated Fault-Injection BIT with Reversible Snapshot):</b>
 *       Executes fault-injection and boundary probes inside an {@link InMemorySliceBitSession}
 *       ({@code try / finally}) that snapshots pre-probe state, verifies deterministic fault-oracle
 *       detection on suspect chains, and restores all in-memory state immediately afterward.</li>
 * </ol>
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy leaffuzz-ADR-001
 * @trace REQ-SLEUTH-FUZZ-001
 * @trace REQ-SLEUTH-FUZZ-002
 * @trace REQ-SLEUTH-FUZZ-003
 * @trace REQ-SLEUTH-FUZZ-004
 * @trace S-002
 * @trace S-004
 * @trace S-005
 */
public final class SliceBitHarness implements BuiltInTestable {

    private final String artifactName;
    private final CausalChainSlice slice;
    private final List<CausalFinding> sliceFindings;
    private final Map<String, byte[]> inMemoryClassBytes;
    private final AtomicReference<BitHealth> lastHealth = new AtomicReference<>(BitHealth.HEALTHY);

    /**
     * Structured per-slice BIT report combining {@code PBIT}, {@code CBIT}, and {@code IBIT}
     * results alongside proof that in-memory state was restored cleanly.
     *
     * @param artifactName       owning plugin/mod artifact name
     * @param entrySymbol        slice entry {@code Class#method} symbol
     * @param kind               slice entry-point kind ({@code COMMAND}, {@code EVENT}, {@code SUPPLIER})
     * @param pbitResult         Tier 1 structural &amp; bytecode contract check result
     * @param cbitResult         Tier 2 runtime conservation &amp; sink delivery check result
     * @param ibitResult         Tier 3 reversible fault-injection check result
     * @param health             aggregate {@link BitHealth} for the slice
     * @param violatedInvariants deterministic list of violated invariant codes (e.g. {@code S-004}, {@code S-005})
     * @param stateRestored      {@code true} iff all ephemeral in-memory BIT state was restored after execution
     */
    public record SliceBitReport(
            String artifactName,
            String entrySymbol,
            EntryPointKind kind,
            CheckResult pbitResult,
            CheckResult cbitResult,
            CheckResult ibitResult,
            BitHealth health,
            List<String> violatedInvariants,
            boolean stateRestored
    ) {
        public SliceBitReport {
            artifactName = artifactName == null ? "unknown" : artifactName;
            entrySymbol = entrySymbol == null ? "<unknown>" : entrySymbol;
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(pbitResult, "pbitResult");
            Objects.requireNonNull(cbitResult, "cbitResult");
            Objects.requireNonNull(ibitResult, "ibitResult");
            Objects.requireNonNull(health, "health");
            violatedInvariants = violatedInvariants == null ? List.of() : List.copyOf(violatedInvariants);
        }

        public boolean allPassed() {
            return pbitResult.passed() && cbitResult.passed() && ibitResult.passed() && stateRestored;
        }
    }

    /**
     * Isolated, disposable in-memory {@link ClassLoader} that loads cloned {@code byte[]} class
     * payloads for slice inspection without touching any {@code .jar} file on disk or polluting
     * the host plugin/mod classloader.
     */
    public static final class EphemeralSliceClassLoader extends ClassLoader implements AutoCloseable {
        private final Map<String, byte[]> classBytesByBinaryName = new ConcurrentHashMap<>();
        private final Map<String, Class<?>> definedClasses = new ConcurrentHashMap<>();
        private final AtomicBoolean closed = new AtomicBoolean(false);

        public EphemeralSliceClassLoader(ClassLoader parent, Map<String, byte[]> initialClassBytes) {
            super(parent);
            if (initialClassBytes != null) {
                for (var entry : initialClassBytes.entrySet()) {
                    if (entry.getKey() != null && entry.getValue() != null) {
                        // Defensive clone so caller's byte[] buffer is never mutated
                        this.classBytesByBinaryName.put(
                                entry.getKey().replace('/', '.'),
                                Arrays.copyOf(entry.getValue(), entry.getValue().length)
                        );
                    }
                }
            }
        }

        /**
         * Stages an in-memory replacement or probe class definition for the duration of the BIT
         * session without writing to disk.
         *
         * @param binaryClassName binary class name (e.g. {@code com.example.MySlice})
         * @param bytecode        raw {@code .class} bytes
         */
        public void stageInMemoryClassBytes(String binaryClassName, byte[] bytecode) {
            if (closed.get()) {
                throw new IllegalStateException("EphemeralSliceClassLoader is already closed");
            }
            Objects.requireNonNull(binaryClassName, "binaryClassName");
            Objects.requireNonNull(bytecode, "bytecode");
            classBytesByBinaryName.put(
                    binaryClassName.replace('/', '.'),
                    Arrays.copyOf(bytecode, bytecode.length)
            );
        }

        public int stagedClassCount() {
            return classBytesByBinaryName.size();
        }

        public boolean isClosed() {
            return closed.get();
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            if (closed.get()) {
                throw new ClassNotFoundException("EphemeralSliceClassLoader is closed: " + name);
            }
            String binaryName = name.replace('/', '.');
            Class<?> existing = definedClasses.get(binaryName);
            if (existing != null) {
                return existing;
            }
            byte[] bytes = classBytesByBinaryName.get(binaryName);
            if (bytes == null) {
                return super.findClass(name);
            }
            Class<?> defined = defineClass(binaryName, bytes, 0, bytes.length);
            definedClasses.put(binaryName, defined);
            return defined;
        }

        @Override
        public void close() {
            if (closed.compareAndSet(false, true)) {
                classBytesByBinaryName.clear();
                definedClasses.clear();
            }
        }
    }

    /**
     * Reversible in-memory session guard ({@code try-with-resources}) that snapshots pre-BIT
     * state, provides an isolated {@link EphemeralSliceClassLoader} and temporary probe map, and
     * restores all state to baseline on {@link #close()}.
     */
    public static final class InMemorySliceBitSession implements AutoCloseable {
        private final Map<String, byte[]> baselineClassBytes;
        private final Map<String, Object> baselineAttributes;
        private final Map<String, Object> workingAttributes;
        private final EphemeralSliceClassLoader ephemeralLoader;
        private final Runnable onRestoreHook;
        private final AtomicBoolean restored = new AtomicBoolean(false);

        public InMemorySliceBitSession(
                ClassLoader parentLoader,
                Map<String, byte[]> classBytes,
                Map<String, Object> initialAttributes,
                Runnable onRestoreHook
        ) {
            Map<String, byte[]> snapBytes = new LinkedHashMap<>();
            if (classBytes != null) {
                for (var e : classBytes.entrySet()) {
                    if (e.getKey() != null && e.getValue() != null) {
                        snapBytes.put(e.getKey(), Arrays.copyOf(e.getValue(), e.getValue().length));
                    }
                }
            }
            this.baselineClassBytes = Collections.unmodifiableMap(snapBytes);
            this.baselineAttributes = initialAttributes == null
                    ? Map.of()
                    : Collections.unmodifiableMap(new LinkedHashMap<>(initialAttributes));
            this.workingAttributes = new ConcurrentHashMap<>(this.baselineAttributes);
            this.ephemeralLoader = new EphemeralSliceClassLoader(parentLoader, snapBytes);
            this.onRestoreHook = onRestoreHook;
        }

        public EphemeralSliceClassLoader ephemeralLoader() {
            return ephemeralLoader;
        }

        public void putTemporaryProbeAttribute(String key, Object value) {
            if (restored.get()) {
                throw new IllegalStateException("InMemorySliceBitSession already restored");
            }
            workingAttributes.put(Objects.requireNonNull(key, "key"), value);
        }

        public Map<String, Object> currentAttributes() {
            return Collections.unmodifiableMap(new LinkedHashMap<>(workingAttributes));
        }

        public Map<String, byte[]> baselineClassBytes() {
            return baselineClassBytes;
        }

        public boolean isRestored() {
            return restored.get();
        }

        @Override
        public void close() {
            if (restored.compareAndSet(false, true)) {
                try {
                    workingAttributes.clear();
                    workingAttributes.putAll(baselineAttributes);
                    if (onRestoreHook != null) {
                        onRestoreHook.run();
                    }
                } finally {
                    ephemeralLoader.close();
                }
            }
        }
    }

    public SliceBitHarness(
            String artifactName,
            CausalChainSlice slice,
            List<CausalFinding> allReportFindings,
            Map<String, byte[]> inMemoryClassBytes
    ) {
        this.artifactName = (artifactName == null || artifactName.isBlank()) ? "plugin:unknown" : artifactName.trim();
        this.slice = Objects.requireNonNull(slice, "slice");
        this.sliceFindings = filterFindingsForSlice(slice, allReportFindings);
        Map<String, byte[]> cloned = new LinkedHashMap<>();
        if (inMemoryClassBytes != null) {
            for (var e : inMemoryClassBytes.entrySet()) {
                if (e.getKey() != null && e.getValue() != null) {
                    cloned.put(e.getKey().replace('/', '.'), Arrays.copyOf(e.getValue(), e.getValue().length));
                }
            }
        }
        this.inMemoryClassBytes = Collections.unmodifiableMap(cloned);
    }

    public CausalChainSlice slice() {
        return slice;
    }

    @Override
    public PbitResult executePbit() {
        long t0 = System.nanoTime();
        CheckResult pbit = runSlicePbit();
        long elapsedNanos = Math.max(1L, System.nanoTime() - t0);
        String compName = "SliceBit[" + artifactName + ":" + slice.entrySymbol() + "]";
        if (pbit.passed()) {
            lastHealth.set(BitHealth.HEALTHY);
            return PbitResult.ok(compName, elapsedNanos, pbit.summary());
        }
        lastHealth.set(BitHealth.DEGRADED);
        return PbitResult.failed(compName, elapsedNanos, pbit.summary(), null);
    }

    @Override
    public BitHealth getHealthStatus() {
        return lastHealth.get();
    }

    /**
     * Executes Tier 1 ({@code PBIT}), Tier 2 ({@code CBIT}), and Tier 3 ({@code IBIT}) in memory
     * for this slice, restoring all temporary probe state in {@code finally}.
     *
     * @param liveFaults    attributed runtime fault signatures from {@link LogAndStallSignatureOracle}
     * @param liveLeaks     attributed post-GC class retention findings
     * @param commandsRun   number of live command dispatches observed during the run
     * @param effectsSeen   number of live teleports/menus/effects observed during the run
     * @return structured {@link SliceBitReport}
     */
    public SliceBitReport executeFullSliceBit(
            List<FaultSignature> liveFaults,
            List<ClassRetentionFinding> liveLeaks,
            int commandsRun,
            int effectsSeen
    ) {
        Set<String> invariants = new LinkedHashSet<>();
        AtomicBoolean hookRestored = new AtomicBoolean(false);
        CheckResult pbit;
        CheckResult cbit;
        CheckResult ibit;
        boolean sessionRestored;

        Map<String, Object> baselineAttrs = Map.of(
                "entrySymbol", slice.entrySymbol(),
                "commandsRun", commandsRun,
                "effectsSeen", effectsSeen
        );

        InMemorySliceBitSession capturedSession;
        try (InMemorySliceBitSession session = new InMemorySliceBitSession(
                SliceBitHarness.class.getClassLoader(),
                this.inMemoryClassBytes,
                baselineAttrs,
                () -> hookRestored.set(true)
        )) {
            capturedSession = session;
            pbit = runSlicePbitWithSession(session, invariants);
            cbit = runSliceCbit(liveFaults, liveLeaks, commandsRun, effectsSeen, invariants);
            ibit = runSliceIbit(session, !pbit.passed() || !cbit.passed(), invariants);
        }
        sessionRestored = capturedSession.isRestored()
                && hookRestored.get()
                && capturedSession.ephemeralLoader().isClosed()
                && capturedSession.currentAttributes().equals(baselineAttrs);

        BitHealth health;
        if (!sessionRestored) {
            health = BitHealth.FAILED;
        } else if (pbit.passed() && cbit.passed() && ibit.passed()) {
            health = BitHealth.HEALTHY;
        } else if (ibit.passed()) {
            health = BitHealth.DEGRADED;
        } else {
            health = BitHealth.FAILED;
        }
        lastHealth.set(health);

        return new SliceBitReport(
                artifactName,
                slice.entrySymbol(),
                slice.kind(),
                pbit,
                cbit,
                ibit,
                health,
                new ArrayList<>(invariants),
                sessionRestored
        );
    }

    /**
     * Runs Tier 1 ({@code PBIT}): verifies structural wiring and bytecode invariants on the slice.
     */
    public CheckResult runSlicePbit() {
        Set<String> invariants = new LinkedHashSet<>();
        try (InMemorySliceBitSession session = new InMemorySliceBitSession(
                SliceBitHarness.class.getClassLoader(),
                this.inMemoryClassBytes,
                Map.of("entrySymbol", slice.entrySymbol()),
                null
        )) {
            return runSlicePbitWithSession(session, invariants);
        }
    }

    private CheckResult runSlicePbitWithSession(InMemorySliceBitSession session, Set<String> invariants) {
        long t0 = System.nanoTime();
        List<String> issues = new ArrayList<>();

        if (slice.kind() == EntryPointKind.EVENT && slice.registrationMode() == ListenerRegistrationMode.UNREGISTERED) {
            invariants.add("ORDER-1-UNREGISTERED-LISTENER");
            issues.add("Listener slice " + slice.entrySymbol() + " is UNREGISTERED");
        }

        for (CausalFinding f : sliceFindings) {
            switch (f.kind()) {
                case CAUSAL_SWALLOWED_FAILURE -> {
                    invariants.add("S-004-SWALLOWED-FAILURE");
                    issues.add("S-004 swallowed exception in " + f.entryPointSymbol());
                }
                case CAUSAL_ORPHANED_SUPPLIER -> {
                    invariants.add("S-004-ORPHANED-FUTURE");
                    issues.add("S-004 popped CompletableFuture/Supplier in " + f.entryPointSymbol());
                }
                case CAUSAL_ASYNC_MAIN_THREAD_SINK -> {
                    invariants.add("S-005-MAIN-THREAD-SINK");
                    issues.add("S-005/F-001 main-thread/Folia sink violation in " + f.entryPointSymbol());
                }
                case CAUSAL_SYNC_MAIN_THREAD_IO -> {
                    invariants.add("S-005-SYNC-MAIN-IO");
                    issues.add("S-005 synchronous main-thread I/O contagion in " + f.entryPointSymbol());
                }
                case CAUSAL_UNCLOSED_RESOURCE_LEAK -> {
                    invariants.add("S-002-RESOURCE-LEAK");
                    issues.add("S-002 unclosed Closeable/ChunkTicket leak in " + f.entryPointSymbol());
                }
                case CAUSAL_SHARED_STATE_RACE -> {
                    invariants.add("CAUSAL-SHARED-STATE-RACE");
                    issues.add("CAUSAL-RACE shared-state concurrency hazard in " + f.entryPointSymbol());
                }
                case CAUSAL_DEAD_CONFIG_KEY, CAUSAL_UNREAD_CONFIG_FIELD -> {
                    invariants.add("CFG-DEAD-OR-UNREAD");
                    issues.add(f.kind().name() + " on " + f.entryPointSymbol());
                }
                case CAUSAL_UNIT_MISMATCH -> {
                    invariants.add("CFG-UNIT-MISMATCH");
                    issues.add("Unit mismatch in " + f.entryPointSymbol());
                }
                case CAUSAL_UNWIRED_COMMAND -> {
                    invariants.add("ORDER-1-UNWIRED-CMD");
                    issues.add("Unwired command " + f.entryPointSymbol());
                }
                default -> {
                }
            }
        }

        // Verify in-memory ephemeral class bytes integrity without mutating originals
        String entryClass = extractOwnerClassName(slice.entrySymbol());
        byte[] rawBytes = session.baselineClassBytes().get(entryClass);
        if (rawBytes != null) {
            if (rawBytes.length < 4
                    || (rawBytes[0] & 0xFF) != 0xCA
                    || (rawBytes[1] & 0xFF) != 0xFE
                    || (rawBytes[2] & 0xFF) != 0xBA
                    || (rawBytes[3] & 0xFF) != 0xBE) {
                invariants.add("BYTECODE-MAGIC-INVALID");
                issues.add("Invalid 0xCAFEBABE header for " + entryClass);
            } else {
                session.ephemeralLoader().stageInMemoryClassBytes(entryClass, rawBytes);
            }
        }

        double ms = (System.nanoTime() - t0) / 1_000_000.0;
        boolean ok = issues.isEmpty();
        String detail = ok
                ? ("Causal-chain PBIT clean (" + slice.kind() + " " + slice.entrySymbol()
                + ", hops=" + slice.hopTrace().size() + ", sinks=" + slice.reachableEffectSinks() + ")")
                : ("Causal-chain PBIT flagged " + issues.size() + " invariant(s): " + String.join("; ", issues));
        return new CheckResult("SLICE-PBIT:" + slice.entrySymbol(), "PBIT", ok, detail, ms);
    }

    /**
     * Runs Tier 2 ({@code CBIT}): checks runtime zero-sum resource conservation ({@code S-002}),
     * stall/exception attribution ({@code S-005}), and sink delivery vs. hollow no-op ({@code S-004}).
     */
    public CheckResult runSliceCbit(
            List<FaultSignature> liveFaults,
            List<ClassRetentionFinding> liveLeaks,
            int commandsRun,
            int effectsSeen,
            Set<String> invariants
    ) {
        long t0 = System.nanoTime();
        List<String> issues = new ArrayList<>();
        Set<String> sliceClasses = extractSliceClassNames(slice);

        // 1. Check hollow command / non-delivery (S-004)
        for (CausalFinding f : sliceFindings) {
            if (f.kind() == FindingKind.CAUSAL_HOLLOW_COMMAND) {
                invariants.add("S-004-HOLLOW-COMMAND");
                issues.add("Hollow command slice (" + f.causalDefect() + ")");
            }
        }
        if (slice.kind() == EntryPointKind.COMMAND
                && commandsRun > 0
                && effectsSeen == 0
                && (slice.reachableEffectSinks().contains("TELEPORT")
                || slice.reachableEffectSinks().contains("INVENTORY_MENU")
                || slice.reachableEffectSinks().contains("WORLD_MUTATION"))) {
            invariants.add("S-004-ZERO-LIVE-DELIVERY");
            issues.add("Dispatched " + commandsRun + " command(s) but observed 0 runtime sink deliveries");
        }

        // 2. Check post-GC class retention conservation (S-002)
        if (liveLeaks != null) {
            for (ClassRetentionFinding leak : liveLeaks) {
                if (matchesAnySliceClass(leak.className(), sliceClasses)) {
                    invariants.add("S-002-RETENTION-LEAK");
                    issues.add(String.format(
                            Locale.ROOT,
                            "S-002 retention slope +%.2f inst/ep on %s",
                            leak.slopePerEvent(),
                            leak.className()
                    ));
                }
            }
        }

        // 3. Check main-thread stalls & uncaught exceptions intersecting the slice's hop trace (S-005 / S-004)
        if (liveFaults != null) {
            for (FaultSignature fault : liveFaults) {
                if (matchesAnySliceClass( extractFrameClass(fault.topPluginFrame()), sliceClasses)) {
                    invariants.add(fault.signatureId().startsWith("stall:") || fault.signatureId().startsWith("hazard:")
                            ? "S-005-RUNTIME-STALL"
                            : "S-004-UNCAUGHT-EXCEPTION");
                    issues.add("Attributed fault " + fault.signatureId() + " (count=" + fault.occurrences() + ")");
                }
            }
        }

        double ms = (System.nanoTime() - t0) / 1_000_000.0;
        boolean ok = issues.isEmpty();
        String detail = ok
                ? ("Causal-chain CBIT conservation & delivery verified (" + slice.entrySymbol() + ")")
                : ("Causal-chain CBIT tripped: " + String.join("; ", issues));
        return new CheckResult("SLICE-CBIT:" + slice.entrySymbol(), "CBIT", ok, detail, ms);
    }

    /**
     * Runs Tier 3 ({@code IBIT}): injects a controlled synthetic fault against an isolated
     * in-memory oracle scoped to the slice's entry class, verifying that the BIT fault detector
     * catches and attributes the fault and that all temporary probe state is rolled back.
     */
    public CheckResult runSliceIbit(
            InMemorySliceBitSession session,
            boolean sliceSuspectOrFailed,
            Set<String> invariants
    ) {
        long t0 = System.nanoTime();
        String entryClass = extractOwnerClassName(slice.entrySymbol());
        String probeClass = (entryClass.startsWith("net.leaf.fuzz.") || entryClass.startsWith("net.leaf.sleuth."))
                ? "com.probe.slice." + simpleClassName(entryClass)
                : entryClass;
        String entryMethod = extractMethodName(slice.entrySymbol());
        try {
            session.putTemporaryProbeAttribute("ibit.active", Boolean.TRUE);
            session.putTemporaryProbeAttribute("ibit.suspect", sliceSuspectOrFailed);

            // Isolated in-memory fault-injection oracle (zero impact on live runtime oracle)
            String syntheticJarName = artifactName.endsWith(".jar") ? artifactName : (artifactName + ".jar");
            LogAndStallSignatureOracle isolatedOracle = new LogAndStallSignatureOracle(
                    JarClassOwnershipIndex.fromJarClassMap(Map.of(syntheticJarName, Set.of(probeClass)))
            );

            StackTraceElement[] injectedFrames = new StackTraceElement[]{
                    new StackTraceElement("net.minecraft.server.level.ServerChunkCache", "getChunk", "ServerChunkCache.java", 120),
                    new StackTraceElement(probeClass, entryMethod, simpleClassName(probeClass) + ".java", 1)
            };
            Optional<FaultSignature> detectedHazard = isolatedOracle.recordMainThreadHazardStack(35.0, injectedFrames, 0L);
            IllegalStateException syntheticFault = new IllegalStateException("IBIT fault-injection probe for " + slice.entrySymbol());
            syntheticFault.setStackTrace(injectedFrames);
            isolatedOracle.recordThrowable(syntheticFault, "IBIT probe", 0L);

            boolean faultDetected = detectedHazard.isPresent()
                    && detectedHazard.get().topPluginFrame().startsWith(probeClass)
                    && isolatedOracle.totalExceptionsRecorded() == 1L;
            if (!faultDetected) {
                invariants.add("IBIT-ORACLE-BLIND");
            }
            double ms = (System.nanoTime() - t0) / 1_000_000.0;
            String modeLabel = sliceSuspectOrFailed ? "failing-chain IBIT fault-injection" : "baseline IBIT self-verification";
            String detail = faultDetected
                    ? ("Causal-chain IBIT (" + modeLabel + ") verified deterministic hazard/exception capture & in-memory rollback on " + slice.entrySymbol())
                    : ("Causal-chain IBIT oracle failed to attribute injected fault on " + slice.entrySymbol());
            return new CheckResult("SLICE-IBIT:" + slice.entrySymbol(), "IBIT", faultDetected, detail, ms);
        } catch (Throwable t) {
            double ms = (System.nanoTime() - t0) / 1_000_000.0;
            invariants.add("IBIT-EXCEPTION");
            return new CheckResult("SLICE-IBIT:" + slice.entrySymbol(), "IBIT", false, "IBIT exception: " + t.getMessage(), ms);
        }
    }

    /**
     * Audits all entry slices in a {@link CausalGraphReport} using in-memory {@code PBIT},
     * {@code CBIT}, and {@code IBIT} harnesses and returns their reports.
     */
    public static List<SliceBitReport> auditReportSlices(
            CausalGraphReport report,
            Map<String, byte[]> inMemoryClassBytes,
            List<FaultSignature> liveFaults,
            List<ClassRetentionFinding> liveLeaks,
            int commandsRun,
            int effectsSeen
    ) {
        if (report == null || report.entryChains().isEmpty()) {
            return List.of();
        }
        List<SliceBitReport> out = new ArrayList<>(report.entryChains().size());
        for (CausalChainSlice slice : report.entryChains()) {
            SliceBitHarness harness = new SliceBitHarness(
                    report.displayName(),
                    slice,
                    report.findings(),
                    inMemoryClassBytes
            );
            out.add(harness.executeFullSliceBit(liveFaults, liveLeaks, commandsRun, effectsSeen));
        }
        return List.copyOf(out);
    }

    /**
     * Computes the SHA-256 digest of a {@code .jar} file on disk so callers and tests can prove
     * that in-memory slice BIT auditing never modifies or touches the archive file.
     */
    public static byte[] computeFileSha256(Path jarPath) throws IOException {
        Objects.requireNonNull(jarPath, "jarPath");
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(Files.readAllBytes(jarPath));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static List<CausalFinding> filterFindingsForSlice(
            CausalChainSlice slice,
            List<CausalFinding> allFindings
    ) {
        if (allFindings == null || allFindings.isEmpty()) {
            return List.of();
        }
        Set<String> sliceSymbols = new LinkedHashSet<>();
        sliceSymbols.add(slice.entrySymbol());
        sliceSymbols.add(simpleMethodRef(slice.entrySymbol()));
        for (String hop : slice.hopTrace()) {
            int bracket = hop.indexOf(' ');
            String cleanHop = bracket > 0 ? hop.substring(0, bracket).trim() : hop.trim();
            sliceSymbols.add(cleanHop);
            sliceSymbols.add(simpleMethodRef(cleanHop));
        }
        for (String sp : slice.spawnedSuppliersAndLambdas()) {
            sliceSymbols.add(sp);
            sliceSymbols.add(simpleMethodRef(sp));
        }
        Set<String> sliceClasses = extractSliceClassNames(slice);
        Set<String> sliceConfigs = new LinkedHashSet<>(slice.readConfigKeys());
        if (!slice.gatingConfigKey().isBlank()) {
            sliceConfigs.add(slice.gatingConfigKey());
        }

        List<CausalFinding> matched = new ArrayList<>();
        for (CausalFinding f : allFindings) {
            String ep = f.entryPointSymbol();
            String epSimple = simpleMethodRef(ep);
            String epClass = extractOwnerClassName(ep);
            boolean symbolMatch = sliceSymbols.contains(ep)
                    || sliceSymbols.contains(epSimple)
                    || sliceClasses.contains(epClass)
                    || sliceConfigs.contains(ep);
            if (symbolMatch) {
                matched.add(f);
            }
        }
        return List.copyOf(matched);
    }

    private static Set<String> extractSliceClassNames(CausalChainSlice slice) {
        Set<String> classes = new LinkedHashSet<>();
        String entryCls = extractOwnerClassName(slice.entrySymbol());
        if (!entryCls.isEmpty()) {
            classes.add(entryCls);
            classes.add(simpleClassName(entryCls));
        }
        for (String hop : slice.hopTrace()) {
            int space = hop.indexOf(' ');
            String sym = space > 0 ? hop.substring(0, space).trim() : hop.trim();
            String cls = extractOwnerClassName(sym);
            if (!cls.isEmpty()) {
                classes.add(cls);
                classes.add(simpleClassName(cls));
            }
        }
        return classes;
    }

    private static boolean matchesAnySliceClass(String candidateClass, Set<String> sliceClasses) {
        if (candidateClass == null || candidateClass.isBlank() || sliceClasses.isEmpty()) {
            return false;
        }
        String norm = candidateClass.replace('/', '.').trim();
        return sliceClasses.contains(norm) || sliceClasses.contains(simpleClassName(norm));
    }

    private static String extractFrameClass(String topPluginFrame) {
        if (topPluginFrame == null || topPluginFrame.isBlank()) {
            return "";
        }
        String norm = topPluginFrame.replace('#', '.').trim();
        int lastDot = norm.lastIndexOf('.');
        return lastDot > 0 ? norm.substring(0, lastDot) : norm;
    }

    private static String extractOwnerClassName(String symbol) {
        if (symbol == null || symbol.isBlank()) {
            return "unknown.SliceTarget";
        }
        int hash = symbol.indexOf('#');
        String raw = hash >= 0 ? symbol.substring(0, hash) : symbol;
        return raw.replace('/', '.').trim();
    }

    private static String extractMethodName(String symbol) {
        if (symbol == null || symbol.isBlank()) {
            return "execute";
        }
        int hash = symbol.indexOf('#');
        return hash >= 0 && hash + 1 < symbol.length() ? symbol.substring(hash + 1).trim() : "execute";
    }

    private static String simpleClassName(String binaryOrInternal) {
        if (binaryOrInternal == null || binaryOrInternal.isEmpty()) {
            return "";
        }
        String norm = binaryOrInternal.replace('/', '.');
        int dot = norm.lastIndexOf('.');
        return dot >= 0 ? norm.substring(dot + 1) : norm;
    }

    private static String simpleMethodRef(String symbol) {
        if (symbol == null || symbol.isEmpty()) {
            return "";
        }
        int hash = symbol.indexOf('#');
        if (hash < 0) {
            return simpleClassName(symbol);
        }
        return simpleClassName(symbol.substring(0, hash)) + symbol.substring(hash);
    }
}
