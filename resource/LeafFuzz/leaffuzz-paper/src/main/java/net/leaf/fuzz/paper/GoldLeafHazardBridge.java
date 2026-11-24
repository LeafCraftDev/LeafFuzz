package net.leaf.fuzz.paper;

import net.leaf.fuzz.common.LeafFuzzRuntime;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Reflection-safe runtime bridge to GoldLeaf's {@code dev.leafcraft.goldleaf.diagnostics.TickHazardMonitor}
 * ({@code goldleaf-ADR-007} §2.2).
 *
 * <p>When {@code LeafFuzz} runs on a GoldLeaf server, subscribes a non-blocking proxy
 * {@code TickHazardListener} to forward {@code SYNC_CHUNK_LOAD}, {@code TICK_STALL}, and
 * {@code WRONG_REGION_ACCESS} events directly into {@link LeafFuzzRuntime#recordRuntimeHazard}.
 * On stock Paper/Folia servers where GoldLeaf's monitor is absent, {@link #tryBind} returns
 * {@code null} with zero runtime dependency or error.</p>
 *
 * @governedBy goldleaf-ADR-007, ADR-115, ADR-125, leaffuzz-ADR-001
 * @trace REQ-SLEUTH-FUZZ-004, S-002, S-004, S-005
 */
public final class GoldLeafHazardBridge implements AutoCloseable {

    static final String MONITOR_CLASS_NAME = "dev.leafcraft.goldleaf.diagnostics.TickHazardMonitor";
    static final String LISTENER_CLASS_NAME = "dev.leafcraft.goldleaf.diagnostics.TickHazardListener";

    private final Method unregisterMethod;
    private final Object listenerProxy;
    private final Logger logger;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicLong syncChunkLoadEvents;
    private final AtomicLong tickStallEvents;
    private final AtomicLong wrongRegionAccessEvents;

    private GoldLeafHazardBridge(
            Method unregisterMethod,
            Object listenerProxy,
            Logger logger,
            AtomicLong syncChunkLoadEvents,
            AtomicLong tickStallEvents,
            AtomicLong wrongRegionAccessEvents
    ) {
        this.unregisterMethod = unregisterMethod;
        this.listenerProxy = listenerProxy;
        this.logger = logger;
        this.syncChunkLoadEvents = syncChunkLoadEvents;
        this.tickStallEvents = tickStallEvents;
        this.wrongRegionAccessEvents = wrongRegionAccessEvents;
    }

    /**
     * Probes for GoldLeaf's {@code TickHazardMonitor} on the runtime classpath and registers a
     * non-blocking listener proxy if present.
     *
     * @return active bridge, or {@code null} when running on stock Paper/Folia
     */
    public static GoldLeafHazardBridge tryBind(LeafFuzzRuntime runtime, Logger logger) {
        Objects.requireNonNull(runtime, "runtime");
        Logger log = logger != null ? logger : Logger.getLogger(GoldLeafHazardBridge.class.getName());
        try {
            ClassLoader cl = GoldLeafHazardBridge.class.getClassLoader();
            Class<?> monitorClass = Class.forName(MONITOR_CLASS_NAME, false, cl);
            Class<?> listenerInterface = Class.forName(LISTENER_CLASS_NAME, false, cl);
            return bindToMonitor(monitorClass, listenerInterface, runtime, log);
        } catch (ClassNotFoundException e) {
            log.log(Level.FINE, "[LeafFuzz] GoldLeaf TickHazardMonitor not present on classpath", e);
            return null;
        } catch (Throwable t) {
            log.log(Level.WARNING, "[LeafFuzz] Failed probing GoldLeaf TickHazardMonitor", t);
            return null;
        }
    }

    static GoldLeafHazardBridge bindToMonitor(
            Class<?> monitorClass,
            Class<?> listenerInterface,
            LeafFuzzRuntime runtime,
            Logger logger
    ) throws ReflectiveOperationException {
        Objects.requireNonNull(monitorClass, "monitorClass");
        Objects.requireNonNull(listenerInterface, "listenerInterface");
        Objects.requireNonNull(runtime, "runtime");
        Logger log = logger != null ? logger : Logger.getLogger(GoldLeafHazardBridge.class.getName());

        Method registerMethod = monitorClass.getMethod("registerListener", listenerInterface);
        Method unregisterMethod = monitorClass.getMethod("unregisterListener", listenerInterface);

        AtomicLong syncCounter = new AtomicLong();
        AtomicLong stallCounter = new AtomicLong();
        AtomicLong wrongRegionCounter = new AtomicLong();

        Object proxy = Proxy.newProxyInstance(
                listenerInterface.getClassLoader(),
                new Class<?>[]{listenerInterface},
                (p, method, args) -> {
                    String name = method.getName();
                    if ("onSyncChunkLoad".equals(name) && args != null && args.length == 4) {
                        syncCounter.incrementAndGet();
                        String worldName = args[0] != null ? args[0].toString() : "world";
                        int chunkX = ((Number) args[1]).intValue();
                        int chunkZ = ((Number) args[2]).intValue();
                        String caller = args[3] != null ? args[3].toString() : "unknown";
                        runtime.recordRuntimeHazard(
                                caller,
                                "goldleaf:sync_chunk_load:" + worldName + ":" + chunkX + "," + chunkZ,
                                "GOLDLEAF_SYNC_CHUNK_LOAD",
                                "FAIL",
                                worldName + " (" + chunkX + "," + chunkZ + ")",
                                "Synchronous tick-thread chunk load attributed to " + caller
                        );
                    } else if ("onTickStall".equals(name) && args != null && args.length == 3) {
                        stallCounter.incrementAndGet();
                        long regionId = ((Number) args[0]).longValue();
                        long durationNanos = ((Number) args[1]).longValue();
                        String phase = args[2] != null ? args[2].toString() : "region_tick";
                        double durationMs = durationNanos / 1_000_000.0;
                        runtime.recordRuntimeHazard(
                                "goldleaf-region-" + regionId,
                                "goldleaf:tick_stall:" + phase + ":" + regionId,
                                "GOLDLEAF_TICK_STALL",
                                "WARN",
                                phase + " region=" + regionId,
                                String.format("Tick stall %.2f ms in %s (region=%d)", durationMs, phase, regionId)
                        );
                    } else if ("onWrongRegionAccess".equals(name) && args != null && args.length == 2) {
                        wrongRegionCounter.incrementAndGet();
                        String reason = args[0] != null ? args[0].toString() : "wrong_region";
                        String context = args[1] != null ? args[1].toString() : "";
                        runtime.recordRuntimeHazard(
                                "goldleaf-region",
                                "goldleaf:wrong_region:" + reason,
                                "GOLDLEAF_WRONG_REGION_ACCESS",
                                "FAIL",
                                reason,
                                context
                        );
                    } else if ("equals".equals(name) && args != null && args.length == 1) {
                        return p == args[0];
                    } else if ("hashCode".equals(name)) {
                        return System.identityHashCode(p);
                    } else if ("toString".equals(name)) {
                        return "LeafFuzzGoldLeafHazardListener";
                    }
                    return null;
                }
        );

        registerMethod.invoke(null, proxy);
        log.info("[LeafFuzz] Subscribed to GoldLeaf TickHazardMonitor (goldleaf-ADR-007)");
        return new GoldLeafHazardBridge(
                unregisterMethod,
                proxy,
                log,
                syncCounter,
                stallCounter,
                wrongRegionCounter
        );
    }

    public boolean isClosed() {
        return this.closed.get();
    }

    public long syncChunkLoadEvents() {
        return this.syncChunkLoadEvents.get();
    }

    public long tickStallEvents() {
        return this.tickStallEvents.get();
    }

    public long wrongRegionAccessEvents() {
        return this.wrongRegionAccessEvents.get();
    }

    @Override
    public void close() {
        if (!this.closed.compareAndSet(false, true)) {
            return;
        }
        try {
            this.unregisterMethod.invoke(null, this.listenerProxy);
        } catch (Throwable t) {
            this.logger.log(Level.WARNING, "[LeafFuzz] Failed unregistering GoldLeaf TickHazardListener", t);
        }
    }
}
