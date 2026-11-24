package net.leaf.fuzz.paper;

import net.leaf.bit.config.FuzzDiagnosticSnapshotSource.FuzzRuntimeHazardRecord;
import io.github.dailystruggle.server.api.ServerAccessor;
import net.leaf.fuzz.common.LeafFuzzRuntime;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GoldLeafHazardBridgeTest {

    public interface FakeTickHazardListener {
        void onSyncChunkLoad(String worldName, int chunkX, int chunkZ, String callerClass);
        void onTickStall(long regionId, long durationNanos, String tickPhase);
        void onWrongRegionAccess(String reason, String context);
    }

    public static final class FakeTickHazardMonitor {
        static final CopyOnWriteArrayList<FakeTickHazardListener> LISTENERS = new CopyOnWriteArrayList<>();
        static final AtomicInteger UNREGISTER_CALLS = new AtomicInteger();

        public static void registerListener(FakeTickHazardListener listener) {
            LISTENERS.addIfAbsent(listener);
        }

        public static boolean unregisterListener(FakeTickHazardListener listener) {
            UNREGISTER_CALLS.incrementAndGet();
            return LISTENERS.remove(listener);
        }

        static void reset() {
            LISTENERS.clear();
            UNREGISTER_CALLS.set(0);
        }
    }

    @AfterEach
    void tearDown() {
        FakeTickHazardMonitor.reset();
    }

    private static ServerAccessor stubServerAccessor() {
        return (ServerAccessor) Proxy.newProxyInstance(
                ServerAccessor.class.getClassLoader(),
                new Class<?>[]{ServerAccessor.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getPlatform" -> "paper";
                    case "getServerVersion" -> "1.21.4";
                    case "equals" -> proxy == args[0];
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "toString" -> "StubServerAccessor";
                    default -> null;
                }
        );
    }

    @Test
    void tryBindReturnsNullCleanlyOnStockPaperWithoutGoldLeaf() {
        LeafFuzzRuntime runtime = new LeafFuzzRuntime(stubServerAccessor());
        GoldLeafHazardBridge bridge = GoldLeafHazardBridge.tryBind(runtime, Logger.getLogger("test"));
        assertNull(bridge, "stock Paper/Folia without GoldLeaf TickHazardMonitor must return null cleanly");
    }

    @Test
    void bindToMonitorForwardsAllHazardTypesAndClosesIdempotently() throws Exception {
        LeafFuzzRuntime runtime = new LeafFuzzRuntime(stubServerAccessor());
        GoldLeafHazardBridge bridge = GoldLeafHazardBridge.bindToMonitor(
                FakeTickHazardMonitor.class,
                FakeTickHazardListener.class,
                runtime,
                Logger.getLogger("test")
        );
        assertNotNull(bridge);
        assertFalse(bridge.isClosed());
        assertEquals(1, FakeTickHazardMonitor.LISTENERS.size());

        FakeTickHazardListener listener = FakeTickHazardMonitor.LISTENERS.get(0);
        listener.onSyncChunkLoad("world", 12, -4, "com.example.LagPlugin");
        listener.onTickStall(7L, 145_000_000L, "global_tick");
        listener.onWrongRegionAccess("off-region write", "world=world block=(1,64,2)");

        assertEquals(1L, bridge.syncChunkLoadEvents());
        assertEquals(1L, bridge.tickStallEvents());
        assertEquals(1L, bridge.wrongRegionAccessEvents());

        List<FuzzRuntimeHazardRecord> hazards = runtime.diagnosticFuzzRuntimeHazards();
        assertEquals(3, hazards.size());
        assertTrue(hazards.stream().anyMatch(h -> "GOLDLEAF_SYNC_CHUNK_LOAD".equals(h.category())));
        assertTrue(hazards.stream().anyMatch(h -> "GOLDLEAF_TICK_STALL".equals(h.category())));
        assertTrue(hazards.stream().anyMatch(h -> "GOLDLEAF_WRONG_REGION_ACCESS".equals(h.category())));

        // S-002 idempotent close: second close must be a no-op
        bridge.close();
        bridge.close();
        assertTrue(bridge.isClosed());
        assertEquals(0, FakeTickHazardMonitor.LISTENERS.size());
        assertEquals(1, FakeTickHazardMonitor.UNREGISTER_CALLS.get());
    }
}
