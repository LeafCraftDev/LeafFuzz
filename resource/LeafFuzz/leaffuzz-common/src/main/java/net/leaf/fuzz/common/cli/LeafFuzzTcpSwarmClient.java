package net.leaf.fuzz.common.cli;

import net.leaf.fuzz.common.LeafFuzzRuntime;
import net.leaf.fuzz.common.LeafFuzzScorecardReport.Verdict;
import net.leaf.fuzz.common.NmsEmbeddedPlayerSession;
import net.leaf.sleuth.common.fuzz.PersonaPolicyBotActor;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;

/**
 * Pure-Java standalone Minecraft TCP protocol swarm client and ramp-to-instability capacity
 * verifier packed inside {@code LeafFuzz.jar} ({@code ADR-115}, {@code ADR-125},
 * {@code leaffuzz-ADR-001}).
 *
 * <p>Requires zero external runtime dependencies (`java -jar LeafFuzz.jar swarm`): auto-detects
 * server protocol version via Server List Ping (`SLP`), connects up to 500 concurrent offline-mode
 * bot sockets dispersed across an Archimedean spiral, steps their {@link PersonaPolicyBotActor}
 * policies, measures server response latency (`p95`/`max` RTT), and progressively ramps concurrent
 * players until the server becomes unstable or reaches the target capacity ceiling.
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy leaffuzz-ADR-001
 * @trace REQ-SLEUTH-FUZZ-004
 * @trace S-004
 */
public final class LeafFuzzTcpSwarmClient {

    private static final Pattern PROTOCOL_JSON_PATTERN =
            Pattern.compile("\"protocol\"\\s*:\\s*(-?[0-9]+)");
    private static final Pattern VERSION_NAME_JSON_PATTERN =
            Pattern.compile("\"name\"\\s*:\\s*\"([^\"]+)\"");

    /**
     * Decoded Minecraft framed packet (`packetId` + uncompressed payload bytes).
     */
    public record RawPacket(int packetId, byte[] payload) {
    }

    /**
     * Result of a Server List Ping (`SLP`) status + latency probe.
     */
    public record ServerStatusProbe(
            boolean reachable,
            String versionName,
            int protocolVersion,
            double pingRttMs,
            String rawJson
    ) {
    }

    /**
     * Configuration for an external TCP swarm and ramp-to-instability run.
     */
    public record SwarmConfig(
            String host,
            int port,
            int targetPlayers,
            boolean rampUntilUnstable,
            int durationSeconds,
            int connectTimeoutMs,
            int protocolVersion,
            double maxStableRttP95Ms
    ) {
        public SwarmConfig {
            host = (host == null || host.isBlank()) ? "127.0.0.1" : host.trim();
            port = (port <= 0 || port > 65535) ? 25565 : port;
            targetPlayers = Math.max(1, Math.min(500, targetPlayers <= 0 ? 100 : targetPlayers));
            durationSeconds = Math.max(1, Math.min(3600, durationSeconds));
            connectTimeoutMs = Math.max(200, Math.min(30_000, connectTimeoutMs <= 0 ? 3_000 : connectTimeoutMs));
            maxStableRttP95Ms = (Double.isFinite(maxStableRttP95Ms) && maxStableRttP95Ms >= 10.0)
                    ? maxStableRttP95Ms
                    : 55.0;
        }

        public static SwarmConfig defaults() {
            return new SwarmConfig("127.0.0.1", 25565, 100, true, 15, 3_000, -1, 55.0);
        }
    }

    /**
     * Final readiness report produced by {@link #runSwarm(SwarmConfig)}.
     */
    public record SwarmReadinessReport(
            Verdict verdict,
            String host,
            int port,
            String serverVersion,
            int protocolVersion,
            int targetPlayers,
            int peakConnectedPlayers,
            int maxStablePlayers,
            int droppedConnections,
            int totalBotStepsExecuted,
            double rttMeanMs,
            double rttP95Ms,
            double rttMaxMs,
            long elapsedMillis,
            String instabilityTrigger
    ) {
        public SwarmReadinessReport {
            verdict = verdict == null ? Verdict.FAIL : verdict;
            host = host == null ? "127.0.0.1" : host;
            serverVersion = (serverVersion == null || serverVersion.isBlank()) ? "unknown" : serverVersion;
            instabilityTrigger = instabilityTrigger == null ? "" : instabilityTrigger.trim();
        }

        public List<String> formatConsoleLines() {
            List<String> lines = new ArrayList<>();
            lines.add("=== LeafFuzz Standalone Swarm Readiness Report -> " + verdict.name() + " ===");
            lines.add(String.format(
                    Locale.ROOT,
                    "Target Server: %s:%d (version=%s, protocol=%d, elapsed=%d ms)",
                    host, port, serverVersion, protocolVersion, elapsedMillis
            ));
            lines.add(String.format(
                    Locale.ROOT,
                    "Concurrent Players: peak=%d/%d | certifiedMaxStable=%d | dropped=%d | policySteps=%d",
                    peakConnectedPlayers, targetPlayers, maxStablePlayers, droppedConnections, totalBotStepsExecuted
            ));
            lines.add(String.format(
                    Locale.ROOT,
                    "Response Latency (RTT): mean=%.2f ms | p95=%.2f ms | max=%.2f ms",
                    rttMeanMs, rttP95Ms, rttMaxMs
            ));
            if (!instabilityTrigger.isEmpty()) {
                lines.add("Instability Breaking Point: " + instabilityTrigger);
            } else {
                lines.add("Stability Proof: Server remained stable through full " + maxStablePlayers + "-player ceiling.");
            }
            return List.copyOf(lines);
        }

        public String toMarkdownReport() {
            StringBuilder sb = new StringBuilder();
            sb.append("### LeafFuzz Standalone Swarm Readiness Report — **")
                    .append(verdict.name()).append("**\n\n");
            sb.append("- **Target Server:** `").append(host).append(':').append(port)
                    .append("` (`").append(serverVersion).append("`, protocol `")
                    .append(protocolVersion).append("`)\n");
            sb.append("- **Peak Concurrent Players:** `").append(peakConnectedPlayers)
                    .append('/').append(targetPlayers).append("`\n");
            sb.append("- **Certified Max Stable Players:** `").append(maxStablePlayers).append("`\n");
            sb.append("- **Dropped / Rejected Connections:** `").append(droppedConnections).append("`\n");
            sb.append("- **Persona Policy Steps Executed:** `").append(totalBotStepsExecuted).append("`\n");
            sb.append(String.format(
                    Locale.ROOT,
                    "- **Response Latency (RTT):** mean `%.2f ms` | p95 `%.2f ms` | max `%.2f ms`\n",
                    rttMeanMs, rttP95Ms, rttMaxMs
            ));
            sb.append("- **Breaking Point / Trigger:** `")
                    .append(instabilityTrigger.isEmpty() ? "none (stable through ceiling)" : instabilityTrigger)
                    .append("`\n");
            sb.append("- **Elapsed Wall Time:** `").append(elapsedMillis).append(" ms`\n");
            sb.append("- **Generated At:** `").append(Instant.now()).append("`\n");
            return sb.toString();
        }
    }

    private LeafFuzzTcpSwarmClient() {
    }

    /**
     * Writes a Minecraft protocol VarInt to {@code out}.
     */
    public static void writeVarInt(OutputStream out, int value) throws IOException {
        int v = value;
        while ((v & ~0x7F) != 0) {
            out.write((v & 0x7F) | 0x80);
            v >>>= 7;
        }
        out.write(v);
    }

    /**
     * Reads a Minecraft protocol VarInt from {@code in}.
     */
    public static int readVarInt(InputStream in) throws IOException {
        int numRead = 0;
        int result = 0;
        int read;
        do {
            read = in.read();
            if (read == -1) {
                throw new EOFException("Unexpected EOF while reading VarInt");
            }
            int value = (read & 0x7F);
            result |= (value << (7 * numRead));
            numRead++;
            if (numRead > 5) {
                throw new IOException("VarInt is too big");
            }
        } while ((read & 0x80) != 0);
        return result;
    }

    /**
     * Writes a UTF-8 length-prefixed string to {@code out}.
     */
    public static void writeUtfString(OutputStream out, String str) throws IOException {
        byte[] bytes = (str == null ? "" : str).getBytes(StandardCharsets.UTF_8);
        writeVarInt(out, bytes.length);
        out.write(bytes);
    }

    /**
     * Reads a UTF-8 length-prefixed string from {@code in}.
     */
    public static String readUtfString(InputStream in, int maxChars) throws IOException {
        int byteLen = readVarInt(in);
        if (byteLen < 0 || byteLen > maxChars * 4) {
            throw new IOException("Invalid string byte length: " + byteLen);
        }
        byte[] buf = in.readNBytes(byteLen);
        if (buf.length < byteLen) {
            throw new EOFException("Truncated UTF-8 string");
        }
        return new String(buf, StandardCharsets.UTF_8);
    }

    /**
     * Sends a framed Minecraft packet, applying Zlib framing when {@code compressionThreshold >= 0}.
     */
    public static void sendPacket(
            OutputStream out,
            int packetId,
            byte[] payload,
            int compressionThreshold
    ) throws IOException {
        ByteArrayOutputStream uncompressed = new ByteArrayOutputStream(
                (payload != null ? payload.length : 0) + 5
        );
        writeVarInt(uncompressed, packetId);
        if (payload != null && payload.length > 0) {
            uncompressed.write(payload);
        }
        byte[] raw = uncompressed.toByteArray();

        ByteArrayOutputStream frame = new ByteArrayOutputStream(raw.length + 10);
        if (compressionThreshold < 0) {
            writeVarInt(frame, raw.length);
            frame.write(raw);
        } else if (raw.length < compressionThreshold) {
            ByteArrayOutputStream body = new ByteArrayOutputStream(raw.length + 5);
            writeVarInt(body, 0);
            body.write(raw);
            byte[] bodyBytes = body.toByteArray();
            writeVarInt(frame, bodyBytes.length);
            frame.write(bodyBytes);
        } else {
            ByteArrayOutputStream deflated = new ByteArrayOutputStream();
            try (DeflaterOutputStream dos = new DeflaterOutputStream(deflated)) {
                dos.write(raw);
            }
            byte[] compBytes = deflated.toByteArray();
            ByteArrayOutputStream body = new ByteArrayOutputStream(compBytes.length + 5);
            writeVarInt(body, raw.length);
            body.write(compBytes);
            byte[] bodyBytes = body.toByteArray();
            writeVarInt(frame, bodyBytes.length);
            frame.write(bodyBytes);
        }
        out.write(frame.toByteArray());
        out.flush();
    }

    /**
     * Reads a single framed Minecraft packet from {@code in}.
     */
    public static RawPacket readPacket(InputStream in, int compressionThreshold) throws IOException {
        int frameLen = readVarInt(in);
        if (frameLen <= 0 || frameLen > 2_097_152) {
            throw new IOException("Invalid packet frame length: " + frameLen);
        }
        byte[] frameBytes = in.readNBytes(frameLen);
        if (frameBytes.length < frameLen) {
            throw new EOFException("Truncated packet frame");
        }
        ByteArrayInputStream bais = new ByteArrayInputStream(frameBytes);
        byte[] uncompressed;
        if (compressionThreshold < 0) {
            uncompressed = frameBytes;
        } else {
            int dataLen = readVarInt(bais);
            if (dataLen == 0) {
                uncompressed = bais.readAllBytes();
            } else {
                try (InflaterInputStream iis = new InflaterInputStream(bais)) {
                    uncompressed = iis.readNBytes(dataLen);
                }
            }
        }
        ByteArrayInputStream pktIn = new ByteArrayInputStream(uncompressed);
        int packetId = readVarInt(pktIn);
        byte[] payload = pktIn.readAllBytes();
        return new RawPacket(packetId, payload);
    }

    /**
     * Probes the target server via Server List Ping (`nextState = 1`) to auto-detect its
     * protocol version and measure baseline ping RTT.
     */
    public static ServerStatusProbe probeServerStatus(String host, int port, int timeoutMs) {
        long t0 = System.nanoTime();
        try (Socket socket = new Socket()) {
            socket.setSoTimeout(Math.max(250, timeoutMs));
            socket.connect(new InetSocketAddress(host, port), Math.max(250, timeoutMs));
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            ByteArrayOutputStream hs = new ByteArrayOutputStream();
            writeVarInt(hs, 767);
            writeUtfString(hs, host);
            DataOutputStream dos = new DataOutputStream(hs);
            dos.writeShort(port);
            writeVarInt(hs, 1); // Status state
            sendPacket(out, 0x00, hs.toByteArray(), -1);
            sendPacket(out, 0x00, new byte[0], -1);

            RawPacket statusResp = readPacket(in, -1);
            String json = "";
            if (statusResp.packetId() == 0x00 && statusResp.payload().length > 0) {
                json = readUtfString(new ByteArrayInputStream(statusResp.payload()), 32767);
            }

            long pingSend = System.nanoTime();
            ByteArrayOutputStream pingBuf = new ByteArrayOutputStream(8);
            new DataOutputStream(pingBuf).writeLong(System.currentTimeMillis());
            sendPacket(out, 0x01, pingBuf.toByteArray(), -1);
            double rttMs;
            try {
                readPacket(in, -1);
                rttMs = (System.nanoTime() - pingSend) / 1_000_000.0;
            } catch (IOException ignored) {
                rttMs = (System.nanoTime() - t0) / 1_000_000.0;
            }

            int protocol = 767;
            Matcher pm = PROTOCOL_JSON_PATTERN.matcher(json);
            if (pm.find()) {
                try {
                    protocol = Integer.parseInt(pm.group(1));
                } catch (NumberFormatException ignored) {
                }
            }
            String versionName = "unknown";
            Matcher vm = VERSION_NAME_JSON_PATTERN.matcher(json);
            if (vm.find()) {
                versionName = vm.group(1);
            }
            return new ServerStatusProbe(true, versionName, protocol, rttMs, json);
        } catch (IOException e) {
            return new ServerStatusProbe(false, "unreachable", 767, 0.0, "");
        }
    }

    /**
     * Executes a concurrent multi-player TCP swarm and ramp-to-instability capacity test against
     * {@code config.host():config.port()}.
     */
    public static SwarmReadinessReport runSwarm(SwarmConfig config) {
        Objects.requireNonNull(config, "config");
        long t0 = System.currentTimeMillis();
        ServerStatusProbe initialProbe = probeServerStatus(
                config.host(),
                config.port(),
                config.connectTimeoutMs()
        );
        int effProtocol = config.protocolVersion() > 0
                ? config.protocolVersion()
                : initialProbe.protocolVersion();
        String serverVer = initialProbe.versionName();

        List<Double> rttSamples = new CopyOnWriteArrayList<>();
        if (initialProbe.reachable() && initialProbe.pingRttMs() > 0.0) {
            rttSamples.add(initialProbe.pingRttMs());
        }

        List<Integer> rampSchedule = config.rampUntilUnstable()
                ? LeafFuzzRuntime.computePlayerRampSchedule(config.targetPlayers(), 4)
                : List.of(config.targetPlayers());

        List<ActiveBotConnection> activeBots = new CopyOnWriteArrayList<>();
        AtomicBoolean keepRunning = new AtomicBoolean(true);
        AtomicInteger droppedConnections = new AtomicInteger(0);
        AtomicInteger totalSteps = new AtomicInteger(0);
        int peakConnected = 0;
        int maxStable = 0;
        String instabilityTrigger = "";

        long stepWindowMs = Math.max(
                150L,
                (config.durationSeconds() * 1000L) / Math.max(1, rampSchedule.size())
        );

        try {
            for (int stepPop : rampSchedule) {
                while (activeBots.size() < stepPop) {
                    int botSlot = activeBots.size();
                    ActiveBotConnection conn = connectSingleBot(
                            config,
                            effProtocol,
                            botSlot,
                            keepRunning,
                            droppedConnections,
                            totalSteps,
                            rttSamples
                    );
                    if (conn != null) {
                        activeBots.add(conn);
                    } else {
                        droppedConnections.incrementAndGet();
                        break;
                    }
                }

                long stepDeadline = System.currentTimeMillis() + Math.min(stepWindowMs, 1_500L);
                while (System.currentTimeMillis() < stepDeadline) {
                    ServerStatusProbe probe = probeServerStatus(
                            config.host(),
                            config.port(),
                            config.connectTimeoutMs()
                    );
                    if (probe.reachable() && probe.pingRttMs() > 0.0) {
                        rttSamples.add(probe.pingRttMs());
                    }
                    for (ActiveBotConnection b : activeBots) {
                        b.stepPersona();
                    }
                    try {
                        Thread.sleep(60L);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }

                int liveConnected = 0;
                for (ActiveBotConnection b : activeBots) {
                    if (b.isAlive()) {
                        liveConnected++;
                    }
                }
                peakConnected = Math.max(peakConnected, liveConnected);
                double curP95 = percentile(rttSamples, 0.95);

                if (liveConnected < stepPop || droppedConnections.get() > 0) {
                    instabilityTrigger = String.format(
                            Locale.ROOT,
                            "connection_drop (connected %d/%d, dropped=%d) at %d players",
                            liveConnected,
                            stepPop,
                            droppedConnections.get(),
                            stepPop
                    );
                    break;
                }
                if (curP95 > config.maxStableRttP95Ms()) {
                    instabilityTrigger = String.format(
                            Locale.ROOT,
                            "rtt_p95=%.1fms (>%.1fms) at %d players",
                            curP95,
                            config.maxStableRttP95Ms(),
                            stepPop
                    );
                    break;
                }
                maxStable = Math.max(maxStable, liveConnected);
            }
        } finally {
            keepRunning.set(false);
            for (ActiveBotConnection b : activeBots) {
                b.close();
            }
        }

        long elapsed = Math.max(1L, System.currentTimeMillis() - t0);
        double meanRtt = mean(rttSamples);
        double p95Rtt = percentile(rttSamples, 0.95);
        double maxRtt = percentile(rttSamples, 1.0);

        Verdict verdict;
        if (peakConnected == 0) {
            verdict = Verdict.FAIL;
            if (instabilityTrigger.isEmpty()) {
                instabilityTrigger = "server_unreachable";
            }
        } else if (!instabilityTrigger.isEmpty()) {
            verdict = instabilityTrigger.startsWith("rtt_p95=") ? Verdict.WARN : Verdict.FAIL;
        } else if (peakConnected < config.targetPlayers()) {
            verdict = Verdict.FAIL;
        } else {
            verdict = Verdict.PASS;
        }

        return new SwarmReadinessReport(
                verdict,
                config.host(),
                config.port(),
                serverVer,
                effProtocol,
                config.targetPlayers(),
                peakConnected,
                maxStable,
                droppedConnections.get(),
                totalSteps.get(),
                meanRtt,
                p95Rtt,
                maxRtt,
                elapsed,
                instabilityTrigger
        );
    }

    private static ActiveBotConnection connectSingleBot(
            SwarmConfig config,
            int protocolVersion,
            int slotIndex,
            AtomicBoolean keepRunning,
            AtomicInteger droppedConnections,
            AtomicInteger totalSteps,
            List<Double> rttSamples
    ) {
        long t0 = System.nanoTime();
        List<PersonaPolicyBotActor.PersonaProfile> catalog = PersonaPolicyBotActor.defaultPersonaCatalog();
        PersonaPolicyBotActor.PersonaProfile persona =
                PersonaPolicyBotActor.selectPersonaForEpisode(catalog, slotIndex);
        PersonaPolicyBotActor actor = new PersonaPolicyBotActor(persona, "default", 1337 + slotIndex * 31);
        NmsEmbeddedPlayerSession.assignSpiralAnchor(actor, slotIndex);
        String botName = String.format(Locale.ROOT, "LFSwarm_%03d", slotIndex);
        UUID offlineUuid = UUID.nameUUIDFromBytes(
                ("OfflinePlayer:" + botName).getBytes(StandardCharsets.UTF_8)
        );

        Socket socket = new Socket();
        try {
            socket.setSoTimeout(config.connectTimeoutMs());
            socket.setTcpNoDelay(true);
            socket.connect(
                    new InetSocketAddress(config.host(), config.port()),
                    config.connectTimeoutMs()
            );
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            // 1. Handshake (nextState = 2 Login)
            ByteArrayOutputStream hs = new ByteArrayOutputStream();
            writeVarInt(hs, protocolVersion);
            writeUtfString(hs, config.host());
            new DataOutputStream(hs).writeShort(config.port());
            writeVarInt(hs, 2);
            sendPacket(out, 0x00, hs.toByteArray(), -1);

            // 2. Login Start (0x00: username + UUID for 1.20.2+ protocols)
            ByteArrayOutputStream loginStart = new ByteArrayOutputStream();
            writeUtfString(loginStart, botName);
            if (protocolVersion >= 764) {
                DataOutputStream ldos = new DataOutputStream(loginStart);
                ldos.writeLong(offlineUuid.getMostSignificantBits());
                ldos.writeLong(offlineUuid.getLeastSignificantBits());
            }
            sendPacket(out, 0x00, loginStart.toByteArray(), -1);

            int compressionThreshold = -1;
            // Read initial Login response packets (Set Compression 0x03 / Login Success 0x02 / Disconnect 0x00)
            for (int i = 0; i < 4; i++) {
                RawPacket pkt = readPacket(in, compressionThreshold);
                if (pkt.packetId() == 0x00) {
                    // Login Disconnect
                    socket.close();
                    return null;
                } else if (pkt.packetId() == 0x03) {
                    compressionThreshold = readVarInt(new ByteArrayInputStream(pkt.payload()));
                } else if (pkt.packetId() == 0x02) {
                    // Login Success
                    if (protocolVersion >= 764) {
                        sendPacket(out, 0x03, new byte[0], compressionThreshold); // Login Acknowledged
                    }
                    break;
                }
            }
            double handshakeMs = (System.nanoTime() - t0) / 1_000_000.0;
            rttSamples.add(handshakeMs);

            ActiveBotConnection botConn = new ActiveBotConnection(
                    socket,
                    in,
                    out,
                    compressionThreshold,
                    actor,
                    keepRunning,
                    droppedConnections,
                    totalSteps
            );
            botConn.startReaderThread(slotIndex);
            return botConn;
        } catch (IOException e) {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
            return null;
        }
    }

    private static final class ActiveBotConnection implements AutoCloseable {
        private final Socket socket;
        private final InputStream in;
        private final OutputStream out;
        private final int compressionThreshold;
        private final PersonaPolicyBotActor actor;
        private final AtomicBoolean keepRunning;
        private final AtomicInteger droppedConnections;
        private final AtomicInteger totalSteps;
        private final AtomicBoolean alive = new AtomicBoolean(true);
        private Thread readerThread;

        ActiveBotConnection(
                Socket socket,
                InputStream in,
                OutputStream out,
                int compressionThreshold,
                PersonaPolicyBotActor actor,
                AtomicBoolean keepRunning,
                AtomicInteger droppedConnections,
                AtomicInteger totalSteps
        ) {
            this.socket = socket;
            this.in = in;
            this.out = out;
            this.compressionThreshold = compressionThreshold;
            this.actor = actor;
            this.keepRunning = keepRunning;
            this.droppedConnections = droppedConnections;
            this.totalSteps = totalSteps;
        }

        void startReaderThread(int slotIndex) {
            this.readerThread = Thread.ofVirtual()
                    .name("leaffuzz-swarm-bot-" + slotIndex)
                    .start(() -> {
                        try {
                            while (keepRunning.get() && !socket.isClosed()) {
                                RawPacket pkt = readPacket(in, compressionThreshold);
                                if (pkt.packetId() == 0x04 && pkt.payload().length == 8) {
                                    // Echo 8-byte KeepAlive payload when encountered
                                    synchronized (out) {
                                        sendPacket(out, 0x04, pkt.payload(), compressionThreshold);
                                    }
                                }
                            }
                        } catch (IOException e) {
                            if (keepRunning.get()) {
                                alive.set(false);
                                droppedConnections.incrementAndGet();
                            }
                        }
                    });
        }

        void stepPersona() {
            if (!alive.get() || socket.isClosed()) {
                return;
            }
            actor.stepAutonomousPolicy();
            totalSteps.incrementAndGet();
        }

        boolean isAlive() {
            return alive.get() && !socket.isClosed();
        }

        @Override
        public void close() {
            alive.set(false);
            try {
                socket.close();
            } catch (IOException ignored) {
            }
            if (readerThread != null) {
                readerThread.interrupt();
            }
        }
    }

    private static double mean(List<Double> vals) {
        if (vals == null || vals.isEmpty()) {
            return 0.0;
        }
        double sum = 0.0;
        for (double v : vals) {
            sum += v;
        }
        return sum / vals.size();
    }

    private static double percentile(List<Double> vals, double q) {
        if (vals == null || vals.isEmpty()) {
            return 0.0;
        }
        List<Double> copy = new ArrayList<>(vals);
        Collections.sort(copy);
        if (copy.size() == 1) {
            return copy.get(0);
        }
        double pos = Math.max(0.0, Math.min(1.0, q)) * (copy.size() - 1);
        int lo = (int) Math.floor(pos);
        int hi = (int) Math.ceil(pos);
        if (lo == hi) {
            return copy.get(lo);
        }
        double frac = pos - lo;
        return copy.get(lo) * (1.0 - frac) + copy.get(hi) * frac;
    }
}
