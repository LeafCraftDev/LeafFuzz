package net.leaf.fuzz.common.cli;

import net.leaf.fuzz.common.LeafFuzzScorecardReport.Verdict;
import net.leaf.fuzz.common.cli.LeafFuzzTcpSwarmClient.SwarmConfig;
import net.leaf.fuzz.common.cli.LeafFuzzTcpSwarmClient.SwarmReadinessReport;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.Objects;

/**
 * Dual-purpose standalone CLI entrypoint packed inside {@code LeafFuzz-<version>.jar}
 * ({@code java -jar LeafFuzz.jar ...}) ({@code ADR-115}, {@code ADR-125}, {@code leaffuzz-ADR-001}).
 *
 * <p>Allows the exact same {@code LeafFuzz.jar} dropped into {@code plugins/} or {@code mods/}
 * to be executed directly from a terminal to launch a 100-player external TCP swarm or extract
 * the bundled {@code bench-swarm.js} Mineflayer harness:
 * <ul>
 *   <li>{@code java -jar LeafFuzz.jar swarm --host 127.0.0.1 --port 25565 --players auto}</li>
 *   <li>{@code java -jar LeafFuzz.jar swarm --host 127.0.0.1 --port 25565 --players 100 --duration-sec 60}</li>
 *   <li>{@code java -jar LeafFuzz.jar extract-mineflayer --out ./bench-swarm.js}</li>
 * </ul>
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy leaffuzz-ADR-001
 * @trace REQ-SLEUTH-FUZZ-004
 * @trace S-004
 */
public final class LeafFuzzStandaloneCli {

    /** Classpath resource path for the bundled Mineflayer swarm script inside {@code LeafFuzz.jar}. */
    public static final String BUNDLED_MINEFLAYER_RESOURCE =
            "/META-INF/leaffuzz/swarm/bench-swarm.js";

    private LeafFuzzStandaloneCli() {
    }

    public static void main(String[] args) {
        int code = executeCli(args, System.out, System.err);
        if (code != 0) {
            System.exit(code);
        }
    }

    /**
     * Executes the standalone CLI and returns a process exit code (`0` on PASS/WARN or help,
     * non-zero on FAIL or argument error).
     */
    public static int executeCli(String[] args, PrintStream out, PrintStream err) {
        Objects.requireNonNull(out, "out");
        Objects.requireNonNull(err, "err");
        if (args == null || args.length == 0) {
            printUsage(out);
            return 0;
        }
        String sub = args[0].trim().toLowerCase(Locale.ROOT);
        return switch (sub) {
            case "-h", "--help", "help" -> {
                printUsage(out);
                yield 0;
            }
            case "-v", "--version", "version" -> {
                out.println("LeafFuzz Standalone Swarm & Production Readiness CLI v0.1.0");
                yield 0;
            }
            case "extract-mineflayer" -> handleExtractMineflayer(args, out, err);
            case "swarm" -> handleSwarm(args, out, err);
            default -> {
                if (sub.startsWith("--")) {
                    yield handleSwarm(args, out, err);
                }
                err.println("Unknown subcommand: " + args[0]);
                printUsage(out);
                yield 2;
            }
        };
    }

    /**
     * Extracts the bundled {@code bench-swarm.js} Mineflayer script from {@code LeafFuzz.jar}
     * to {@code destination}.
     *
     * @param destination output file path
     * @return written path
     * @throws IOException if the resource is missing or cannot be written
     */
    public static Path extractBundledMineflayerScript(Path destination) throws IOException {
        Objects.requireNonNull(destination, "destination");
        try (InputStream in = LeafFuzzStandaloneCli.class.getResourceAsStream(BUNDLED_MINEFLAYER_RESOURCE)) {
            if (in == null) {
                throw new IOException("Bundled resource not found: " + BUNDLED_MINEFLAYER_RESOURCE);
            }
            Path parent = destination.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.copy(in, destination, StandardCopyOption.REPLACE_EXISTING);
            return destination;
        }
    }

    private static int handleExtractMineflayer(String[] args, PrintStream out, PrintStream err) {
        Path outPath = Path.of("bench-swarm.js");
        for (int i = 1; i < args.length; i++) {
            if (("--out".equals(args[i]) || "-o".equals(args[i])) && i + 1 < args.length) {
                outPath = Path.of(args[++i]);
            } else if (args[i].startsWith("--out=")) {
                outPath = Path.of(args[i].substring("--out=".length()));
            }
        }
        try {
            Path written = extractBundledMineflayerScript(outPath);
            out.println("Extracted bundled Mineflayer swarm harness to: " + written.toAbsolutePath());
            return 0;
        } catch (IOException e) {
            err.println("Failed to extract bench-swarm.js: " + e.getMessage());
            return 1;
        }
    }

    private static int handleSwarm(String[] args, PrintStream out, PrintStream err) {
        String host = "127.0.0.1";
        int port = 25565;
        int players = 100;
        boolean rampUntilUnstable = true;
        int durationSec = 15;
        int timeoutMs = 3_000;
        int protocol = -1;
        double maxRttP95Ms = 55.0;
        Path reportOut = null;

        int startIdx = (args.length > 0 && "swarm".equalsIgnoreCase(args[0])) ? 1 : 0;
        for (int i = startIdx; i < args.length; i++) {
            String arg = args[i];
            if (("--host".equals(arg) || "-H".equals(arg)) && i + 1 < args.length) {
                host = args[++i];
            } else if (arg.startsWith("--host=")) {
                host = arg.substring("--host=".length());
            } else if (("--port".equals(arg) || "-p".equals(arg)) && i + 1 < args.length) {
                port = parseIntOrDefault(args[++i], 25565);
            } else if (arg.startsWith("--port=")) {
                port = parseIntOrDefault(arg.substring("--port=".length()), 25565);
            } else if (("--players".equals(arg) || "-n".equals(arg)) && i + 1 < args.length) {
                String val = args[++i].trim().toLowerCase(Locale.ROOT);
                if ("auto".equals(val) || "ramp".equals(val)) {
                    players = 100;
                    rampUntilUnstable = true;
                } else {
                    players = parseIntOrDefault(val, 100);
                }
            } else if (arg.startsWith("--players=")) {
                String val = arg.substring("--players=".length()).trim().toLowerCase(Locale.ROOT);
                if ("auto".equals(val) || "ramp".equals(val)) {
                    players = 100;
                    rampUntilUnstable = true;
                } else {
                    players = parseIntOrDefault(val, 100);
                }
            } else if ("--no-ramp".equals(arg)) {
                rampUntilUnstable = false;
            } else if ("--ramp".equals(arg) || "--ramp-until-unstable".equals(arg)) {
                rampUntilUnstable = true;
            } else if ("--duration-sec".equals(arg) && i + 1 < args.length) {
                durationSec = parseIntOrDefault(args[++i], 15);
            } else if (arg.startsWith("--duration-sec=")) {
                durationSec = parseIntOrDefault(arg.substring("--duration-sec=".length()), 15);
            } else if ("--timeout-ms".equals(arg) && i + 1 < args.length) {
                timeoutMs = parseIntOrDefault(args[++i], 3_000);
            } else if ("--protocol".equals(arg) && i + 1 < args.length) {
                String pv = args[++i];
                protocol = "auto".equalsIgnoreCase(pv) ? -1 : parseIntOrDefault(pv, -1);
            } else if ("--max-rtt-ms".equals(arg) && i + 1 < args.length) {
                maxRttP95Ms = parseDoubleOrDefault(args[++i], 55.0);
            } else if ("--report".equals(arg) && i + 1 < args.length) {
                reportOut = Path.of(args[++i]);
            } else if (arg.startsWith("--report=")) {
                reportOut = Path.of(arg.substring("--report=".length()));
            }
        }

        SwarmConfig cfg = new SwarmConfig(
                host,
                port,
                players,
                rampUntilUnstable,
                durationSec,
                timeoutMs,
                protocol,
                maxRttP95Ms
        );
        SwarmReadinessReport report = LeafFuzzTcpSwarmClient.runSwarm(cfg);
        for (String line : report.formatConsoleLines()) {
            out.println(line);
        }
        if (reportOut != null) {
            try {
                Path parent = reportOut.toAbsolutePath().getParent();
                if (parent != null) {
                    Files.createDirectories(parent);
                }
                Files.writeString(reportOut, report.toMarkdownReport(), StandardCharsets.UTF_8);
                out.println("Saved Markdown swarm report: " + reportOut.toAbsolutePath());
            } catch (IOException e) {
                err.println("Failed to write Markdown report: " + e.getMessage());
            }
        }
        return report.verdict() == Verdict.FAIL ? 1 : 0;
    }

    private static void printUsage(PrintStream out) {
        out.println("LeafFuzz Standalone Swarm & Server Production Readiness CLI");
        out.println("Usage:");
        out.println("  java -jar LeafFuzz.jar swarm [--host 127.0.0.1] [--port 25565] [--players auto|100] [--duration-sec 30] [--report report.md]");
        out.println("  java -jar LeafFuzz.jar extract-mineflayer [--out ./bench-swarm.js]");
        out.println("  java -jar LeafFuzz.jar --version");
    }

    private static int parseIntOrDefault(String raw, int fallback) {
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    private static double parseDoubleOrDefault(String raw, double fallback) {
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            return Double.parseDouble(raw.trim());
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }
}
