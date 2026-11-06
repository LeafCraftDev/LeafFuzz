package net.leaf.fuzz.common;

import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.CausalFinding;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.ConfidenceTier;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.LeastPrivilegeFinding;
import net.leaf.sleuth.common.fuzz.DualAudienceMitigationReport;
import net.leaf.sleuth.common.fuzz.LogAndStallSignatureOracle.FaultSignature;
import net.leaf.sleuth.common.resource.ClassRetentionFinding;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Four-stage automated QC scorecard and Markdown report generator for {@code /fuzz check <target>}
 * ({@code ADR-125}, {@code leaffuzz-ADR-001}).
 *
 * <p>Summarizes:
 * <ol>
 *   <li><b>Stage 1 (Command &amp; Permission Surface):</b> Brigadier/Bukkit tree discovery and
 *       {@link LeastPrivilegeFinding} checks across {@code default} vs {@code op} tiers.</li>
 *   <li><b>Stage 2 (Boundary &amp; Lifecycle Fuzzing):</b> UCB1 exploration across numeric boundary
 *       ladders and player join/quit lifecycle follow-ups with {@code ddmin} reproducer shrinking.</li>
 *   <li><b>Stage 3 (Main-Thread Stall &amp; Exception Oracle):</b> Uncaught exception ({@code exc:})
 *       and slow-tick stall ({@code stall:}) attribution via {@code JarClassOwnershipIndex}.</li>
 *   <li><b>Stage 4 (Post-GC Memory &amp; Session Leak Screen):</b> Bonferroni-corrected OLS class
 *       retention slopes across player departures and command executions.</li>
 * </ol>
 *
 * @param targetName             tested plugin/mod name or {@code "all"}
 * @param platformName           server platform identifier ({@code "paper"}, {@code "folia"}, {@code "fabric"}, {@code "neoforge"})
 * @param serverVersion          server version string
 * @param indexedJars            number of plugin/mod JARs indexed
 * @param auditedCommands        number of distinct command nodes audited for the target
 * @param defaultTierCommands    number of command nodes executable by {@code default} players
 * @param leastPrivilegeFindings unguarded state-mutating commands exposed on {@code default}
 * @param episodesExecuted       number of synthetic fuzz episodes executed
 * @param distinctArmsProbed     number of distinct {@code (nodeId, followUpShape)} arms exercised
 * @param shrunkReproducers      {@code ddmin}-minimized reproducer reports
 * @param faultSignatures        attributed {@code exc:} and {@code stall:} signatures
 * @param checkpointsCaptured    number of post-GC class histogram checkpoints evaluated
 * @param retentionFindings      statistically significant post-GC class retention slopes
 * @param elapsedMillis          wall-clock duration of the QC check in milliseconds
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy leaffuzz-ADR-001
 * @trace REQ-SLEUTH-FUZZ-004
 */
public record LeafFuzzScorecardReport(
        String targetName,
        String platformName,
        String serverVersion,
        int indexedJars,
        int auditedCommands,
        int defaultTierCommands,
        List<LeastPrivilegeFinding> leastPrivilegeFindings,
        int episodesExecuted,
        int distinctArmsProbed,
        List<DualAudienceMitigationReport> shrunkReproducers,
        List<FaultSignature> faultSignatures,
        int checkpointsCaptured,
        List<ClassRetentionFinding> retentionFindings,
        long elapsedMillis,
        ExecutionTelemetry telemetry,
        List<CausalFinding> causalFindings
) {
    /**
     * Verdict level for an individual QC stage or overall scorecard.
     */
    public enum Verdict {
        PASS,
        WARN,
        FAIL
    }

    /**
     * Concrete runtime activity, MSPT, concurrent player survival, and post-GC heap telemetry
     * observed during a QC pass.
     */
    public record ExecutionTelemetry(
            int botsSpawned,
            int commandsDispatched,
            int menusOpened,
            int menuSlotsClicked,
            int teleportsObserved,
            double maxTeleportDistanceBlocks,
            int infoResponsesObserved,
            int usageErrorsObserved,
            double idleMsptMean,
            double idleMsptP95,
            double fuzzMsptMean,
            double fuzzMsptP95,
            double fuzzMsptMax,
            int tickSamplesCollected,
            double baselineHeapMb,
            double finalHeapMb,
            int totalClassesScanned,
            long totalInstancesScanned,
            List<String> clickedMenuItems,
            List<String> commandSummaries,
            List<String> topTargetClassDeltas,
            int targetConcurrentPlayers,
            int peakConcurrentPlayers,
            int loadedChunksAtPeak,
            int entitiesAtPeak,
            int maxStablePlayers,
            String instabilityTrigger
    ) {
        public ExecutionTelemetry(
                int botsSpawned,
                int commandsDispatched,
                int menusOpened,
                int menuSlotsClicked,
                int teleportsObserved,
                double maxTeleportDistanceBlocks,
                int infoResponsesObserved,
                int usageErrorsObserved,
                double idleMsptMean,
                double idleMsptP95,
                double fuzzMsptMean,
                double fuzzMsptP95,
                double fuzzMsptMax,
                int tickSamplesCollected,
                double baselineHeapMb,
                double finalHeapMb,
                int totalClassesScanned,
                long totalInstancesScanned,
                List<String> clickedMenuItems,
                List<String> commandSummaries,
                List<String> topTargetClassDeltas
        ) {
            this(
                    botsSpawned,
                    commandsDispatched,
                    menusOpened,
                    menuSlotsClicked,
                    teleportsObserved,
                    maxTeleportDistanceBlocks,
                    infoResponsesObserved,
                    usageErrorsObserved,
                    idleMsptMean,
                    idleMsptP95,
                    fuzzMsptMean,
                    fuzzMsptP95,
                    fuzzMsptMax,
                    tickSamplesCollected,
                    baselineHeapMb,
                    finalHeapMb,
                    totalClassesScanned,
                    totalInstancesScanned,
                    clickedMenuItems,
                    commandSummaries,
                    topTargetClassDeltas,
                    1,
                    botsSpawned > 0 ? 1 : 0,
                    0,
                    0,
                    botsSpawned > 0 ? 1 : 0,
                    ""
            );
        }

        public ExecutionTelemetry(
                int botsSpawned,
                int commandsDispatched,
                int menusOpened,
                int menuSlotsClicked,
                int teleportsObserved,
                double maxTeleportDistanceBlocks,
                int infoResponsesObserved,
                int usageErrorsObserved,
                double idleMsptMean,
                double idleMsptP95,
                double fuzzMsptMean,
                double fuzzMsptP95,
                double fuzzMsptMax,
                int tickSamplesCollected,
                double baselineHeapMb,
                double finalHeapMb,
                int totalClassesScanned,
                long totalInstancesScanned,
                List<String> clickedMenuItems,
                List<String> commandSummaries,
                List<String> topTargetClassDeltas,
                int targetConcurrentPlayers,
                int peakConcurrentPlayers,
                int loadedChunksAtPeak,
                int entitiesAtPeak
        ) {
            this(
                    botsSpawned,
                    commandsDispatched,
                    menusOpened,
                    menuSlotsClicked,
                    teleportsObserved,
                    maxTeleportDistanceBlocks,
                    infoResponsesObserved,
                    usageErrorsObserved,
                    idleMsptMean,
                    idleMsptP95,
                    fuzzMsptMean,
                    fuzzMsptP95,
                    fuzzMsptMax,
                    tickSamplesCollected,
                    baselineHeapMb,
                    finalHeapMb,
                    totalClassesScanned,
                    totalInstancesScanned,
                    clickedMenuItems,
                    commandSummaries,
                    topTargetClassDeltas,
                    targetConcurrentPlayers,
                    peakConcurrentPlayers,
                    loadedChunksAtPeak,
                    entitiesAtPeak,
                    fuzzMsptP95 <= 55.0 ? peakConcurrentPlayers : 0,
                    ""
            );
        }

        public ExecutionTelemetry {
            clickedMenuItems = clickedMenuItems == null ? List.of() : List.copyOf(clickedMenuItems);
            commandSummaries = commandSummaries == null ? List.of() : List.copyOf(commandSummaries);
            topTargetClassDeltas = topTargetClassDeltas == null ? List.of() : List.copyOf(topTargetClassDeltas);
            targetConcurrentPlayers = Math.max(1, targetConcurrentPlayers);
            peakConcurrentPlayers = Math.max(0, peakConcurrentPlayers);
            loadedChunksAtPeak = Math.max(0, loadedChunksAtPeak);
            entitiesAtPeak = Math.max(0, entitiesAtPeak);
            maxStablePlayers = Math.max(0, maxStablePlayers);
            instabilityTrigger = instabilityTrigger == null ? "" : instabilityTrigger.trim();
        }

        public static ExecutionTelemetry empty() {
            return new ExecutionTelemetry(
                    0, 0, 0, 0, 0, 0.0, 0, 0,
                    0.0, 0.0, 0.0, 0.0, 0.0, 0,
                    0.0, 0.0, 0, 0L,
                    List.of(), List.of(), List.of(),
                    1, 0, 0, 0, 0, ""
            );
        }

        public boolean hasLiveObservations() {
            return botsSpawned > 0
                    || commandsDispatched > 0
                    || tickSamplesCollected > 0
                    || totalClassesScanned > 0
                    || peakConcurrentPlayers > 0;
        }
    }

    public LeafFuzzScorecardReport(
            String targetName,
            String platformName,
            String serverVersion,
            int indexedJars,
            int auditedCommands,
            int defaultTierCommands,
            List<LeastPrivilegeFinding> leastPrivilegeFindings,
            int episodesExecuted,
            int distinctArmsProbed,
            List<DualAudienceMitigationReport> shrunkReproducers,
            List<FaultSignature> faultSignatures,
            int checkpointsCaptured,
            List<ClassRetentionFinding> retentionFindings,
            long elapsedMillis
    ) {
        this(
                targetName,
                platformName,
                serverVersion,
                indexedJars,
                auditedCommands,
                defaultTierCommands,
                leastPrivilegeFindings,
                episodesExecuted,
                distinctArmsProbed,
                shrunkReproducers,
                faultSignatures,
                checkpointsCaptured,
                retentionFindings,
                elapsedMillis,
                ExecutionTelemetry.empty(),
                List.of()
        );
    }

    public LeafFuzzScorecardReport(
            String targetName,
            String platformName,
            String serverVersion,
            int indexedJars,
            int auditedCommands,
            int defaultTierCommands,
            List<LeastPrivilegeFinding> leastPrivilegeFindings,
            int episodesExecuted,
            int distinctArmsProbed,
            List<DualAudienceMitigationReport> shrunkReproducers,
            List<FaultSignature> faultSignatures,
            int checkpointsCaptured,
            List<ClassRetentionFinding> retentionFindings,
            long elapsedMillis,
            ExecutionTelemetry telemetry
    ) {
        this(
                targetName,
                platformName,
                serverVersion,
                indexedJars,
                auditedCommands,
                defaultTierCommands,
                leastPrivilegeFindings,
                episodesExecuted,
                distinctArmsProbed,
                shrunkReproducers,
                faultSignatures,
                checkpointsCaptured,
                retentionFindings,
                elapsedMillis,
                telemetry,
                List.of()
        );
    }

    public LeafFuzzScorecardReport {
        targetName = (targetName == null || targetName.isBlank()) ? "all" : targetName.trim();
        platformName = (platformName == null || platformName.isBlank()) ? "unknown" : platformName.trim();
        serverVersion = (serverVersion == null || serverVersion.isBlank()) ? "unknown" : serverVersion.trim();
        leastPrivilegeFindings = leastPrivilegeFindings == null ? List.of() : List.copyOf(leastPrivilegeFindings);
        shrunkReproducers = shrunkReproducers == null ? List.of() : List.copyOf(shrunkReproducers);
        faultSignatures = faultSignatures == null ? List.of() : List.copyOf(faultSignatures);
        retentionFindings = retentionFindings == null ? List.of() : List.copyOf(retentionFindings);
        elapsedMillis = Math.max(0L, elapsedMillis);
        telemetry = telemetry == null ? ExecutionTelemetry.empty() : telemetry;
        causalFindings = causalFindings == null ? List.of() : List.copyOf(causalFindings);
    }

    public Verdict stage1CommandSurfaceVerdict() {
        return leastPrivilegeFindings.isEmpty() ? Verdict.PASS : Verdict.WARN;
    }

    public Verdict stage2BoundaryFuzzVerdict() {
        if (!shrunkReproducers.isEmpty()) {
            return Verdict.FAIL;
        }
        if (episodesExecuted > 0 && telemetry.hasLiveObservations()) {
            if (!telemetry.instabilityTrigger().isEmpty()) {
                if (telemetry.instabilityTrigger().startsWith("fault:")) {
                    return Verdict.FAIL;
                }
                return Verdict.WARN;
            }
            if (telemetry.targetConcurrentPlayers() > 1
                    && telemetry.peakConcurrentPlayers() < telemetry.targetConcurrentPlayers()) {
                return Verdict.FAIL;
            }
            if (telemetry.commandsDispatched() == 0) {
                return Verdict.FAIL;
            }
            if (telemetry.menusOpened() > 0 && telemetry.menuSlotsClicked() == 0) {
                return Verdict.FAIL;
            }
            if (telemetry.teleportsObserved() == 0
                    && telemetry.menusOpened() == 0
                    && telemetry.infoResponsesObserved() == 0) {
                return Verdict.FAIL;
            }
            if (telemetry.usageErrorsObserved() > 0
                    && telemetry.usageErrorsObserved() >= telemetry.commandsDispatched()) {
                return Verdict.WARN;
            }
        }
        return Verdict.PASS;
    }

    public Verdict stage3StallAndExceptionVerdict() {
        if (!faultSignatures.isEmpty()) {
            return Verdict.FAIL;
        }
        if (telemetry.fuzzMsptP95() > 55.0) {
            return Verdict.WARN;
        }
        return Verdict.PASS;
    }

    public Verdict stage4MemoryRetentionVerdict() {
        return retentionFindings.isEmpty() ? Verdict.PASS : Verdict.FAIL;
    }

    /**
     * Evaluates Stage 5 (First-Order &amp; Second-Order Bytecode &amp; Causal Audit).
     *
     * <p>Deterministic {@link ConfidenceTier#CONFIRMED} or {@link ConfidenceTier#HIGH} wiring/causal
     * findings yield {@link Verdict#WARN}; {@link ConfidenceTier#ADVISORY} LLM hypotheses never
     * downgrade the stage or overall scorecard verdict.
     */
    public Verdict stage5CausalAuditVerdict() {
        for (CausalFinding f : causalFindings) {
            if (f.confidenceTier() == ConfidenceTier.CONFIRMED
                    || f.confidenceTier() == ConfidenceTier.HIGH) {
                return Verdict.WARN;
            }
        }
        return Verdict.PASS;
    }

    public Verdict overallVerdict() {
        if (stage2BoundaryFuzzVerdict() == Verdict.FAIL
                || stage3StallAndExceptionVerdict() == Verdict.FAIL
                || stage4MemoryRetentionVerdict() == Verdict.FAIL) {
            return Verdict.FAIL;
        }
        if (stage1CommandSurfaceVerdict() == Verdict.WARN
                || stage2BoundaryFuzzVerdict() == Verdict.WARN
                || stage3StallAndExceptionVerdict() == Verdict.WARN
                || stage5CausalAuditVerdict() == Verdict.WARN) {
            return Verdict.WARN;
        }
        return Verdict.PASS;
    }

    /**
     * Formats concise in-game / console scorecard lines with concrete observed telemetry.
     *
     * @param prefix chat prefix
     * @param savedReportPath optional path where the Markdown report was written
     * @return immutable list of formatted lines
     */
    public List<String> formatChatLines(String prefix, Path savedReportPath) {
        String p = prefix == null ? "" : prefix;
        List<String> lines = new ArrayList<>();
        String overallColor = switch (overallVerdict()) {
            case PASS -> "&aPASS";
            case WARN -> "&eWARN";
            case FAIL -> "&cFAIL";
        };
        lines.add(p + "&f=== &2LeafFuzz QC Scorecard &7[" + targetName + "] &f-> " + overallColor
                + " &7(" + elapsedMillis + " ms on " + platformName + " " + serverVersion + ") ===");
        lines.add(p + formatStageBadge("1. Command & Permission Audit", stage1CommandSurfaceVerdict())
                + " &7(" + auditedCommands + " nodes, " + defaultTierCommands + " default-visible, "
                + leastPrivilegeFindings.size() + " exposure warnings)");
        lines.add(p + formatStageBadge("2. Boundary & Lifecycle Fuzz", stage2BoundaryFuzzVerdict())
                + " &7(" + episodesExecuted + " eps, &f" + telemetry.botsSpawned() + "&7 bots"
                + (telemetry.targetConcurrentPlayers() > 1 || telemetry.peakConcurrentPlayers() > 1
                ? " [&b" + telemetry.peakConcurrentPlayers() + "/" + telemetry.targetConcurrentPlayers()
                        + " concurrent&7, &astable=" + telemetry.maxStablePlayers()
                        + "&7, &f" + telemetry.loadedChunksAtPeak() + "&7 chunks, &f"
                        + telemetry.entitiesAtPeak() + "&7 entities"
                        + (!telemetry.instabilityTrigger().isEmpty()
                        ? ", &cbreak=" + telemetry.instabilityTrigger() + "&7"
                        : "")
                        + "]"
                : "")
                + ", &f"
                + telemetry.menusOpened() + "&7 menus/&f" + telemetry.menuSlotsClicked() + "&7 shiny clicks, &a"
                + telemetry.teleportsObserved() + "&7 teleports"
                + (telemetry.maxTeleportDistanceBlocks() > 0.0
                ? String.format(Locale.ROOT, " [max %.0fb]", telemetry.maxTeleportDistanceBlocks())
                : "")
                + ", " + shrunkReproducers.size() + " repros)");
        lines.add(p + formatStageBadge("3. Tick Stall & Exception Guard", stage3StallAndExceptionVerdict())
                + String.format(
                Locale.ROOT,
                " &7(idle &f%.1f&7 mspt -> fuzz p95 &f%.1f&7 / max &f%.1f&7 mspt, %d samples, %d faults)",
                telemetry.idleMsptMean(),
                telemetry.fuzzMsptP95(),
                telemetry.fuzzMsptMax(),
                telemetry.tickSamplesCollected(),
                faultSignatures.size()
        ));
        lines.add(p + formatStageBadge("4. Post-GC Leak & Retention Screen", stage4MemoryRetentionVerdict())
                + String.format(
                Locale.ROOT,
                " &7(%d GC CPs, heap &f%.1f->%.1f MB&7, &f%d&7 classes scanned, %d leaks)",
                checkpointsCaptured,
                telemetry.baselineHeapMb(),
                telemetry.finalHeapMb(),
                telemetry.totalClassesScanned(),
                retentionFindings.size()
        ));
        long confirmedCausal = causalFindings.stream()
                .filter(f -> f.confidenceTier() == ConfidenceTier.CONFIRMED)
                .count();
        long highCausal = causalFindings.stream()
                .filter(f -> f.confidenceTier() == ConfidenceTier.HIGH)
                .count();
        lines.add(p + formatStageBadge("5. Bytecode & Causal Audit", stage5CausalAuditVerdict())
                + String.format(
                Locale.ROOT,
                " &7(%d causal findings: &f%d&7 confirmed 100%%, &f%d&7 high confidence)",
                causalFindings.size(),
                confirmedCausal,
                highCausal
        ));

        List<String> topClicked = headItems(telemetry.clickedMenuItems(), 4);
        if (!topClicked.isEmpty()) {
            lines.add(p + "  &b[Menu Clicks] &f" + String.join("&7, &f", topClicked));
        }
        List<String> topCmds = headItems(telemetry.commandSummaries(), 3);
        if (!topCmds.isEmpty()) {
            lines.add(p + "  &a[Activity] &f" + String.join("&7 | &f", topCmds));
        }
        List<String> topClasses = headItems(telemetry.topTargetClassDeltas(), 2);
        if (!topClasses.isEmpty() && retentionFindings.isEmpty()) {
            lines.add(p + "  &7[Top Target Classes] &f" + String.join("&7, &f", topClasses));
        }

        for (int i = 0; i < Math.min(2, leastPrivilegeFindings.size()); i++) {
            LeastPrivilegeFinding f = leastPrivilegeFindings.get(i);
            lines.add(p + "  &e[Perm] &f/" + f.nodeId() + " &7(" + f.suspectPluginOrJar() + ") -> " + f.remediationCommand());
        }
        for (int i = 0; i < Math.min(2, shrunkReproducers.size()); i++) {
            DualAudienceMitigationReport r = shrunkReproducers.get(i);
            lines.add(p + "  &c[Repro] &f" + r.signatureId() + " &7(" + r.suspectJar() + ") -> "
                    + String.join(" ; ", r.minimalCommandSequence())
                    + r.bisectedNumericThreshold().map(t -> " [" + t + "]").orElse(""));
        }
        for (int i = 0; i < Math.min(2, faultSignatures.size()); i++) {
            FaultSignature sig = faultSignatures.get(i);
            lines.add(p + "  &c[Fault] &f" + sig.signatureId() + " &7(" + sig.suspectJar()
                    + ", count=" + sig.occurrences() + ")");
        }
        for (int i = 0; i < Math.min(2, retentionFindings.size()); i++) {
            ClassRetentionFinding rf = retentionFindings.get(i);
            lines.add(p + "  &c[Leak] &f" + rf.formatSummaryLine());
        }
        for (int i = 0; i < Math.min(2, causalFindings.size()); i++) {
            CausalFinding cf = causalFindings.get(i);
            lines.add(p + "  &e[Causal] &f[" + cf.confidenceTier().name() + " " + cf.confidencePercent()
                    + "%] (Order " + cf.order() + ") &7Declared: &f" + cf.declaredSurface()
                    + " &7-> Finding: &c" + cf.causalDefect());
        }
        if (savedReportPath != null) {
            lines.add(p + "&7Saved Markdown QC report: &f" + savedReportPath);
            String safeTarget = sanitizedTargetSlug();
            Path parentDir = savedReportPath.getParent();
            if (parentDir != null) {
                lines.add(p + "&7Saved Publishable QC Data (BBB/Modrinth): &a"
                        + parentDir.resolve(safeTarget + "-qc-data.yml")
                        + " &7(&f.json&7)");
            }
        }
        return List.copyOf(lines);
    }

    /**
     * Returns a single-line status summary leading with {@link #overallVerdict()} for moderation
     * and release readiness review.
     *
     * @return concise status summary string
     */
    public String verdictSummary() {
        int passedStages = 0;
        if (stage1CommandSurfaceVerdict() == Verdict.PASS) {
            passedStages++;
        }
        if (stage2BoundaryFuzzVerdict() == Verdict.PASS) {
            passedStages++;
        }
        if (stage3StallAndExceptionVerdict() == Verdict.PASS) {
            passedStages++;
        }
        if (stage4MemoryRetentionVerdict() == Verdict.PASS) {
            passedStages++;
        }
        if (stage5CausalAuditVerdict() == Verdict.PASS) {
            passedStages++;
        }
        long confirmedOrHighCausal = causalFindings.stream()
                .filter(f -> f.confidenceTier() == ConfidenceTier.CONFIRMED
                        || f.confidenceTier() == ConfidenceTier.HIGH)
                .count();
        return String.format(
                Locale.ROOT,
                "%s (%d/5 stages passed; %d reproducers, %d faults, %d memory leaks, %d confirmed/high causal defects)",
                overallVerdict().name(),
                passedStages,
                shrunkReproducers.size(),
                faultSignatures.size(),
                retentionFindings.size(),
                confirmedOrHighCausal
        );
    }

    private String sanitizedTargetSlug() {
        String safeTarget = targetName.replaceAll("[^a-zA-Z0-9._-]", "_").toLowerCase(Locale.ROOT);
        return safeTarget.isBlank() ? "all" : safeTarget;
    }

    private static List<String> headItems(List<String> items, int limit) {
        if (items == null || items.isEmpty() || limit <= 0) {
            return List.of();
        }
        int end = Math.min(limit, items.size());
        List<String> out = new ArrayList<>(end);
        for (int i = 0; i < end; i++) {
            out.add(items.get(i));
        }
        return out;
    }

    private static String formatStageBadge(String label, Verdict v) {
        String badge = switch (v) {
            case PASS -> "&a[PASS]";
            case WARN -> "&e[WARN]";
            case FAIL -> "&c[FAIL]";
        };
        return badge + " &f" + label;
    }

    /**
     * Generates a self-contained Markdown report suitable for pasting into GitHub issues, pull
     * requests, BuiltByBit, or Modrinth moderation tickets, leading on line 1 with the overall
     * {@code STATUS: <PASS|WARN|FAIL>} header.
     *
     * @return Markdown report string
     */
    public String toMarkdownReport() {
        String nowIso = Instant.now().toString();
        StringBuilder sb = new StringBuilder();
        sb.append("STATUS: ").append(overallVerdict().name())
                .append(" | Target: `").append(targetName)
                .append("` | Platform: `").append(platformName).append("` (`").append(serverVersion)
                .append("`) | Stages: `1:").append(stage1CommandSurfaceVerdict())
                .append(" 2:").append(stage2BoundaryFuzzVerdict())
                .append(" 3:").append(stage3StallAndExceptionVerdict())
                .append(" 4:").append(stage4MemoryRetentionVerdict())
                .append(" 5:").append(stage5CausalAuditVerdict()).append("`\n");
        sb.append("Moderation Evidence Summary: `").append(verdictSummary()).append("`\n\n");
        sb.append("### LeafFuzz Automated QC Scorecard: `").append(targetName).append("` — **")
                .append(overallVerdict().name()).append("**\n\n");
        sb.append("- **Overall Status:** `").append(overallVerdict().name()).append("` (")
                .append(verdictSummary()).append(")\n");
        sb.append("- **Platform / Runtime:** `").append(platformName).append("` (`").append(serverVersion).append("`)\n");
        sb.append("- **Indexed Plugin/Mod Archives:** `").append(indexedJars).append("`\n");
        sb.append("- **Concurrent Player Survival Roster:** `").append(telemetry.peakConcurrentPlayers())
                .append('/').append(telemetry.targetConcurrentPlayers())
                .append(" players` (max stable: `").append(telemetry.maxStablePlayers())
                .append(" players`, `").append(telemetry.loadedChunksAtPeak())
                .append("` loaded chunks, `").append(telemetry.entitiesAtPeak())
                .append("` tracked entities at peak");
        if (!telemetry.instabilityTrigger().isEmpty()) {
            sb.append(", breaking point: `").append(telemetry.instabilityTrigger()).append('`');
        }
        sb.append(")\n");
        sb.append("- **Elapsed Wall Time:** `").append(elapsedMillis).append(" ms`\n");
        sb.append("- **Generated At:** `").append(nowIso).append("`\n\n");

        sb.append("| QC Stage | Verdict | Key Metrics |\n");
        sb.append("|---|---|---|\n");
        sb.append("| **1. Command & Least-Privilege Audit** | `").append(stage1CommandSurfaceVerdict())
                .append("` | `").append(auditedCommands).append("` commands audited (`")
                .append(defaultTierCommands).append("` default-accessible, `")
                .append(leastPrivilegeFindings.size()).append("` unguarded state-mutating nodes) |\n");
        sb.append("| **2. Boundary & Lifecycle Fuzz Pass** | `").append(stage2BoundaryFuzzVerdict())
                .append("` | `").append(episodesExecuted).append("` episodes across `")
                .append(distinctArmsProbed).append("` arms (`")
                .append(telemetry.botsSpawned()).append("` bots, `")
                .append(telemetry.menusOpened()).append("` menus/`")
                .append(telemetry.menuSlotsClicked()).append("` shiny clicks, `")
                .append(telemetry.teleportsObserved()).append("` teleports, `")
                .append(shrunkReproducers.size()).append("` repros) |\n");
        sb.append("| **3. Main-Thread Stall & Exception Guard** | `").append(stage3StallAndExceptionVerdict())
                .append(String.format(
                        Locale.ROOT,
                        "` | Idle `%.2f mspt` -> Fuzz P95 `%.2f mspt` / Max `%.2f mspt` (`%d` tick samples, `%d` `exc:`/`stall:` signatures) |\n",
                        telemetry.idleMsptMean(),
                        telemetry.fuzzMsptP95(),
                        telemetry.fuzzMsptMax(),
                        telemetry.tickSamplesCollected(),
                        faultSignatures.size()
                ));
        sb.append("| **4. Post-GC Class Retention Screen** | `").append(stage4MemoryRetentionVerdict())
                .append(String.format(
                        Locale.ROOT,
                        "` | `%d` Full-GC checkpoints, OldGen `%.1f -> %.1f MB` (`%d` classes / `%d` instances scanned, `%d` leaking) |\n",
                        checkpointsCaptured,
                        telemetry.baselineHeapMb(),
                        telemetry.finalHeapMb(),
                        telemetry.totalClassesScanned(),
                        telemetry.totalInstancesScanned(),
                        retentionFindings.size()
                ));
        long confirmedCausal = causalFindings.stream()
                .filter(f -> f.confidenceTier() == ConfidenceTier.CONFIRMED)
                .count();
        long highCausal = causalFindings.stream()
                .filter(f -> f.confidenceTier() == ConfidenceTier.HIGH)
                .count();
        sb.append("| **5. Bytecode & Causal Audit** | `").append(stage5CausalAuditVerdict())
                .append(String.format(
                        Locale.ROOT,
                        "` | `%d` causal findings (`%d` Order-1/2 `CONFIRMED 100%%`, `%d` `HIGH`) |\n\n",
                        causalFindings.size(),
                        confirmedCausal,
                        highCausal
                ));

        if (!telemetry.clickedMenuItems().isEmpty()) {
            sb.append("#### Salient Menu Items Discovered & Clicked\n\n");
            for (String item : telemetry.clickedMenuItems()) {
                sb.append("- `").append(item).append("`\n");
            }
            sb.append('\n');
        }

        if (!telemetry.commandSummaries().isEmpty()) {
            sb.append("#### Per-Command Execution & Effect Telemetry\n\n");
            for (String cmdSum : telemetry.commandSummaries()) {
                sb.append("- `").append(cmdSum).append("`\n");
            }
            sb.append('\n');
        }

        if (!telemetry.topTargetClassDeltas().isEmpty()) {
            sb.append("#### Top Target Plugin Post-GC Class Deltas (`qc-baseline -> qc-batch-3`)\n\n");
            for (String clsDelta : telemetry.topTargetClassDeltas()) {
                sb.append("- `").append(clsDelta).append("`\n");
            }
            sb.append('\n');
        }

        if (!leastPrivilegeFindings.isEmpty()) {
            sb.append("#### Stage 1 Findings: Command Permission Exposure\n\n");
            for (LeastPrivilegeFinding f : leastPrivilegeFindings) {
                sb.append("- **`/").append(f.nodeId()).append("`** (`").append(f.suspectPluginOrJar())
                        .append("`, kind: `").append(f.findingKind()).append("`) — Fix: `")
                        .append(f.remediationCommand()).append("`\n");
            }
            sb.append('\n');
        }

        if (!shrunkReproducers.isEmpty()) {
            sb.append("#### Stage 2 Findings: Minimized Fault & Leak Reproducers (`ddmin`)\n\n");
            for (DualAudienceMitigationReport r : shrunkReproducers) {
                sb.append("- **").append(r.authorReproducerSummary()).append("**\n");
                sb.append("  - **LuckPerms Fix:** `").append(r.permissionRevokeCommand()).append("`\n");
                sb.append("  - **`commands.yml` Override:**\n```yaml\n")
                        .append(r.commandsYmlOverrideSnippet()).append("\n```\n");
            }
            sb.append('\n');
        }

        if (!faultSignatures.isEmpty()) {
            sb.append("#### Stage 3 Findings: Attributed Exception & Main-Thread Stall Signatures\n\n");
            for (FaultSignature sig : faultSignatures) {
                sb.append("- **`").append(sig.signatureId()).append("`** (`").append(sig.suspectJar())
                        .append("`, occurrences: `").append(sig.occurrences()).append("`");
                if (sig.maxDurationMs() > 0.0) {
                    sb.append(String.format(Locale.ROOT, ", peak stall: `%.1f ms`", sig.maxDurationMs()));
                }
                sb.append(")\n");
            }
            sb.append('\n');
        }

        if (!retentionFindings.isEmpty()) {
            sb.append("#### Stage 4 Findings: Post-GC Class Retention Slopes (Bonferroni OLS)\n\n");
            for (ClassRetentionFinding rf : retentionFindings) {
                sb.append("- `").append(rf.formatSummaryLine()).append("`\n");
            }
            sb.append('\n');
        }

        if (!causalFindings.isEmpty()) {
            sb.append("#### Stage 5 Findings: First-Order & Second-Order Bytecode & Causal Audit\n\n");
            for (CausalFinding cf : causalFindings) {
                sb.append("- **[").append(cf.confidenceTier().name()).append(' ').append(cf.confidencePercent())
                        .append("%]** *(Order ").append(cf.order()).append(" — `").append(cf.kind().name())
                        .append("`, `").append(cf.artifactName()).append("`)*\n");
                sb.append("  - **Declared:** ").append(cf.declaredSurface()).append('\n');
                sb.append("  - **Finding:** ").append(cf.causalDefect()).append('\n');
                sb.append("  - **Clears When:** ").append(cf.clearsWhen()).append('\n');
                if (!cf.llmExplanation().isEmpty()) {
                    sb.append("  - **AST-Grounded Explanation:** ").append(cf.llmExplanation()).append('\n');
                }
            }
            sb.append('\n');
        }

        return sb.toString();
    }

    /**
     * Generates a self-contained, publishable YAML quality-evidence data document leading on line 1
     * with {@code status: <PASS|WARN|FAIL>} so the file can be directly copied or attached for
     * BuiltByBit (BBB) or Modrinth moderation review.
     *
     * @return publishable YAML data string leading with {@code status}
     */
    public String toPublishableDataYaml() {
        String nowIso = Instant.now().toString();
        long confirmedCausal = causalFindings.stream()
                .filter(f -> f.confidenceTier() == ConfidenceTier.CONFIRMED)
                .count();
        long highCausal = causalFindings.stream()
                .filter(f -> f.confidenceTier() == ConfidenceTier.HIGH)
                .count();
        StringBuilder sb = new StringBuilder();
        sb.append("status: ").append(overallVerdict().name()).append('\n');
        sb.append("moderation_ready: ").append(overallVerdict() != Verdict.FAIL).append('\n');
        sb.append("verdict_summary: ").append(yamlQuote(verdictSummary())).append('\n');
        sb.append("evidence_purpose: \"BuiltByBit (BBB) / Modrinth / Hangar Quality & Safety Moderation Evidence\"\n");
        sb.append("target: ").append(yamlQuote(targetName)).append('\n');
        sb.append("platform: ").append(yamlQuote(platformName)).append('\n');
        sb.append("server_version: ").append(yamlQuote(serverVersion)).append('\n');
        sb.append("generated_at: ").append(yamlQuote(nowIso)).append('\n');
        sb.append("elapsed_ms: ").append(elapsedMillis).append('\n');

        sb.append("stage_verdicts:\n");
        sb.append("  stage_1_command_surface: ").append(stage1CommandSurfaceVerdict().name()).append('\n');
        sb.append("  stage_2_boundary_lifecycle_fuzz: ").append(stage2BoundaryFuzzVerdict().name()).append('\n');
        sb.append("  stage_3_stall_exception_guard: ").append(stage3StallAndExceptionVerdict().name()).append('\n');
        sb.append("  stage_4_post_gc_retention: ").append(stage4MemoryRetentionVerdict().name()).append('\n');
        sb.append("  stage_5_causal_audit: ").append(stage5CausalAuditVerdict().name()).append('\n');

        sb.append("quality_metrics:\n");
        sb.append("  indexed_jars: ").append(indexedJars).append('\n');
        sb.append("  audited_commands: ").append(auditedCommands).append('\n');
        sb.append("  default_tier_commands: ").append(defaultTierCommands).append('\n');
        sb.append("  least_privilege_warnings: ").append(leastPrivilegeFindings.size()).append('\n');
        sb.append("  episodes_executed: ").append(episodesExecuted).append('\n');
        sb.append("  distinct_arms_probed: ").append(distinctArmsProbed).append('\n');
        sb.append("  bots_spawned: ").append(telemetry.botsSpawned()).append('\n');
        sb.append("  target_concurrent_players: ").append(telemetry.targetConcurrentPlayers()).append('\n');
        sb.append("  peak_concurrent_players: ").append(telemetry.peakConcurrentPlayers()).append('\n');
        sb.append("  max_stable_players: ").append(telemetry.maxStablePlayers()).append('\n');
        sb.append("  loaded_chunks_at_peak: ").append(telemetry.loadedChunksAtPeak()).append('\n');
        sb.append("  entities_at_peak: ").append(telemetry.entitiesAtPeak()).append('\n');
        sb.append("  instability_trigger: ")
                .append(yamlQuote(telemetry.instabilityTrigger().isEmpty() ? "none" : telemetry.instabilityTrigger()))
                .append('\n');
        sb.append("  menus_opened: ").append(telemetry.menusOpened()).append('\n');
        sb.append("  menu_slots_clicked: ").append(telemetry.menuSlotsClicked()).append('\n');
        sb.append("  teleports_observed: ").append(telemetry.teleportsObserved()).append('\n');
        sb.append(String.format(
                Locale.ROOT,
                "  max_teleport_distance_blocks: %.2f\n",
                telemetry.maxTeleportDistanceBlocks()
        ));
        sb.append("  shrunk_reproducers: ").append(shrunkReproducers.size()).append('\n');
        sb.append(String.format(
                Locale.ROOT,
                "  idle_mspt_mean: %.2f\n  idle_mspt_p95: %.2f\n  fuzz_mspt_mean: %.2f\n  fuzz_mspt_p95: %.2f\n  fuzz_mspt_max: %.2f\n",
                telemetry.idleMsptMean(),
                telemetry.idleMsptP95(),
                telemetry.fuzzMsptMean(),
                telemetry.fuzzMsptP95(),
                telemetry.fuzzMsptMax()
        ));
        sb.append("  tick_samples_collected: ").append(telemetry.tickSamplesCollected()).append('\n');
        sb.append("  attributed_fault_signatures: ").append(faultSignatures.size()).append('\n');
        sb.append("  gc_checkpoints_captured: ").append(checkpointsCaptured).append('\n');
        sb.append(String.format(
                Locale.ROOT,
                "  baseline_old_gen_mb: %.2f\n  final_old_gen_mb: %.2f\n",
                telemetry.baselineHeapMb(),
                telemetry.finalHeapMb()
        ));
        sb.append("  classes_scanned: ").append(telemetry.totalClassesScanned()).append('\n');
        sb.append("  instances_scanned: ").append(telemetry.totalInstancesScanned()).append('\n');
        sb.append("  retention_leaks: ").append(retentionFindings.size()).append('\n');
        sb.append("  causal_findings_total: ").append(causalFindings.size()).append('\n');
        sb.append("  causal_findings_confirmed: ").append(confirmedCausal).append('\n');
        sb.append("  causal_findings_high: ").append(highCausal).append('\n');

        appendYamlStringList(sb, "clicked_menu_items", telemetry.clickedMenuItems());
        appendYamlStringList(sb, "command_execution_telemetry", telemetry.commandSummaries());
        appendYamlStringList(sb, "top_target_class_deltas", telemetry.topTargetClassDeltas());

        List<String> lpLines = new ArrayList<>(leastPrivilegeFindings.size());
        for (LeastPrivilegeFinding f : leastPrivilegeFindings) {
            lpLines.add("/" + f.nodeId() + " (" + f.suspectPluginOrJar() + ", " + f.findingKind() + ") -> " + f.remediationCommand());
        }
        appendYamlStringList(sb, "least_privilege_findings", lpLines);

        List<String> reproLines = new ArrayList<>(shrunkReproducers.size());
        for (DualAudienceMitigationReport r : shrunkReproducers) {
            reproLines.add(r.authorReproducerSummary());
        }
        appendYamlStringList(sb, "shrunk_reproducers", reproLines);

        List<String> faultLines = new ArrayList<>(faultSignatures.size());
        for (FaultSignature sig : faultSignatures) {
            faultLines.add(sig.signatureId() + " (" + sig.suspectJar() + ", count=" + sig.occurrences() + ")");
        }
        appendYamlStringList(sb, "fault_signatures", faultLines);

        List<String> leakLines = new ArrayList<>(retentionFindings.size());
        for (ClassRetentionFinding rf : retentionFindings) {
            leakLines.add(rf.formatSummaryLine());
        }
        appendYamlStringList(sb, "retention_findings", leakLines);

        List<String> causalLines = new ArrayList<>(causalFindings.size());
        for (CausalFinding cf : causalFindings) {
            causalLines.add("[" + cf.confidenceTier().name() + " " + cf.confidencePercent() + "% Order "
                    + cf.order() + "] Declared: " + cf.declaredSurface() + " -> Finding: " + cf.causalDefect());
        }
        appendYamlStringList(sb, "causal_findings", causalLines);
        return sb.toString();
    }

    /**
     * Generates a self-contained, publishable JSON quality-evidence data document leading on the
     * first property with {@code "status": "<PASS|WARN|FAIL>"} for BuiltByBit (BBB), Modrinth, or
     * CI moderation pipelines.
     *
     * @return publishable JSON data string leading with {@code "status"}
     */
    public String toPublishableDataJson() {
        String nowIso = Instant.now().toString();
        long confirmedCausal = causalFindings.stream()
                .filter(f -> f.confidenceTier() == ConfidenceTier.CONFIRMED)
                .count();
        long highCausal = causalFindings.stream()
                .filter(f -> f.confidenceTier() == ConfidenceTier.HIGH)
                .count();
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"status\": ").append(jsonQuote(overallVerdict().name())).append(",\n");
        sb.append("  \"moderationReady\": ").append(overallVerdict() != Verdict.FAIL).append(",\n");
        sb.append("  \"verdictSummary\": ").append(jsonQuote(verdictSummary())).append(",\n");
        sb.append("  \"evidencePurpose\": \"BuiltByBit (BBB) / Modrinth / Hangar Quality & Safety Moderation Evidence\",\n");
        sb.append("  \"target\": ").append(jsonQuote(targetName)).append(",\n");
        sb.append("  \"platform\": ").append(jsonQuote(platformName)).append(",\n");
        sb.append("  \"serverVersion\": ").append(jsonQuote(serverVersion)).append(",\n");
        sb.append("  \"generatedAt\": ").append(jsonQuote(nowIso)).append(",\n");
        sb.append("  \"elapsedMillis\": ").append(elapsedMillis).append(",\n");

        sb.append("  \"stageVerdicts\": {\n");
        sb.append("    \"stage1CommandSurface\": ").append(jsonQuote(stage1CommandSurfaceVerdict().name())).append(",\n");
        sb.append("    \"stage2BoundaryLifecycleFuzz\": ").append(jsonQuote(stage2BoundaryFuzzVerdict().name())).append(",\n");
        sb.append("    \"stage3StallExceptionGuard\": ").append(jsonQuote(stage3StallAndExceptionVerdict().name())).append(",\n");
        sb.append("    \"stage4PostGcRetention\": ").append(jsonQuote(stage4MemoryRetentionVerdict().name())).append(",\n");
        sb.append("    \"stage5CausalAudit\": ").append(jsonQuote(stage5CausalAuditVerdict().name())).append("\n");
        sb.append("  },\n");

        sb.append("  \"qualityMetrics\": {\n");
        sb.append("    \"indexedJars\": ").append(indexedJars).append(",\n");
        sb.append("    \"auditedCommands\": ").append(auditedCommands).append(",\n");
        sb.append("    \"defaultTierCommands\": ").append(defaultTierCommands).append(",\n");
        sb.append("    \"leastPrivilegeWarnings\": ").append(leastPrivilegeFindings.size()).append(",\n");
        sb.append("    \"episodesExecuted\": ").append(episodesExecuted).append(",\n");
        sb.append("    \"distinctArmsProbed\": ").append(distinctArmsProbed).append(",\n");
        sb.append("    \"botsSpawned\": ").append(telemetry.botsSpawned()).append(",\n");
        sb.append("    \"targetConcurrentPlayers\": ").append(telemetry.targetConcurrentPlayers()).append(",\n");
        sb.append("    \"peakConcurrentPlayers\": ").append(telemetry.peakConcurrentPlayers()).append(",\n");
        sb.append("    \"maxStablePlayers\": ").append(telemetry.maxStablePlayers()).append(",\n");
        sb.append("    \"loadedChunksAtPeak\": ").append(telemetry.loadedChunksAtPeak()).append(",\n");
        sb.append("    \"entitiesAtPeak\": ").append(telemetry.entitiesAtPeak()).append(",\n");
        sb.append("    \"instabilityTrigger\": ")
                .append(jsonQuote(telemetry.instabilityTrigger().isEmpty() ? "none" : telemetry.instabilityTrigger()))
                .append(",\n");
        sb.append("    \"menusOpened\": ").append(telemetry.menusOpened()).append(",\n");
        sb.append("    \"menuSlotsClicked\": ").append(telemetry.menuSlotsClicked()).append(",\n");
        sb.append("    \"teleportsObserved\": ").append(telemetry.teleportsObserved()).append(",\n");
        sb.append(String.format(
                Locale.ROOT,
                "    \"maxTeleportDistanceBlocks\": %.2f,\n",
                telemetry.maxTeleportDistanceBlocks()
        ));
        sb.append("    \"shrunkReproducers\": ").append(shrunkReproducers.size()).append(",\n");
        sb.append(String.format(
                Locale.ROOT,
                "    \"idleMsptMean\": %.2f,\n    \"idleMsptP95\": %.2f,\n    \"fuzzMsptMean\": %.2f,\n    \"fuzzMsptP95\": %.2f,\n    \"fuzzMsptMax\": %.2f,\n",
                telemetry.idleMsptMean(),
                telemetry.idleMsptP95(),
                telemetry.fuzzMsptMean(),
                telemetry.fuzzMsptP95(),
                telemetry.fuzzMsptMax()
        ));
        sb.append("    \"tickSamplesCollected\": ").append(telemetry.tickSamplesCollected()).append(",\n");
        sb.append("    \"attributedFaultSignatures\": ").append(faultSignatures.size()).append(",\n");
        sb.append("    \"gcCheckpointsCaptured\": ").append(checkpointsCaptured).append(",\n");
        sb.append(String.format(
                Locale.ROOT,
                "    \"baselineOldGenMb\": %.2f,\n    \"finalOldGenMb\": %.2f,\n",
                telemetry.baselineHeapMb(),
                telemetry.finalHeapMb()
        ));
        sb.append("    \"classesScanned\": ").append(telemetry.totalClassesScanned()).append(",\n");
        sb.append("    \"instancesScanned\": ").append(telemetry.totalInstancesScanned()).append(",\n");
        sb.append("    \"retentionLeaks\": ").append(retentionFindings.size()).append(",\n");
        sb.append("    \"causalFindingsTotal\": ").append(causalFindings.size()).append(",\n");
        sb.append("    \"causalFindingsConfirmed\": ").append(confirmedCausal).append(",\n");
        sb.append("    \"causalFindingsHigh\": ").append(highCausal).append("\n");
        sb.append("  },\n");

        appendJsonStringList(sb, "clickedMenuItems", telemetry.clickedMenuItems(), true);
        appendJsonStringList(sb, "commandExecutionTelemetry", telemetry.commandSummaries(), true);
        appendJsonStringList(sb, "topTargetClassDeltas", telemetry.topTargetClassDeltas(), true);

        List<String> lpLines = new ArrayList<>(leastPrivilegeFindings.size());
        for (LeastPrivilegeFinding f : leastPrivilegeFindings) {
            lpLines.add("/" + f.nodeId() + " (" + f.suspectPluginOrJar() + ", " + f.findingKind() + ") -> " + f.remediationCommand());
        }
        appendJsonStringList(sb, "leastPrivilegeFindings", lpLines, true);

        List<String> reproLines = new ArrayList<>(shrunkReproducers.size());
        for (DualAudienceMitigationReport r : shrunkReproducers) {
            reproLines.add(r.authorReproducerSummary());
        }
        appendJsonStringList(sb, "shrunkReproducers", reproLines, true);

        List<String> faultLines = new ArrayList<>(faultSignatures.size());
        for (FaultSignature sig : faultSignatures) {
            faultLines.add(sig.signatureId() + " (" + sig.suspectJar() + ", count=" + sig.occurrences() + ")");
        }
        appendJsonStringList(sb, "faultSignatures", faultLines, true);

        List<String> leakLines = new ArrayList<>(retentionFindings.size());
        for (ClassRetentionFinding rf : retentionFindings) {
            leakLines.add(rf.formatSummaryLine());
        }
        appendJsonStringList(sb, "retentionFindings", leakLines, true);

        List<String> causalLines = new ArrayList<>(causalFindings.size());
        for (CausalFinding cf : causalFindings) {
            causalLines.add("[" + cf.confidenceTier().name() + " " + cf.confidencePercent() + "% Order "
                    + cf.order() + "] Declared: " + cf.declaredSurface() + " -> Finding: " + cf.causalDefect());
        }
        appendJsonStringList(sb, "causalFindings", causalLines, false);
        sb.append("}\n");
        return sb.toString();
    }

    /**
     * Writes publishable quality-evidence data files ({@code <sanitizedTarget>-qc-data.yml} and
     * {@code <sanitizedTarget>-qc-data.json}) leading with {@code status} to
     * {@code <rootFolder>/reports/}.
     *
     * @param rootFolder plugin or mod root configuration directory
     * @return path to the written YAML data file
     * @throws IOException if file writing fails
     */
    public Path writePublishableDataFiles(Path rootFolder) throws IOException {
        Objects.requireNonNull(rootFolder, "rootFolder");
        Path reportsDir = rootFolder.resolve("reports");
        Files.createDirectories(reportsDir);
        String safeTarget = sanitizedTargetSlug();
        Path yamlFile = reportsDir.resolve(safeTarget + "-qc-data.yml");
        Path jsonFile = reportsDir.resolve(safeTarget + "-qc-data.json");
        Files.writeString(yamlFile, toPublishableDataYaml(), StandardCharsets.UTF_8);
        Files.writeString(jsonFile, toPublishableDataJson(), StandardCharsets.UTF_8);
        return yamlFile;
    }

    /**
     * Writes {@link #toMarkdownReport()} to {@code <rootFolder>/reports/<sanitizedTarget>-qc-report.md}
     * and writes companion publishable moderation data files ({@code -qc-data.yml} and
     * {@code -qc-data.json}) in the same directory.
     *
     * @param rootFolder plugin or mod root configuration directory
     * @return path to the written Markdown file
     * @throws IOException if file writing fails
     */
    public Path writeMarkdownReport(Path rootFolder) throws IOException {
        Objects.requireNonNull(rootFolder, "rootFolder");
        Path reportsDir = rootFolder.resolve("reports");
        Files.createDirectories(reportsDir);
        String safeTarget = sanitizedTargetSlug();
        Path reportFile = reportsDir.resolve(safeTarget + "-qc-report.md");
        Files.writeString(reportFile, toMarkdownReport(), StandardCharsets.UTF_8);
        writePublishableDataFiles(rootFolder);
        return reportFile;
    }

    private static void appendYamlStringList(StringBuilder sb, String key, List<String> items) {
        if (items == null || items.isEmpty()) {
            sb.append(key).append(": []\n");
            return;
        }
        sb.append(key).append(":\n");
        for (String item : items) {
            sb.append("  - ").append(yamlQuote(item)).append('\n');
        }
    }

    private static void appendJsonStringList(
            StringBuilder sb,
            String key,
            List<String> items,
            boolean trailingComma
    ) {
        if (items == null || items.isEmpty()) {
            sb.append("  ").append(jsonQuote(key)).append(": []")
                    .append(trailingComma ? ",\n" : "\n");
            return;
        }
        sb.append("  ").append(jsonQuote(key)).append(": [\n");
        for (int i = 0; i < items.size(); i++) {
            sb.append("    ").append(jsonQuote(items.get(i)));
            if (i + 1 < items.size()) {
                sb.append(',');
            }
            sb.append('\n');
        }
        sb.append("  ]").append(trailingComma ? ",\n" : "\n");
    }

    private static String yamlQuote(String raw) {
        return jsonQuote(raw);
    }

    private static String jsonQuote(String raw) {
        if (raw == null) {
            return "\"\"";
        }
        StringBuilder sb = new StringBuilder(raw.length() + 4);
        sb.append('"');
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
        return sb.toString();
    }
}
