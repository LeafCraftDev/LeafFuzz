package net.leaf.fuzz.common.cli;

import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.CausalChainSlice;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.CausalFinding;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.CausalGraphReport;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.ConfidenceTier;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.EntryPointKind;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.FindingKind;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.ListenerRegistrationMode;
import io.github.dailystruggle.bytecode.JarConfigScanner;
import io.github.dailystruggle.bytecode.JarConfigScanner.HarvestedArtifact;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Headless Pass 1 static bytecode batch triage runner capable of filtering thousands of submitted
 * plugin and mod {@code .jar} archives down to a ranked top-{@code N} shortlist off-thread without
 * booting a Minecraft server.
 *
 * <p>Applies a deterministic closed-world hard-reject gate (rejecting solely on intra-JAR
 * structural or causal-chain proofs validated to {@code < 0.5%} empirical false-positive rate on
 * real-world corpora), while inferring undeclared ecosystem and third-party package dependencies
 * from constant pools with zero score penalty.
 *
 * @governedBy leaffuzz-ADR-001, ADR-115, ADR-125
 * @trace REQ-FUZZ-TRIAGE-001, REQ-FUZZ-TRIAGE-002, REQ-FUZZ-TRIAGE-003, REQ-FUZZ-TRIAGE-004
 */
public final class LeafFuzzBatchTriageRunner {

    /** Default shortlist pass cap when {@code --max-pass} is omitted. */
    public static final int DEFAULT_MAX_PASS = 200;

    private LeafFuzzBatchTriageRunner() {
    }

    /** Pass 1 batch triage disposition for a scanned archive. */
    public enum TriageDecision {
        SHORTLIST_PASS,
        DEFERRED_RANK,
        REJECT
    }

      /** Closed-world deterministic hard-reject reasons. */
      public enum HardRejectReason {
          CORRUPT_OR_EMPTY_ARCHIVE,
          MISSING_DECLARED_MAIN_CLASS,
          ALL_ENTRYPOINTS_UNWIRED,
          CONFIRMED_S005_ASYNC_MAIN_SINK,
          CONFIRMED_S004_SWALLOWED_IO_FAILURE,
          CONFIRMED_FOLIA_CLAIM_VIOLATION,
          CONFIRMED_MALICIOUS_BACKDOOR_SINK
      }

    /**
     * Configuration for a headless Pass 1 batch triage execution.
     *
     * @param inputDir       directory containing candidate {@code .jar} files
     * @param maxPass        maximum number of passing archives to promote to {@link TriageDecision#SHORTLIST_PASS}
     * @param threads        worker thread count for parallel off-thread archive scanning
     * @param strictS004S005 whether {@code CONFIRMED} {@code S-004}/{@code S-005} bytecode proofs trigger {@link TriageDecision#REJECT}
     * @param jsonOut        optional path to write the JSON shortlist &amp; dependency manifest
     * @param csvOut         optional path to write the CSV leaderboard
     * @param markdownOut    optional path to write the Markdown leaderboard report
     */
    public record TriageConfig(
            Path inputDir,
            int maxPass,
            int threads,
            boolean strictS004S005,
            Path jsonOut,
            Path csvOut,
            Path markdownOut
    ) {
        public TriageConfig {
            Objects.requireNonNull(inputDir, "inputDir");
            maxPass = Math.max(1, maxPass);
            threads = Math.max(1, Math.min(64, threads));
        }

        public TriageConfig(Path inputDir, int maxPass) {
            this(
                    inputDir,
                    maxPass,
                    Math.max(1, Math.min(16, Runtime.getRuntime().availableProcessors())),
                    true,
                    null,
                    null,
                    null
            );
        }
    }

    /**
     * Triage evaluation result and inferred dependency manifest for a single {@code .jar} submission.
     *
     * @param rank                          1-based deterministic rank across the batch
     * @param jarFileName                   archive file name
     * @param artifactId                    canonical artifact ID (e.g. {@code plugin:myplugin})
     * @param displayName                   plugin or mod display name
     * @param version                       declared version string
     * @param loaderFamily                  detected loader family ({@code paper}, {@code bukkit}, {@code fabric}, {@code neoforge}, {@code velocity})
     * @param jarSha512                     hex SHA-512 digest of the archive
     * @param decision                      final Pass 1 triage decision
     * @param compositeScore                composite delivery &amp; quality score in {@code [0.0, 100.0]}
     * @param causalDeliveryRatio           ratio of active entrypoints reaching verified effect sinks in {@code [0.0, 1.0]}
     * @param scannedClassCount             number of non-shaded {@code .class} entries analyzed
     * @param entryChainCount               number of causal entrypoint chains extracted
     * @param confirmedFindingCount         count of {@code CONFIRMED (100%)} findings
     * @param highFindingCount              count of {@code HIGH} confidence findings
     * @param rejectReasons                 deterministic closed-world rejection reasons (empty unless {@link TriageDecision#REJECT})
     * @param declaredDependencies          dependencies declared in {@code plugin.yml} / {@code paper-plugin.yml} ({@code depend} + {@code softdepend})
     * @param inferredEcosystemDependencies companion plugins inferred from bytecode constant pools (e.g. {@code Vault}, {@code PlaceholderAPI})
     * @param inferredExternalPackages      external 3-segment package prefixes referenced in bytecode constant pools
     * @param findingSummaries              concise summaries of static findings contributing to score deductions or rejection
     */
    public record ArtifactTriageEntry(
            int rank,
            String jarFileName,
            String artifactId,
            String displayName,
            String version,
            String loaderFamily,
            String jarSha512,
            TriageDecision decision,
            double compositeScore,
            double causalDeliveryRatio,
            int scannedClassCount,
            int entryChainCount,
            int confirmedFindingCount,
            int highFindingCount,
            List<HardRejectReason> rejectReasons,
            List<String> declaredDependencies,
            List<String> inferredEcosystemDependencies,
            List<String> inferredExternalPackages,
            List<String> findingSummaries
    ) {
        public ArtifactTriageEntry {
            jarFileName = jarFileName == null ? "" : jarFileName;
            artifactId = artifactId == null ? "plugin:unknown" : artifactId;
            displayName = displayName == null ? artifactId : displayName;
            version = version == null ? "unknown" : version;
            loaderFamily = loaderFamily == null ? "bukkit" : loaderFamily;
            jarSha512 = jarSha512 == null ? "" : jarSha512;
            decision = decision == null ? TriageDecision.REJECT : decision;
            rejectReasons = rejectReasons == null ? List.of() : List.copyOf(rejectReasons);
            declaredDependencies = declaredDependencies == null ? List.of() : List.copyOf(declaredDependencies);
            inferredEcosystemDependencies = inferredEcosystemDependencies == null
                    ? List.of()
                    : List.copyOf(inferredEcosystemDependencies);
            inferredExternalPackages = inferredExternalPackages == null
                    ? List.of()
                    : List.copyOf(inferredExternalPackages);
            findingSummaries = findingSummaries == null ? List.of() : List.copyOf(findingSummaries);
        }

        ArtifactTriageEntry withRankAndDecision(int newRank, TriageDecision newDecision) {
            return new ArtifactTriageEntry(
                    newRank,
                    jarFileName,
                    artifactId,
                    displayName,
                    version,
                    loaderFamily,
                    jarSha512,
                    newDecision,
                    compositeScore,
                    causalDeliveryRatio,
                    scannedClassCount,
                    entryChainCount,
                    confirmedFindingCount,
                    highFindingCount,
                    rejectReasons,
                    declaredDependencies,
                    inferredEcosystemDependencies,
                    inferredExternalPackages,
                    findingSummaries
            );
        }
    }

    /**
     * Completed Pass 1 batch triage report with JSON, CSV, and Markdown serializers.
     *
     * @param totalScanned       total number of candidate {@code .jar} archives evaluated
     * @param maxPassCap         configured {@code --max-pass} shortlist cap
     * @param shortlistPassCount count of archives promoted to {@link TriageDecision#SHORTLIST_PASS}
     * @param deferredRankCount  count of valid archives ranked below {@code maxPassCap} ({@link TriageDecision#DEFERRED_RANK})
     * @param rejectedCount      count of archives rejected by the closed-world hard-reject gate
     * @param elapsedMillis      wall-clock scan duration in milliseconds
     * @param entries            ranked list of all evaluated archives
     */
    public record TriageBatchReport(
            int totalScanned,
            int maxPassCap,
            int shortlistPassCount,
            int deferredRankCount,
            int rejectedCount,
            long elapsedMillis,
            List<ArtifactTriageEntry> entries
    ) {
        public TriageBatchReport {
            entries = entries == null ? List.of() : List.copyOf(entries);
        }

        /** Returns only the shortlisted top-{@code N} entries ({@link TriageDecision#SHORTLIST_PASS}). */
        public List<ArtifactTriageEntry> shortlist() {
            return entries.stream()
                    .filter(e -> e.decision() == TriageDecision.SHORTLIST_PASS)
                    .toList();
        }

        /** Serializes the batch triage report and Pass 2 dependency manifest as machine-readable JSON. */
        public String toJsonReport() {
            StringBuilder sb = new StringBuilder(Math.max(512, entries.size() * 320));
            sb.append("{\n");
            sb.append("  \"totalScanned\": ").append(totalScanned).append(",\n");
            sb.append("  \"maxPassCap\": ").append(maxPassCap).append(",\n");
            sb.append("  \"shortlistPassCount\": ").append(shortlistPassCount).append(",\n");
            sb.append("  \"deferredRankCount\": ").append(deferredRankCount).append(",\n");
            sb.append("  \"rejectedCount\": ").append(rejectedCount).append(",\n");
            sb.append("  \"elapsedMillis\": ").append(elapsedMillis).append(",\n");
            sb.append("  \"entries\": [\n");
            for (int i = 0; i < entries.size(); i++) {
                ArtifactTriageEntry e = entries.get(i);
                sb.append("    {\n");
                sb.append("      \"rank\": ").append(e.rank()).append(",\n");
                sb.append("      \"jarFileName\": \"").append(escapeJson(e.jarFileName())).append("\",\n");
                sb.append("      \"artifactId\": \"").append(escapeJson(e.artifactId())).append("\",\n");
                sb.append("      \"displayName\": \"").append(escapeJson(e.displayName())).append("\",\n");
                sb.append("      \"version\": \"").append(escapeJson(e.version())).append("\",\n");
                sb.append("      \"loaderFamily\": \"").append(escapeJson(e.loaderFamily())).append("\",\n");
                sb.append("      \"jarSha512\": \"").append(escapeJson(e.jarSha512())).append("\",\n");
                sb.append("      \"decision\": \"").append(e.decision().name()).append("\",\n");
                sb.append("      \"compositeScore\": ")
                        .append(String.format(Locale.ROOT, "%.2f", e.compositeScore())).append(",\n");
                sb.append("      \"causalDeliveryRatio\": ")
                        .append(String.format(Locale.ROOT, "%.4f", e.causalDeliveryRatio())).append(",\n");
                sb.append("      \"scannedClassCount\": ").append(e.scannedClassCount()).append(",\n");
                sb.append("      \"entryChainCount\": ").append(e.entryChainCount()).append(",\n");
                sb.append("      \"confirmedFindingCount\": ").append(e.confirmedFindingCount()).append(",\n");
                sb.append("      \"highFindingCount\": ").append(e.highFindingCount()).append(",\n");
                sb.append("      \"rejectReasons\": ")
                        .append(formatJsonStringList(e.rejectReasons().stream().map(Enum::name).toList())).append(",\n");
                sb.append("      \"declaredDependencies\": ")
                        .append(formatJsonStringList(e.declaredDependencies())).append(",\n");
                sb.append("      \"inferredEcosystemDependencies\": ")
                        .append(formatJsonStringList(e.inferredEcosystemDependencies())).append(",\n");
                sb.append("      \"inferredExternalPackages\": ")
                        .append(formatJsonStringList(e.inferredExternalPackages())).append(",\n");
                sb.append("      \"findingSummaries\": ")
                        .append(formatJsonStringList(e.findingSummaries())).append("\n");
                sb.append("    }").append(i + 1 < entries.size() ? "," : "").append("\n");
            }
            sb.append("  ]\n");
            sb.append("}\n");
            return sb.toString();
        }

        /** Serializes the batch triage leaderboard as RFC 4180 CSV. */
        public String toCsvReport() {
            StringBuilder sb = new StringBuilder(Math.max(256, entries.size() * 160));
            sb.append("rank,jar_file,artifact_id,display_name,version,loader,decision,composite_score,")
                    .append("causal_delivery_ratio,scanned_classes,confirmed_findings,high_findings,")
                    .append("reject_reasons,declared_dependencies,inferred_ecosystem_dependencies,inferred_external_packages\n");
            for (ArtifactTriageEntry e : entries) {
                sb.append(e.rank()).append(',');
                sb.append(escapeCsv(e.jarFileName())).append(',');
                sb.append(escapeCsv(e.artifactId())).append(',');
                sb.append(escapeCsv(e.displayName())).append(',');
                sb.append(escapeCsv(e.version())).append(',');
                sb.append(escapeCsv(e.loaderFamily())).append(',');
                sb.append(e.decision().name()).append(',');
                sb.append(String.format(Locale.ROOT, "%.2f", e.compositeScore())).append(',');
                sb.append(String.format(Locale.ROOT, "%.4f", e.causalDeliveryRatio())).append(',');
                sb.append(e.scannedClassCount()).append(',');
                sb.append(e.confirmedFindingCount()).append(',');
                sb.append(e.highFindingCount()).append(',');
                sb.append(escapeCsv(String.join(";", e.rejectReasons().stream().map(Enum::name).toList()))).append(',');
                sb.append(escapeCsv(String.join(";", e.declaredDependencies()))).append(',');
                sb.append(escapeCsv(String.join(";", e.inferredEcosystemDependencies()))).append(',');
                sb.append(escapeCsv(String.join(";", e.inferredExternalPackages()))).append('\n');
            }
            return sb.toString();
        }

        /** Serializes a human-readable Markdown leaderboard and dependency manifest summary. */
        public String toMarkdownReport() {
            StringBuilder sb = new StringBuilder(Math.max(512, entries.size() * 200));
            sb.append("# LeafFuzz Pass 1 Static Batch Triage Report\n\n");
            sb.append("- **Total Scanned:** `").append(totalScanned).append("`\n");
            sb.append("- **Shortlist Pass (`<= ").append(maxPassCap).append("`):** `").append(shortlistPassCount).append("`\n");
            sb.append("- **Deferred Rank (`> ").append(maxPassCap).append("`):** `").append(deferredRankCount).append("`\n");
            sb.append("- **Hard Rejected:** `").append(rejectedCount).append("`\n");
            sb.append("- **Elapsed Wall Time:** `").append(elapsedMillis).append(" ms`\n\n");

            sb.append("## Ranked Triage Leaderboard\n\n");
            sb.append("| Rank | Archive | Artifact | Loader | Decision | Score | Delivery | Classes | Declared Deps | Inferred Ecosystem Deps | Reject / Finding Notes |\n");
            sb.append("|---:|---|---|---|---|---:|---:|---:|---|---|---|\n");
            for (ArtifactTriageEntry e : entries) {
                String notes = !e.rejectReasons().isEmpty()
                        ? String.join(", ", e.rejectReasons().stream().map(Enum::name).toList())
                        : (e.findingSummaries().isEmpty() ? "CLEAN" : e.findingSummaries().get(0));
                sb.append("| ").append(e.rank())
                        .append(" | `").append(escapeMd(e.jarFileName())).append("`")
                        .append(" | `").append(escapeMd(e.displayName())).append("`")
                        .append(" | `").append(escapeMd(e.loaderFamily())).append("`")
                        .append(" | `").append(e.decision().name()).append("`")
                        .append(" | `").append(String.format(Locale.ROOT, "%.2f", e.compositeScore())).append("`")
                        .append(" | `").append(String.format(Locale.ROOT, "%.0f%%", e.causalDeliveryRatio() * 100.0)).append("`")
                        .append(" | `").append(e.scannedClassCount()).append("`")
                        .append(" | ").append(e.declaredDependencies().isEmpty() ? "-" : "`" + String.join(", ", e.declaredDependencies()) + "`")
                        .append(" | ").append(e.inferredEcosystemDependencies().isEmpty() ? "-" : "`" + String.join(", ", e.inferredEcosystemDependencies()) + "`")
                        .append(" | ").append(escapeMd(notes))
                        .append(" |\n");
            }
            return sb.toString();
        }
    }

    /**
     * Runs the Pass 1 static batch triage funnel across all candidate {@code .jar} archives in
     * {@link TriageConfig#inputDir()} and writes any requested output artifacts.
     *
     * @param config batch triage configuration
     * @return completed {@link TriageBatchReport}
     * @throws IOException if the input directory cannot be listed or output files cannot be written
     */
    public static TriageBatchReport runBatchTriage(TriageConfig config) throws IOException {
        Objects.requireNonNull(config, "config");
        long startNanos = System.nanoTime();

        List<Path> jarFiles = discoverCandidateJars(config.inputDir());
        List<ArtifactTriageEntry> rawEntries;
        if (jarFiles.isEmpty()) {
            rawEntries = List.of();
        } else if (config.threads() <= 1 || jarFiles.size() == 1) {
            rawEntries = jarFiles.stream()
                    .map(jar -> evaluateSingleJar(jar, config.strictS004S005()))
                    .toList();
        } else {
            rawEntries = jarFiles.parallelStream()
                    .map(jar -> evaluateSingleJar(jar, config.strictS004S005()))
                    .toList();
        }

        List<ArtifactTriageEntry> passing = new ArrayList<>();
        List<ArtifactTriageEntry> rejected = new ArrayList<>();
        for (ArtifactTriageEntry entry : rawEntries) {
            if (entry.decision() == TriageDecision.REJECT) {
                rejected.add(entry);
            } else {
                passing.add(entry);
            }
        }

        passing.sort(PASSING_COMPARATOR);
        rejected.sort(Comparator.comparing(ArtifactTriageEntry::jarFileName)
                .thenComparing(ArtifactTriageEntry::jarSha512));

        List<ArtifactTriageEntry> ranked = new ArrayList<>(rawEntries.size());
        int shortlistCount = 0;
        int deferredCount = 0;
        int rank = 1;
        for (ArtifactTriageEntry candidate : passing) {
            if (shortlistCount < config.maxPass()) {
                ranked.add(candidate.withRankAndDecision(rank++, TriageDecision.SHORTLIST_PASS));
                shortlistCount++;
            } else {
                ranked.add(candidate.withRankAndDecision(rank++, TriageDecision.DEFERRED_RANK));
                deferredCount++;
            }
        }
        for (ArtifactTriageEntry rej : rejected) {
            ranked.add(rej.withRankAndDecision(rank++, TriageDecision.REJECT));
        }

        long elapsedMillis = Math.max(0L, (System.nanoTime() - startNanos) / 1_000_000L);
        TriageBatchReport report = new TriageBatchReport(
                ranked.size(),
                config.maxPass(),
                shortlistCount,
                deferredCount,
                rejected.size(),
                elapsedMillis,
                ranked
        );

        writeOutputsIfConfigured(config, report);
        return report;
    }

    /**
     * Evaluates a single {@code .jar} archive against the closed-world hard-reject gate and
     * computes its deterministic composite quality score and constant-pool dependency manifest.
     *
     * @param jarPath        path to the candidate {@code .jar} archive
     * @param strictS004S005 whether {@code CONFIRMED} {@code S-004}/{@code S-005} proofs trigger hard rejection
     * @return preliminary {@link ArtifactTriageEntry} (prior to batch-wide rank assignment)
     */
    public static ArtifactTriageEntry evaluateSingleJar(Path jarPath, boolean strictS004S005) {
        Objects.requireNonNull(jarPath, "jarPath");
        String fileName = jarPath.getFileName() != null ? jarPath.getFileName().toString() : jarPath.toString();

        HarvestedArtifact harvested;
        CausalGraphReport causal;
        try {
            harvested = JarConfigScanner.scanJar(jarPath);
            causal = BytecodeCausalGraphScanner.scanJar(jarPath, harvested);
        } catch (IOException | RuntimeException e) {
            return new ArtifactTriageEntry(
                    0,
                    fileName,
                    "plugin:corrupt",
                    fileName,
                    "unknown",
                    "unknown",
                    "",
                    TriageDecision.REJECT,
                    0.0,
                    0.0,
                    0,
                    0,
                    0,
                    0,
                    List.of(HardRejectReason.CORRUPT_OR_EMPTY_ARCHIVE),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of("CORRUPT_OR_EMPTY_ARCHIVE: " + e.getClass().getSimpleName())
            );
        }

        Set<HardRejectReason> rejectReasons = new LinkedHashSet<>();
        if (harvested.scannedClassCount() <= 0) {
            rejectReasons.add(HardRejectReason.CORRUPT_OR_EMPTY_ARCHIVE);
        }
        if (!harvested.declaredMainClass().isEmpty() && !harvested.mainClassPresent()) {
            rejectReasons.add(HardRejectReason.MISSING_DECLARED_MAIN_CLASS);
        }
        if (isAllEntrypointsUnwired(harvested, causal)) {
            rejectReasons.add(HardRejectReason.ALL_ENTRYPOINTS_UNWIRED);
        }

        int confirmedCount = 0;
        int highCount = 0;
        List<String> summaries = new ArrayList<>();
          for (CausalFinding f : causal.findings()) {
              if (f.confidenceTier() == ConfidenceTier.CONFIRMED) {
                  confirmedCount++;
                  if (isCausalMaliciousBackdoorDefect(f)) {
                      rejectReasons.add(HardRejectReason.CONFIRMED_MALICIOUS_BACKDOOR_SINK);
                  } else if (strictS004S005
                          && f.kind() == FindingKind.CAUSAL_ASYNC_MAIN_THREAD_SINK
                          && isCausalFoliaClaimDefect(f)) {
                      rejectReasons.add(HardRejectReason.CONFIRMED_FOLIA_CLAIM_VIOLATION);
                  } else if (strictS004S005
                          && f.kind() == FindingKind.CAUSAL_ASYNC_MAIN_THREAD_SINK
                          && isCausalAsyncMainSinkDefect(f, harvested, causal)) {
                      rejectReasons.add(HardRejectReason.CONFIRMED_S005_ASYNC_MAIN_SINK);
                  } else if (strictS004S005
                          && f.kind() == FindingKind.CAUSAL_SWALLOWED_FAILURE
                          && isCausalSwallowedIoDefect(f, harvested, causal)) {
                      rejectReasons.add(HardRejectReason.CONFIRMED_S004_SWALLOWED_IO_FAILURE);
                  }
              } else if (f.confidenceTier() == ConfidenceTier.HIGH) {
                  highCount++;
              }
              if (summaries.size() < 8) {
                  String detail = (isCausalMaliciousBackdoorDefect(f) || isCausalFoliaClaimDefect(f))
                          ? " (" + f.declaredSurface() + ")"
                          : "";
                  summaries.add(f.kind().name() + " [" + f.confidenceTier().name() + "]: " + f.entryPointSymbol() + detail);
              }
          }

        double deliveryRatio = computeCausalDeliveryRatio(causal);
        boolean rejected = !rejectReasons.isEmpty();
        double compositeScore = rejected ? 0.0 : computeCompositeScore(causal, deliveryRatio);

        return new ArtifactTriageEntry(
                0,
                fileName,
                harvested.artifactId(),
                harvested.displayName(),
                harvested.version(),
                harvested.loaderFamily(),
                harvested.jarSha512(),
                rejected ? TriageDecision.REJECT : TriageDecision.SHORTLIST_PASS,
                compositeScore,
                deliveryRatio,
                harvested.scannedClassCount(),
                causal.entryChains().size(),
                confirmedCount,
                highCount,
                new ArrayList<>(rejectReasons),
                harvested.dependencies(),
                new ArrayList<>(causal.inferredEcosystemDependencies()),
                new ArrayList<>(causal.inferredExternalPackages()),
                summaries
        );
    }

    private static boolean isAllEntrypointsUnwired(HarvestedArtifact harvested, CausalGraphReport causal) {
        int declaredCommands = harvested.commands().size();
        int declaredListeners = causal.listenerRegistrations().size();
        int totalDeclared = declaredCommands + declaredListeners;
        if (totalDeclared <= 0) {
            return false;
        }
        if (!causal.commandSchemas().isEmpty()) {
            return false;
        }
        for (CausalChainSlice chain : causal.entryChains()) {
            if (chain.kind() == EntryPointKind.COMMAND && !chain.reachableEffectSinks().isEmpty()) {
                return false;
            }
            if (chain.kind() == EntryPointKind.EVENT
                    && chain.registrationMode() != ListenerRegistrationMode.UNREGISTERED) {
                return false;
            }
        }

        long confirmedUnwiredCmds = causal.findings().stream()
                .filter(f -> f.confidenceTier() == ConfidenceTier.CONFIRMED
                        && f.kind() == FindingKind.CAUSAL_UNWIRED_COMMAND)
                .count();
        long confirmedUnwiredListeners = causal.findings().stream()
                .filter(f -> f.confidenceTier() == ConfidenceTier.CONFIRMED
                        && f.kind() == FindingKind.CAUSAL_UNREGISTERED_LISTENER
                        && !isMultiLoaderProxyListenerSymbol(f.entryPointSymbol()))
                .count();

        boolean commandsAllUnwired = declaredCommands == 0 || confirmedUnwiredCmds >= declaredCommands;
        boolean listenersAllUnwired = declaredListeners == 0 || confirmedUnwiredListeners >= declaredListeners;
        return commandsAllUnwired && listenersAllUnwired && (confirmedUnwiredCmds + confirmedUnwiredListeners) > 0;
    }

    private static boolean isMultiLoaderProxyListenerSymbol(String symbol) {
        if (symbol == null || symbol.isEmpty()) {
            return false;
        }
        String low = symbol.toLowerCase(Locale.ROOT);
        return low.contains("velocity")
                || low.contains("bungee")
                || low.contains("waterfall")
                || low.contains("sponge")
                  || low.endsWith("#onproxystart")
                  || low.endsWith("#onproxyinitialization")
                  || low.endsWith("#onpluginmessage");
      }

      private static boolean isCausalMaliciousBackdoorDefect(CausalFinding finding) {
          if (finding == null) {
              return false;
          }
          String surface = finding.declaredSurface() != null ? finding.declaredSurface() : "";
          return surface.contains("SEC-FORCE-OP-BACKDOOR")
                  || surface.contains("SEC-COVERT-CLASSLOADER-DROPPER")
                  || finding.causalChainSteps().stream().anyMatch(s -> s.startsWith("MALICIOUS_BACKDOOR ->"));
      }

      private static boolean isCausalFoliaClaimDefect(CausalFinding finding) {
          if (finding == null) {
              return false;
          }
          String surface = finding.declaredSurface() != null ? finding.declaredSurface() : "";
          return surface.contains("folia-supported: true")
                  && finding.causalChainSteps().stream().anyMatch(s -> s.startsWith("FOLIA_CAUSAL_EXCEPTION ->"));
      }

      private static boolean isCausalAsyncMainSinkDefect(
              CausalFinding finding,
              HarvestedArtifact harvested,
              CausalGraphReport causal
      ) {
        boolean isAsyncSpawn = finding.causalChainSteps().stream().anyMatch(s -> s.startsWith("ASYNC_SPAWN ->"));
        if (!isAsyncSpawn) {
            return false;
        }
        String notDelivered = finding.causalDefect().toLowerCase(Locale.ROOT);
        boolean isWorldOrChunkSink = notDelivered.contains("#getchunkat")
                || notDelivered.contains("#loadchunk")
                || notDelivered.contains("#settype")
                || notDelivered.contains("#setblockdata")
                || notDelivered.contains("#breaknaturally")
                || notDelivered.contains("#spawnentity")
                || notDelivered.contains("#createexplosion");
        if (!isWorldOrChunkSink) {
            return false;
        }
        List<CausalChainSlice> activeEntrySlices = causal.entryChains().stream()
                .filter(c -> (c.kind() == EntryPointKind.COMMAND || c.kind() == EntryPointKind.EVENT)
                        && c.registrationMode() != ListenerRegistrationMode.UNREGISTERED)
                .toList();
        if (activeEntrySlices.isEmpty()) {
            return !harvested.declaredMainClass().isEmpty()
                    && finding.entryPointSymbol().startsWith(harvested.declaredMainClass() + "#");
        }
        String targetSym = finding.entryPointSymbol();
        String simpleTarget = toSimpleMethodRef(targetSym);
        for (CausalChainSlice slice : activeEntrySlices) {
            if (slice.macros().contains("@folia_region_guard")) {
                continue;
            }
            if (slice.spawnedSuppliersAndLambdas().contains(targetSym)
                    || slice.spawnedSuppliersAndLambdas().contains(simpleTarget)
                    || slice.hopTrace().stream().anyMatch(h -> h.contains(targetSym) || h.contains(simpleTarget))) {
                return true;
            }
        }
        return false;
    }

    private static boolean isCausalSwallowedIoDefect(
            CausalFinding finding,
            HarvestedArtifact harvested,
            CausalGraphReport causal
    ) {
        String text = (finding.causalDefect() + " " + finding.declaredSurface()).toLowerCase(Locale.ROOT);
        boolean isIoOrSql = text.contains("ioexception")
                || text.contains("sqlexception")
                || text.contains("files.")
                || text.contains("inputstream")
                || text.contains("outputstream");
        if (!isIoOrSql) {
            return false;
        }
        List<CausalChainSlice> activeEntrySlices = causal.entryChains().stream()
                .filter(c -> (c.kind() == EntryPointKind.COMMAND || c.kind() == EntryPointKind.EVENT)
                        && c.registrationMode() != ListenerRegistrationMode.UNREGISTERED)
                .toList();
        if (activeEntrySlices.isEmpty()) {
            return harvested.scannedClassCount() <= 2
                    && !harvested.declaredMainClass().isEmpty()
                    && finding.entryPointSymbol().startsWith(harvested.declaredMainClass() + "#");
        }
        String targetSym = finding.entryPointSymbol();
        String simpleTarget = toSimpleMethodRef(targetSym);
        boolean reachedFromUndeliveredEntry = false;
        for (CausalChainSlice slice : activeEntrySlices) {
            if (!slice.reachableEffectSinks().isEmpty()) {
                return false;
            }
            if (slice.entrySymbol().equals(targetSym)
                    || slice.hopTrace().stream().anyMatch(h -> h.contains(targetSym) || h.contains(simpleTarget))) {
                reachedFromUndeliveredEntry = true;
            }
        }
        return reachedFromUndeliveredEntry;
    }

    private static String toSimpleMethodRef(String symbol) {
        if (symbol == null || symbol.isEmpty()) {
            return "";
        }
        int hash = symbol.indexOf('#');
        int searchEnd = hash > 0 ? hash : symbol.length();
        int dot = symbol.lastIndexOf('.', searchEnd);
        return dot >= 0 ? symbol.substring(dot + 1) : symbol;
    }

    private static double computeCausalDeliveryRatio(CausalGraphReport causal) {
        List<CausalChainSlice> activeChains = causal.entryChains().stream()
                .filter(c -> (c.kind() == EntryPointKind.COMMAND || c.kind() == EntryPointKind.EVENT)
                        && c.registrationMode() != ListenerRegistrationMode.UNREGISTERED)
                .toList();
        if (activeChains.isEmpty()) {
            return 1.0;
        }
        Set<String> hollowEntries = new LinkedHashSet<>();
        for (CausalFinding f : causal.findings()) {
            if (f.kind() == FindingKind.CAUSAL_HOLLOW_COMMAND) {
                hollowEntries.add(f.entryPointSymbol());
            }
        }
        int delivered = 0;
        for (CausalChainSlice slice : activeChains) {
            boolean hasSink = !slice.reachableEffectSinks().isEmpty()
                    && !(slice.reachableEffectSinks().size() == 1
                    && slice.reachableEffectSinks().contains("COSMETIC_ONLY"));
            if (hasSink && !hollowEntries.contains(slice.entrySymbol())) {
                delivered++;
            }
        }
        return (double) delivered / (double) activeChains.size();
    }

    private static double computeCompositeScore(CausalGraphReport causal, double deliveryRatio) {
        double deduction = 0.0;
        for (CausalFinding f : causal.findings()) {
            double tierWeight = switch (f.confidenceTier()) {
                case CONFIRMED -> 1.0;
                case HIGH -> 0.75;
                case MEDIUM -> 0.40;
                case ADVISORY -> 0.15;
            };
            double kindPenalty = switch (f.kind()) {
                case CAUSAL_ASYNC_MAIN_THREAD_SINK -> 25.0;
                case CAUSAL_SWALLOWED_FAILURE -> 18.0;
                case CAUSAL_UNCLOSED_RESOURCE_LEAK -> 15.0;
                case CAUSAL_SYNC_MAIN_THREAD_IO -> 12.0;
                case CAUSAL_HOLLOW_COMMAND -> 12.0;
                case CAUSAL_SHARED_STATE_RACE, CAUSAL_ORPHANED_SUPPLIER -> 10.0;
                case CAUSAL_UNWIRED_COMMAND, CAUSAL_UNREGISTERED_LISTENER -> 10.0;
                case CAUSAL_DEAD_CONFIG_KEY, CAUSAL_UNREAD_CONFIG_FIELD, CAUSAL_UNIT_MISMATCH, CAUSAL_LLM_SEMANTIC_MISMATCH -> 4.0;
            };
            deduction += kindPenalty * tierWeight;
        }
        double scaleFactor = Math.max(1.0, Math.sqrt(Math.max(1, causal.entryChains().size())));
        double normalizedDeduction = deduction / scaleFactor;
        double clampedRatio = Math.max(0.0, Math.min(1.0, deliveryRatio));
        double deliveryBonus = normalizedDeduction > 0.0 ? 0.0 : (10.0 * clampedRatio);
        double raw = Math.max(1.0, Math.min(100.0, 100.0 - Math.min(90.0, normalizedDeduction) + deliveryBonus));
        return Math.round(raw * 100.0) / 100.0;
    }

    private static final Comparator<ArtifactTriageEntry> PASSING_COMPARATOR =
            Comparator.comparingDouble(ArtifactTriageEntry::compositeScore).reversed()
                    .thenComparingInt(e -> e.confirmedFindingCount() + e.highFindingCount())
                    .thenComparing(Comparator.comparingDouble(ArtifactTriageEntry::causalDeliveryRatio).reversed())
                    .thenComparing(ArtifactTriageEntry::jarSha512)
                    .thenComparing(ArtifactTriageEntry::jarFileName);

      private static List<Path> discoverCandidateJars(Path inputDir) throws IOException {
          if (!Files.exists(inputDir)) {
              throw new IOException("Input path does not exist: " + inputDir);
          }
          if (Files.isRegularFile(inputDir)) {
              String name = inputDir.getFileName() != null
                      ? inputDir.getFileName().toString().toLowerCase(Locale.ROOT)
                      : "";
              if (!name.endsWith(".jar")) {
                  throw new IOException("Input file is not a .jar archive: " + inputDir);
              }
              return List.of(inputDir);
          }
          if (!Files.isDirectory(inputDir)) {
              throw new IOException("Input directory does not exist or is not a directory: " + inputDir);
          }
          List<Path> jars = new ArrayList<>();
          try (Stream<Path> stream = Files.list(inputDir)) {
              stream.filter(Files::isRegularFile)
                      .filter(p -> {
                          String name = p.getFileName().toString().toLowerCase(Locale.ROOT);
                          return name.endsWith(".jar")
                                  && !name.endsWith("-javadoc.jar")
                                  && !name.endsWith("-sources.jar")
                                  && !name.contains("leaffuzz")
                                  && !name.contains("leafsleuth");
                      })
                      .sorted(Comparator.comparing(p -> p.getFileName().toString()))
                      .forEach(jars::add);
          }
          return jars;
      }

    private static void writeOutputsIfConfigured(TriageConfig config, TriageBatchReport report) throws IOException {
        if (config.jsonOut() != null) {
            Path parent = config.jsonOut().toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(config.jsonOut(), report.toJsonReport(), StandardCharsets.UTF_8);
        }
        if (config.csvOut() != null) {
            Path parent = config.csvOut().toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(config.csvOut(), report.toCsvReport(), StandardCharsets.UTF_8);
        }
        if (config.markdownOut() != null) {
            Path parent = config.markdownOut().toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(config.markdownOut(), report.toMarkdownReport(), StandardCharsets.UTF_8);
        }
    }

    private static String formatJsonStringList(List<String> items) {
        if (items == null || items.isEmpty()) {
            return "[]";
        }
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append('"').append(escapeJson(items.get(i))).append('"');
        }
        sb.append(']');
        return sb.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\r", "\\r")
                .replace("\n", "\\n")
                .replace("\t", "\\t");
    }

    private static String escapeCsv(String s) {
        if (s == null) {
            return "";
        }
        if (s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }

    private static String escapeMd(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("|", "\\|").replace("\r", "").replace("\n", " ");
    }
}
