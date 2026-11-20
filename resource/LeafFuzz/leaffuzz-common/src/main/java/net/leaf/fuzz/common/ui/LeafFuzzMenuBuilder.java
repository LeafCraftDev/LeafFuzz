package net.leaf.fuzz.common.ui;

import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.CausalFinding;
import io.github.dailystruggle.menu.api.MenuAction;
import io.github.dailystruggle.menu.api.MenuDescriptor;
import io.github.dailystruggle.menu.api.MenuDescriptor.Fragment;
import io.github.dailystruggle.menu.api.MenuDescriptor.Line;
import io.github.dailystruggle.menu.api.MenuDescriptor.Page;
import net.leaf.fuzz.common.LeafFuzzRuntime;
import net.leaf.fuzz.common.LeafFuzzScorecardReport;
import net.leaf.fuzz.common.LeafFuzzScorecardReport.Verdict;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.LeastPrivilegeFinding;
import net.leaf.sleuth.common.fuzz.DualAudienceMitigationReport;
import net.leaf.sleuth.common.fuzz.LogAndStallSignatureOracle.FaultSignature;
import net.leaf.sleuth.common.resource.ClassRetentionFinding;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Builds WCAG 2.1 dual-surface contrast-validated {@link MenuDescriptor} parchment books and
 * interactive chat scorecards for {@code /fuzz report} and {@code /fuzz check}
 * ({@code ADR-035}, {@code ADR-044}, {@code ADR-063}, {@code ADR-115}, {@code leaffuzz-ADR-001}).
 *
 * <p>Strictly enforces dual-surface color contrast rules audited by
 * {@code io.github.dailystruggle.menu.api.BookContrastValidator}:
 * <ul>
 *   <li><b>Parchment Page Text ({@code #F4E8C1}):</b> Dark foreground codes only ({@code &0},
 *       {@code &1}, {@code &2}, {@code &3}, {@code &4}, {@code &5}, {@code &8}; never {@code &e},
 *       {@code &6}, {@code &a}, {@code &b}, {@code &c}, {@code &d}, {@code &f}, or {@code &7}).</li>
 *   <li><b>Hover Tooltips ({@code #100010} dark box):</b> Light/vibrant foreground codes only
 *       ({@code &f}, {@code &7}, {@code &e}, {@code &6}, {@code &a}, {@code &b}, {@code &c},
 *       {@code &d}; never {@code &0}, {@code &1}, {@code &4}, or {@code &8}).</li>
 * </ul>
 *
 * @governedBy ADR-035
 * @governedBy ADR-044
 * @governedBy ADR-063
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy leaffuzz-ADR-001
 * @trace REQ-SLEUTH-FUZZ-004
 * @trace REQ-SLEUTH-UI-001
 */
public final class LeafFuzzMenuBuilder {

    public LeafFuzzMenuBuilder() {
    }

    /**
     * Builds the multi-page interactive {@code LeafFuzz} QC scorecard book from the latest
     * {@link LeafFuzzScorecardReport} (or a runtime status overview when no QC check has run yet).
     *
     * @param runtime active {@link LeafFuzzRuntime}
     * @return WCAG-compliant parchment book descriptor
     */
    public MenuDescriptor buildScorecardBook(LeafFuzzRuntime runtime) {
        Objects.requireNonNull(runtime, "runtime");
        LeafFuzzScorecardReport card = runtime.latestScorecard();
        if (card != null) {
            return buildScorecardBook(card);
        }
        return buildIdleOverviewBook(runtime);
    }

    /**
     * Builds the multi-page interactive {@code LeafFuzz} QC scorecard book for a completed
     * {@link LeafFuzzScorecardReport}.
     *
     * @param card completed 4-stage QC scorecard
     * @return WCAG-compliant parchment book descriptor
     */
    public MenuDescriptor buildScorecardBook(LeafFuzzScorecardReport card) {
        Objects.requireNonNull(card, "card");
        List<Page> pages = new ArrayList<>();
        pages.add(buildOverviewPage(card));
        if (card.telemetry().hasLiveObservations()) {
            pages.add(buildTelemetryAndActivityPage(card));
        }
        if (!card.leastPrivilegeFindings().isEmpty() || !card.shrunkReproducers().isEmpty()) {
            pages.add(buildSurfaceAndReproducersPage(card));
        }
        if (!card.faultSignatures().isEmpty() || !card.retentionFindings().isEmpty()) {
            pages.add(buildFaultsAndRetentionPage(card));
        }
        if (!card.causalFindings().isEmpty()) {
            pages.add(buildCausalAuditPage(card));
        }

        return new MenuDescriptor(
                "&0&lLeafFuzz QC Report",
                MenuDescriptor.DEFAULT_ROWS,
                pages,
                Map.of("author", "LeafFuzz", "theme", "parchment-dark")
        );
    }

    private MenuDescriptor buildIdleOverviewBook(LeafFuzzRuntime runtime) {
        List<Line> lines = new ArrayList<>();
        lines.add(Line.of(Fragment.plain("&0&l⚡ LeafFuzz QC Suite")));
        lines.add(Line.of(Fragment.plain("&8Cross-Platform Fuzzer & Leak QC")));
        lines.add(Line.of(Fragment.plain(String.format(
                Locale.ROOT,
                "&0JARs: &1%d &8| &0Classes: &1%d",
                runtime.ownershipIndex().indexedJarCount(),
                runtime.ownershipIndex().uniqueClassCount()
        ))));
        lines.add(Line.of(Fragment.plain(String.format(
                Locale.ROOT,
                "&0Personas: &5%d &8| &0GC CPs: &2%d",
                runtime.personaCatalog().size(),
                runtime.retentionScreener().checkpointCount()
        ))));
        lines.add(Line.of(Fragment.plain("&8------------------")));
        lines.add(Line.of(Fragment.plain("&8No QC scorecard run yet.")));
        lines.add(Line.of(new Fragment(
                "&2&l▶ [Run QC Check]",
                "&eClick to prefill /fuzz check target=\n&7Runs all 4 QC stages & writes Markdown report\n&a/fuzz check target=<PluginOrMod>",
                new MenuAction.SuggestInput("/fuzz check target=")
        )));
        lines.add(Line.of(new Fragment(
                "&0&l▶ [Ramp Players (auto)]",
                "&eRamp concurrent players until server instability\n&7Steps 10 -> 25 -> 50 -> 75 -> 100 players across spiral chunks\n&a/fuzz check players=auto",
                new MenuAction.RunCommand("fuzz", "check", "players=auto")
        )));
        lines.add(Line.of(new Fragment(
                "&1&l▶ [Audit Commands]",
                "&eAudit Brigadier/Bukkit command permissions\n&7Compares default vs op exposure\n&a/fuzz check stage=commands target=all",
                new MenuAction.RunCommand("fuzz", "check", "stage=commands", "target=all")
        )));
        lines.add(Line.of(new Fragment(
                "&3&l▶ [Screen Memory Leaks]",
                "&eScreen post-GC class retention slopes\n&a/fuzz check stage=leaks",
                new MenuAction.RunCommand("fuzz", "check", "stage=leaks")
        )));
        lines.add(Line.of(new Fragment(
                "&5&l▶ [Run BIT Self-Test]",
                "&eExecute [FUZZ bit] PBIT/CBIT/IBIT suite\n&a/fuzz test",
                new MenuAction.RunCommand("fuzz", "test")
        )));

        return new MenuDescriptor(
                "&0&lLeafFuzz QC Report",
                MenuDescriptor.DEFAULT_ROWS,
                List.of(new Page(lines)),
                Map.of("author", "LeafFuzz", "theme", "parchment-dark")
        );
    }

    private Page buildOverviewPage(LeafFuzzScorecardReport card) {
        List<Line> lines = new ArrayList<>();
        lines.add(Line.of(Fragment.plain("&0&l⚡ LeafFuzz QC Report")));
        String overallBadge = formatParchmentVerdictBadge(card.overallVerdict());
        String targetHover = "&eTarget: &f" + card.targetName() + "\n"
                + "&7Platform: &b" + card.platformName() + " " + card.serverVersion() + "\n"
                + "&7Indexed JARs: &f" + card.indexedJars() + "\n"
                + "&7Elapsed Time: &a" + card.elapsedMillis() + " ms\n"
                + "&7Report: &fplugins/LeafFuzz/reports/";
        lines.add(Line.of(new Fragment(
                "&0Target: &1" + truncate(card.targetName(), 10) + " " + overallBadge,
                targetHover,
                new MenuAction.SuggestInput("/fuzz check target=" + card.targetName())
        )));
        lines.add(Line.of(Fragment.plain("&8------------------")));

        // Stage 1
        lines.add(Line.of(new Fragment(
                formatParchmentVerdictBadge(card.stage1CommandSurfaceVerdict())
                        + " &01.Cmds: &1" + card.auditedCommands() + " &8(" + card.leastPrivilegeFindings().size() + " warn)",
                "&eStage 1: Command & Least-Privilege Audit\n"
                        + "&7Audited Commands: &f" + card.auditedCommands() + "\n"
                        + "&7Default-Accessible: &b" + card.defaultTierCommands() + "\n"
                        + "&7Exposure Warnings: &e" + card.leastPrivilegeFindings().size() + "\n"
                        + "&a▶ Click to audit command permissions",
                new MenuAction.RunCommand("fuzz", "check", "stage=commands", "target=" + card.targetName())
        )));

        // Stage 2
        LeafFuzzScorecardReport.ExecutionTelemetry tel = card.telemetry();
        lines.add(Line.of(new Fragment(
                formatParchmentVerdictBadge(card.stage2BoundaryFuzzVerdict())
                        + " &02.Fuzz: &1" + card.episodesExecuted() + "ep &8(" + tel.teleportsObserved() + "tp/" + tel.menuSlotsClicked() + "clk)",
                "&eStage 2: Persona Bot & Boundary Fuzzing\n"
                        + "&7Episodes Executed: &f" + card.episodesExecuted() + "\n"
                        + "&7Bots Spawned: &a" + tel.botsSpawned() + " &7| Menus Clicked: &b" + tel.menuSlotsClicked() + "\n"
                        + "&7Teleports Confirmed: &a" + tel.teleportsObserved()
                        + (tel.maxTeleportDistanceBlocks() > 0.0
                        ? String.format(Locale.ROOT, " &7(max &f%.0fb&7)", tel.maxTeleportDistanceBlocks())
                        : "") + "\n"
                        + "&7Minimized Reproducers (ddmin): &c" + card.shrunkReproducers().size(),
                null
        )));

        // Stage 3
        lines.add(Line.of(new Fragment(
                formatParchmentVerdictBadge(card.stage3StallAndExceptionVerdict())
                        + String.format(Locale.ROOT, " &03.MSPT: &1%.1f&8->&5%.1f", tel.idleMsptMean(), tel.fuzzMsptP95()),
                String.format(
                        Locale.ROOT,
                        "&eStage 3: Main-Thread Stall & Exception Guard\n"
                                + "&7Idle MSPT: &a%.2f ms &7(p95 &f%.2f ms&7)\n"
                                + "&7Fuzz MSPT: &e%.2f ms &7(p95 &f%.2f ms&7, max &c%.2f ms&7)\n"
                                + "&7Tick Samples: &f%d &7| Fault Signatures: &c%d\n"
                                + "&a▶ Click to list fault signatures",
                        tel.idleMsptMean(),
                        tel.idleMsptP95(),
                        tel.fuzzMsptMean(),
                        tel.fuzzMsptP95(),
                        tel.fuzzMsptMax(),
                        tel.tickSamplesCollected(),
                        card.faultSignatures().size()
                ),
                new MenuAction.RunCommand("fuzz", "check", "stage=faults")
        )));

        // Stage 4
        lines.add(Line.of(new Fragment(
                formatParchmentVerdictBadge(card.stage4MemoryRetentionVerdict())
                        + " &04.Leaks: &4" + card.retentionFindings().size() + " &8(" + card.checkpointsCaptured() + " CPs)",
                String.format(
                        Locale.ROOT,
                        "&eStage 4: Post-GC Class Retention Screen\n"
                                + "&7GC Checkpoints: &f%d &7| OldGen: &b%.1f -> %.1f MB\n"
                                + "&7Scanned: &f%d &7classes (&f%d &7live instances)\n"
                                + "&7Bonferroni Leaking Classes: &c%d\n"
                                + "&a▶ Click to inspect retention screen",
                        card.checkpointsCaptured(),
                        tel.baselineHeapMb(),
                        tel.finalHeapMb(),
                        tel.totalClassesScanned(),
                        tel.totalInstancesScanned(),
                        card.retentionFindings().size()
                ),
                new MenuAction.RunCommand("fuzz", "check", "stage=leaks")
        )));

        // Stage 5
        lines.add(Line.of(new Fragment(
                formatParchmentVerdictBadge(card.stage5CausalAuditVerdict())
                        + " &05.Causal: &5" + card.causalFindings().size() + " &8(1st/2nd ord)",
                "&eStage 5: Bytecode & Causal Audit\n"
                        + "&7First-Order & Second-Order Findings: &f" + card.causalFindings().size() + "\n"
                        + "&7Format: &bDeclared -> Causal Defect\n"
                        + "&a▶ Click to inspect bytecode causal audit",
                new MenuAction.RunCommand("fuzz", "check", "stage=causal", "target=" + card.targetName())
        )));

        lines.add(Line.of(Fragment.plain("&8------------------")));
        lines.add(new Line(List.of(
                new Fragment(
                        "&2&l[↻ Re-Check]",
                        "&eRe-run 4-stage QC check for &f" + card.targetName() + "\n&a/fuzz check target=" + card.targetName(),
                        new MenuAction.RunCommand("fuzz", "check", "target=" + card.targetName())
                ),
                Fragment.plain(" "),
                new Fragment(
                        "&5&l[⚙ BIT]",
                        "&eRun [FUZZ bit] self-tests\n&a/fuzz test",
                        new MenuAction.RunCommand("fuzz", "test")
                )
        )));

        return new Page(lines);
    }

    private Page buildTelemetryAndActivityPage(LeafFuzzScorecardReport card) {
        LeafFuzzScorecardReport.ExecutionTelemetry tel = card.telemetry();
        List<Line> lines = new ArrayList<>();
        lines.add(Line.of(Fragment.plain("&0&l📊 Live Telemetry")));
        lines.add(Line.of(new Fragment(
                "&0Bots: &1" + tel.botsSpawned() + " &8| &0TPs: &2" + tel.teleportsObserved(),
                String.format(
                        Locale.ROOT,
                        "&eBot, Swarm & Teleport Telemetry\n"
                                + "&7Live ServerPlayer Bots Spawned: &a%d\n"
                                + "&7Concurrent Roster (Peak/Target): &b%d/%d players\n"
                                + "&7Certified Max Stable Players: &a%d players\n"
                                + (tel.instabilityTrigger().isEmpty()
                                ? ""
                                : "&7Breaking Point: &c" + tel.instabilityTrigger() + "\n")
                                + "&7Loaded Chunks / Entities at Peak: &f%d chunks / %d entities\n"
                                + "&7Commands Dispatched: &f%d\n"
                                + "&7Confirmed Teleports (>=4b): &a%d\n"
                                + "&7Max Teleport Distance: &b%.1f blocks",
                        tel.botsSpawned(),
                        tel.peakConcurrentPlayers(),
                        tel.targetConcurrentPlayers(),
                        tel.maxStablePlayers(),
                        tel.loadedChunksAtPeak(),
                        tel.entitiesAtPeak(),
                        tel.commandsDispatched(),
                        tel.teleportsObserved(),
                        tel.maxTeleportDistanceBlocks()
                ),
                null
        )));
        lines.add(Line.of(new Fragment(
                "&0Menus: &3" + tel.menusOpened() + " &8| &0Clicks: &5" + tel.menuSlotsClicked(),
                formatMenuItemsHover(tel.clickedMenuItems()),
                null
        )));
        lines.add(Line.of(new Fragment(
                String.format(Locale.ROOT, "&0MSPT: &2%.1f &8-> &5%.1f", tel.idleMsptMean(), tel.fuzzMsptP95()),
                String.format(
                        Locale.ROOT,
                        "&eMain-Thread Tick Timing\n"
                                + "&7Idle Mean / P95: &a%.2f / %.2f ms\n"
                                + "&7Fuzz Mean / P95 / Max: &e%.2f / %.2f / %.2f ms\n"
                                + "&7Samples Collected: &f%d",
                        tel.idleMsptMean(),
                        tel.idleMsptP95(),
                        tel.fuzzMsptMean(),
                        tel.fuzzMsptP95(),
                        tel.fuzzMsptMax(),
                        tel.tickSamplesCollected()
                ),
                null
        )));
        lines.add(Line.of(new Fragment(
                String.format(Locale.ROOT, "&0Heap: &1%.0f&8->&1%.0fMB", tel.baselineHeapMb(), tel.finalHeapMb()),
                formatHeapCensusHover(tel),
                null
        )));
        lines.add(Line.of(Fragment.plain("&8------------------")));
        int shown = 0;
        for (String cmdSum : tel.commandSummaries()) {
            if (shown >= 5) {
                break;
            }
            lines.add(Line.of(new Fragment(
                    "&0• &1" + truncate(cmdSum, 19),
                    "&eCommand Activity\n&f" + cmdSum,
                    null
            )));
            shown++;
        }
        return new Page(lines);
    }

    private Page buildSurfaceAndReproducersPage(LeafFuzzScorecardReport card) {
        List<Line> lines = new ArrayList<>();
        lines.add(Line.of(Fragment.plain("&0&l🔍 Perms & Reproducers")));
        lines.add(Line.of(Fragment.plain("&8Hover for LuckPerms/ddmin fix")));

        int shown = 0;
        for (LeastPrivilegeFinding f : card.leastPrivilegeFindings()) {
            if (shown >= 4) {
                break;
            }
            String text = "&5[Perm] &0/" + truncate(f.nodeId(), 13);
            String hover = "&e/" + f.nodeId() + " &7(" + f.suspectPluginOrJar() + ")\n"
                    + "&7Exposure: &c" + f.findingKind() + "\n"
                    + "&7Fix: &a" + f.remediationCommand() + "\n"
                    + "&b▶ Click to prefill remediation command";
            lines.add(Line.of(new Fragment(
                    text,
                    hover,
                    new MenuAction.SuggestInput(f.remediationCommand())
            )));
            shown++;
        }

        for (DualAudienceMitigationReport r : card.shrunkReproducers()) {
            if (shown >= 8) {
                break;
            }
            String seq = String.join(" ; ", r.minimalCommandSequence());
            String text = "&4[Repro] &0" + truncate(r.suspectJar(), 12);
            String hover = "&c" + r.signatureId() + "\n"
                    + "&7Suspect Archive: &f" + r.suspectJar() + "\n"
                    + "&7Minimal Trace: &e" + seq + "\n"
                    + r.bisectedNumericThreshold().map(t -> "&7Boundary: &b" + t + "\n").orElse("")
                    + "&7Mitigation: &a" + r.permissionRevokeCommand();
            lines.add(Line.of(new Fragment(
                    text,
                    hover,
                    new MenuAction.SuggestInput(r.permissionRevokeCommand())
            )));
            shown++;
        }

        return new Page(lines);
    }

    private Page buildFaultsAndRetentionPage(LeafFuzzScorecardReport card) {
        List<Line> lines = new ArrayList<>();
        lines.add(Line.of(Fragment.plain("&0&l⚠ Faults & Memory Leaks")));
        lines.add(Line.of(Fragment.plain("&8Hover for stack & OLS R²/p-val")));

        int shown = 0;
        for (FaultSignature sig : card.faultSignatures()) {
            if (shown >= 4) {
                break;
            }
            String text = "&4[" + sig.kind() + "] &0" + truncate(sig.suspectJar(), 13);
            String hover = "&c" + sig.signatureId() + "\n"
                    + "&7Owning Archive: &f" + sig.suspectJar() + "\n"
                    + "&7Top Frame: &e" + sig.topPluginFrame() + "\n"
                    + "&7Occurrences: &b" + sig.occurrences()
                    + (sig.maxDurationMs() > 0.0
                            ? String.format(Locale.ROOT, " &7| Peak Stall: &c%.1f ms", sig.maxDurationMs())
                            : "");
            lines.add(Line.of(new Fragment(
                    text,
                    hover,
                    new MenuAction.RunCommand("fuzz", "check", "stage=faults")
            )));
            shown++;
        }

        for (ClassRetentionFinding rf : card.retentionFindings()) {
            if (shown >= 8) {
                break;
            }
            String simpleCls = simpleClassName(rf.className());
            String text = String.format(
                    Locale.ROOT,
                    "&4[Leak] &0%s &4+%.2f",
                    truncate(simpleCls, 10),
                    rf.slopePerEvent()
            );
            String hover = String.format(
                    Locale.ROOT,
                    "&c%s\n"
                            + "&7Owning Archive: &f%s\n"
                            + "&7Slope: &e+%.2f inst/%s &7(%+.1f KB)\n"
                            + "&7Fit: &aR²=%.3f &7| &bp=%.2e\n"
                            + "&7Instances: &f%d -> %d &7across %d CPs",
                    rf.className(),
                    rf.owningJar(),
                    rf.slopePerEvent(),
                    rf.eventBasis(),
                    rf.netByteGrowth() / 1024.0,
                    rf.rSquared(),
                    rf.pValue(),
                    rf.baselineInstances(),
                    rf.peakInstances(),
                    card.checkpointsCaptured()
            );
            lines.add(Line.of(new Fragment(
                    text,
                    hover,
                    new MenuAction.RunCommand("fuzz", "check", "stage=leaks")
            )));
            shown++;
        }

        return new Page(lines);
    }

    private Page buildCausalAuditPage(LeafFuzzScorecardReport card) {
        List<Line> lines = new ArrayList<>();
        lines.add(Line.of(Fragment.plain("&0&l🧭 Bytecode Causal Audit")));
        lines.add(Line.of(Fragment.plain("&8Declared -> Causal Defect")));

        int shown = 0;
        for (CausalFinding cf : card.causalFindings()) {
            if (shown >= 8) {
                break;
            }
            String text = "&5[O" + cf.order() + ":" + cf.confidencePercent() + "%] &0"
                    + truncate(simpleClassName(cf.entryPointSymbol()), 12);
            String hover = "&e[" + cf.confidenceTier().name() + " " + cf.confidencePercent() + "%] Order "
                    + cf.order() + " — " + cf.kind().name() + "\n"
                    + "&7Artifact: &f" + cf.artifactName() + "\n"
                    + "&7Declared: &a" + cf.declaredSurface() + "\n"
                    + "&7Finding: &c" + cf.causalDefect() + "\n"
                    + "&7Clears When: &b" + cf.clearsWhen()
                    + (cf.llmExplanation().isEmpty() ? "" : "\n&7AST Explanation: &e" + cf.llmExplanation());
            lines.add(Line.of(new Fragment(
                    text,
                    hover,
                    new MenuAction.RunCommand("fuzz", "check", "stage=causal", "target=" + card.targetName())
            )));
            shown++;
        }

        return new Page(lines);
    }

    private static String formatMenuItemsHover(List<String> clickedItems) {
        if (clickedItems == null || clickedItems.isEmpty()) {
            return "&eSalient Menu Items Clicked\n&7(0 items clicked)";
        }
        return "&eSalient Menu Items Clicked\n&b" + String.join("\n&b", clickedItems);
    }

    private static String formatHeapCensusHover(LeafFuzzScorecardReport.ExecutionTelemetry tel) {
        String base = String.format(
                Locale.ROOT,
                "&ePost-GC Histogram Census\n"
                        + "&7OldGen Heap: &b%.1f -> %.1f MB\n"
                        + "&7Classes Scanned: &f%d\n"
                        + "&7Live Instances: &f%d",
                tel.baselineHeapMb(),
                tel.finalHeapMb(),
                tel.totalClassesScanned(),
                tel.totalInstancesScanned()
        );
        if (tel.topTargetClassDeltas().isEmpty()) {
            return base;
        }
        return base + "\n&eClass Deltas:\n&7" + String.join("\n&7", tel.topTargetClassDeltas());
    }

    private static String formatParchmentVerdictBadge(Verdict verdict) {
        if (verdict == null) {
            return "&8[?]";
        }
        return switch (verdict) {
            case PASS -> "&2[PASS]";
            case WARN -> "&5[WARN]";
            case FAIL -> "&4[FAIL]";
        };
    }

    private static String simpleClassName(String fqcn) {
        if (fqcn == null || fqcn.isBlank()) {
            return "Unknown";
        }
        int dot = fqcn.lastIndexOf('.');
        return dot >= 0 && dot + 1 < fqcn.length() ? fqcn.substring(dot + 1) : fqcn;
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) {
            return "";
        }
        return s.length() <= maxLen ? s : s.substring(0, Math.max(1, maxLen - 1)) + "…";
    }
}
