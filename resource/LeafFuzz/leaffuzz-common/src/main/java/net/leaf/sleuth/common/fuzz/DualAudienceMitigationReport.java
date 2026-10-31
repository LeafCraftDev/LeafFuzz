package net.leaf.sleuth.common.fuzz;

import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandNode;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandTree;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Dual-audience diagnostic and configuration report emitted after minimizing a reproducing
 * command/lifecycle sequence ({@code ADR-125}, {@code leafsleuth-ADR-006}).
 *
 * <p>Provides both an immediate operator configuration workaround ({@code commands.yml} alias
 * override and LuckPerms permission adjustment) and a concise plugin-author reproducer summary
 * containing the attributed JAR, minimal command sequence, follow-up lifecycle shape, and
 * bisected numeric boundary threshold.
 *
 * @param signatureId               deduplicated fault or retention signature ID
 * @param suspectJar                owning plugin JAR attributed via {@link JarClassOwnershipIndex}
 * @param minimalCommandSequence    1-minimal command sequence produced by {@link FuzzActionShrinker#ddmin}
 * @param followUpShape             reproducing lifecycle follow-up shape (e.g. {@code "quit_lt1s"})
 * @param bisectedNumericThreshold  optional bisected numeric argument threshold (e.g. {@code "n >= 256"})
 * @param commandsYmlOverrideSnippet ready-to-paste {@code commands.yml} alias override snippet
 * @param permissionRevokeCommand   ready-to-run LuckPerms permission command for the default group
 * @param authorReproducerSummary   concise issue report summary for the plugin author
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy ADR-129
 * @governedBy leafsleuth-ADR-006
 * @trace REQ-SLEUTH-FUZZ-004
 */
public record DualAudienceMitigationReport(
        String signatureId,
        String suspectJar,
        List<String> minimalCommandSequence,
        String followUpShape,
        Optional<String> bisectedNumericThreshold,
        String commandsYmlOverrideSnippet,
        String permissionRevokeCommand,
        String authorReproducerSummary
) {
    public DualAudienceMitigationReport {
        Objects.requireNonNull(signatureId, "signatureId");
        suspectJar = (suspectJar == null || suspectJar.isBlank()) ? "server" : suspectJar.trim();
        minimalCommandSequence = minimalCommandSequence == null ? List.of() : List.copyOf(minimalCommandSequence);
        followUpShape = (followUpShape == null || followUpShape.isBlank()) ? "repeat" : followUpShape.trim();
        bisectedNumericThreshold = bisectedNumericThreshold == null ? Optional.empty() : bisectedNumericThreshold;
        commandsYmlOverrideSnippet = commandsYmlOverrideSnippet == null ? "" : commandsYmlOverrideSnippet;
        permissionRevokeCommand = permissionRevokeCommand == null ? "" : permissionRevokeCommand;
        authorReproducerSummary = authorReproducerSummary == null ? "" : authorReproducerSummary;
    }

    /**
     * Builds a {@link DualAudienceMitigationReport} from a minimized command trace, suspect JAR,
     * and optional {@link CommandTree} metadata.
     *
     * @param signatureId              fault or leak signature ID
     * @param suspectJar               attributed plugin JAR name
     * @param minimalCommandSequence   minimized command lines
     * @param followUpShape            lifecycle follow-up shape
     * @param bisectedNumericThreshold optional bisected numeric threshold string
     * @param node                     optional command node in {@code tree}
     * @param tree                     optional command tree for alias and permission resolution
     * @return constructed {@link DualAudienceMitigationReport}
     */
    public static DualAudienceMitigationReport build(
            String signatureId,
            String suspectJar,
            List<String> minimalCommandSequence,
            String followUpShape,
            Optional<String> bisectedNumericThreshold,
            CommandNode node,
            CommandTree tree
    ) {
        String cleanSig = (signatureId == null || signatureId.isBlank()) ? "fault:unknown" : signatureId.trim();
        String cleanJar = (suspectJar == null || suspectJar.isBlank()) ? "server" : suspectJar.trim();
        List<String> cmds = minimalCommandSequence != null ? List.copyOf(minimalCommandSequence) : List.of();
        String shape = (followUpShape == null || followUpShape.isBlank()) ? "repeat" : followUpShape.trim();
        Optional<String> threshold = bisectedNumericThreshold != null ? bisectedNumericThreshold : Optional.empty();

        String rootLiteral = resolveRootLiteral(cmds, node);
        List<String> aliases = resolveAliases(rootLiteral, node, tree);
        String permissionNode = resolvePermissionNode(rootLiteral, cleanJar, node, tree);

        String commandsYml = buildCommandsYmlSnippet(aliases);
        String lpCommand = "lp group default permission set " + permissionNode + " false";
        String authorSummary = buildAuthorSummary(cleanSig, cleanJar, cmds, shape, threshold);

        return new DualAudienceMitigationReport(
                cleanSig,
                cleanJar,
                cmds,
                shape,
                threshold,
                commandsYml,
                lpCommand,
                authorSummary
        );
    }

    private static String resolveRootLiteral(List<String> cmds, CommandNode node) {
        if (node != null && node.rootId() != null && !node.rootId().isBlank()) {
            return CommandSurfaceAuditor.splitNamespace(node.rootId())[1];
        }
        if (!cmds.isEmpty()) {
            String first = cmds.get(0).trim();
            if (first.startsWith("/")) {
                first = first.substring(1).trim();
            }
            String[] parts = first.split("\\s+", 2);
            if (parts.length > 0 && !parts[0].isEmpty()) {
                return CommandSurfaceAuditor.splitNamespace(parts[0].toLowerCase(Locale.ROOT))[1];
            }
        }
        return "command";
    }

    private static List<String> resolveAliases(String rootLiteral, CommandNode node, CommandTree tree) {
        Set<String> aliases = new LinkedHashSet<>();
        aliases.add(rootLiteral);
        if (node != null) {
            for (String a : node.aliases()) {
                if (a != null && !a.isBlank()) {
                    aliases.add(a.trim().split("\\s+", 2)[0]);
                }
            }
        }
        if (tree != null) {
            CommandNode rootNode = tree.nodes().get(rootLiteral);
            if (rootNode != null) {
                for (String a : rootNode.aliases()) {
                    if (a != null && !a.isBlank()) {
                        aliases.add(a.trim().split("\\s+", 2)[0]);
                    }
                }
            }
        }
        return new ArrayList<>(aliases);
    }

    private static String resolvePermissionNode(
            String rootLiteral,
            String suspectJar,
            CommandNode node,
            CommandTree tree
    ) {
        if (node != null && node.permission() != null && !node.permission().isBlank()) {
            return node.permission();
        }
        if (tree != null) {
            CommandNode rootNode = tree.nodes().get(rootLiteral);
            if (rootNode != null && rootNode.permission() != null && !rootNode.permission().isBlank()) {
                return rootNode.permission();
            }
        }
        String pluginStem = suspectJar.toLowerCase(Locale.ROOT);
        if (pluginStem.endsWith(".jar")) {
            pluginStem = pluginStem.substring(0, pluginStem.length() - 4);
        }
        int dash = pluginStem.indexOf('-');
        if (dash > 0) {
            pluginStem = pluginStem.substring(0, dash);
        }
        if (pluginStem.isEmpty() || "server".equals(pluginStem) || "shared".equals(pluginStem)) {
            pluginStem = rootLiteral;
        }
        return pluginStem + ".command." + rootLiteral;
    }

    private static String buildCommandsYmlSnippet(List<String> aliases) {
        StringBuilder sb = new StringBuilder();
        sb.append("aliases:\n");
        for (String alias : aliases) {
            sb.append("  ").append(alias).append(": []\n");
        }
        return sb.toString().trim();
    }

    private static String buildAuthorSummary(
            String signatureId,
            String suspectJar,
            List<String> cmds,
            String followUpShape,
            Optional<String> threshold
    ) {
        StringBuilder sb = new StringBuilder();
        sb.append("Signature: ").append(signatureId)
                .append(" | Suspect JAR: ").append(suspectJar)
                .append(" | Steps: ").append(cmds.isEmpty() ? "<none>" : String.join(" -> ", cmds))
                .append(" | Follow-up: ").append(followUpShape);
        threshold.ifPresent(t -> sb.append(" | Boundary: ").append(t));
        return sb.toString();
    }
}
