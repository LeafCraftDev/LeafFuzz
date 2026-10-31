package io.github.dailystruggle.rtp.common.bit.config.atlas;

import io.github.dailystruggle.rtp.common.configuration.yaml.RtpYamlConfig;
import io.github.dailystruggle.rtp.common.configuration.yaml.RtpYamlSection;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Three-plane configuration and metadata harvester ({@code leafconfig-ADR-001} Section 1).
 *
 * <p>Operates strictly off the main tick thread ({@code S-005}) to:
 * <ol>
 *   <li><b>Plane 1 (Embedded JAR Introspection):</b> Read-only {@link ZipFile} scan of
 *       {@code plugins/*.jar} and {@code mods/*.jar} for loader descriptors
 *       ({@code plugin.yml}, {@code paper-plugin.yml}, {@code bungee.yml},
 *       {@code velocity-plugin.json}, {@code fabric.mod.json},
 *       {@code META-INF/neoforge.mods.toml}), pristine default configuration files and comments,
 *       and zero-classloading {@link BytecodeConfigScanner} {@code READ_BY_CLASS} / enum edges.</li>
 *   <li><b>Plane 2 (Live Server Disk Working Tree):</b> Scans live engine and plugin configuration
 *       files on disk, computes {@code jar_default_value} vs. {@code live_disk_value} diffs, and
 *       restores author comments stripped by third-party {@code JavaPlugin#saveConfig()} calls.</li>
 * </ol>
 *
 * @governedBy ADR-115
 * @governedBy ADR-126
 * @governedBy leafconfig-ADR-001
 * @governedBy leafconfig-ADR-002
 * @trace REQ-CFG-ATLAS-001
 * @trace REQ-CFG-ATLAS-003
 */
public final class JarConfigScanner {

    private static final int MAX_RESOURCE_BYTES = 1024 * 1024; // 1 MiB cap per embedded config/class
    private static final int MAX_CLASSES_PER_JAR = 4096;

    private static final Set<String> DESCRIPTOR_FILES = Set.of(
            "plugin.yml",
            "paper-plugin.yml",
            "bungee.yml",
            "velocity-plugin.json",
            "fabric.mod.json",
            "META-INF/neoforge.mods.toml",
            "META-INF/mods.toml"
    );

    private static final Pattern JSON_ID_RE = Pattern.compile("\"id\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern JSON_NAME_RE = Pattern.compile("\"name\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern JSON_VERSION_RE = Pattern.compile("\"version\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern JSON_HOMEPAGE_RE = Pattern.compile("\"(?:homepage|url|website)\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern TOML_MOD_ID_RE = Pattern.compile("(?m)^\\s*modId\\s*=\\s*\"([^\"]+)\"");
    private static final Pattern TOML_DISPLAY_NAME_RE = Pattern.compile("(?m)^\\s*displayName\\s*=\\s*\"([^\"]+)\"");
    private static final Pattern TOML_VERSION_RE = Pattern.compile("(?m)^\\s*version\\s*=\\s*\"([^\"]+)\"");

    /** Reload orchestration strategy for an installed artifact ({@code leafconfig-ADR-002} Section 5). */
    public enum ReloadStrategy {
        NATIVE_SPI,
        COMMAND_DISPATCH,
        BUKKIT_FILECONFIG_INJECT,
        DEFER_UNTIL_SHUTDOWN
    }

    /**
     * Structured command metadata harvested from {@code plugin.yml} or {@code paper-plugin.yml}
     * in the single-pass JAR scan ({@code leafguide-ADR-001}).
     *
     * @param name              canonical top-level command label (without leading slash)
     * @param pluginDisplayName owning plugin or mod display name
     * @param description       author-supplied command description
     * @param usage             usage template (e.g. {@code /rtp [world]})
     * @param aliases           registered command aliases
     * @param permission        declared permission node, or empty if undeclared
     * @param permissionDefault declared permission default ({@code true}, {@code op}, {@code not op}, {@code false}, or empty)
     */
    public record CommandDescriptor(
            String name,
            String pluginDisplayName,
            String description,
            String usage,
            List<String> aliases,
            String permission,
            String permissionDefault
    ) {
        public CommandDescriptor {
            Objects.requireNonNull(name, "name");
            pluginDisplayName = pluginDisplayName == null ? "" : pluginDisplayName;
            description = description == null ? "" : description;
            usage = (usage == null || usage.isBlank()) ? "/" + name : usage;
            aliases = aliases == null ? List.of() : List.copyOf(aliases);
            permission = permission == null ? "" : permission;
            permissionDefault = permissionDefault == null ? "" : permissionDefault;
        }
    }

    /**
     * Harvested artifact metadata and Plane 1 resources from a single plugin/mod JAR or engine baseline.
     *
     * @param artifactId           canonical artifact identifier (e.g. {@code plugin:leafrtp}, {@code engine:paper})
     * @param displayName          human-readable plugin or engine name
     * @param version              version string
     * @param loaderFamily         loader family ({@code paper}, {@code bukkit}, {@code velocity}, {@code fabric}, {@code neoforge}, {@code engine})
     * @param jarSha512            hex SHA-512 digest of the source JAR, or empty for engine baselines
     * @param docSourceUrl         website or documentation URL from descriptor
     * @param commands             registered top-level command names
     * @param permissions          declared permission nodes
     * @param dependencies         declared plugin dependencies ({@code depend} + {@code softdepend})
     * @param reloadStrategy       classified reload strategy ({@code leafconfig-ADR-002} §5)
     * @param embeddedConfigs      map of relative config path to pristine Plane 1 file content
     * @param readByClassIndex     map of config key path to consuming Java class names ({@code READ_BY_CLASS})
     * @param discoveredEnums      map of enum binary class name to declared enum constant names
     * @param savesConfigOnDisable whether any class in the JAR calls {@code saveConfig()} inside {@code onDisable()}
     * @param keyCallSiteIndex     map of config key path to bytecode call-site descriptors
     * @param commandDescriptors   structured command metadata harvested from descriptor files
     * @param embeddedPlayerDocs   embedded player-facing book/guide resources (Patchouli, Lavender, {@code book.txt}, {@code rules.txt})
     */
    public record HarvestedArtifact(
            String artifactId,
            String displayName,
            String version,
            String loaderFamily,
            String jarSha512,
            String docSourceUrl,
            List<String> commands,
            List<String> permissions,
            List<String> dependencies,
            ReloadStrategy reloadStrategy,
            Map<String, String> embeddedConfigs,
            Map<String, Set<String>> readByClassIndex,
            Map<String, List<String>> discoveredEnums,
            boolean savesConfigOnDisable,
            Map<String, List<BytecodeConfigScanner.KeyCallSite>> keyCallSiteIndex,
            List<CommandDescriptor> commandDescriptors,
            Map<String, String> embeddedPlayerDocs
    ) {
        public HarvestedArtifact(
                String artifactId,
                String displayName,
                String version,
                String loaderFamily,
                String jarSha512,
                String docSourceUrl,
                List<String> commands,
                List<String> permissions,
                List<String> dependencies,
                ReloadStrategy reloadStrategy,
                Map<String, String> embeddedConfigs,
                Map<String, Set<String>> readByClassIndex,
                Map<String, List<String>> discoveredEnums,
                boolean savesConfigOnDisable
        ) {
            this(
                    artifactId,
                    displayName,
                    version,
                    loaderFamily,
                    jarSha512,
                    docSourceUrl,
                    commands,
                    permissions,
                    dependencies,
                    reloadStrategy,
                    embeddedConfigs,
                    readByClassIndex,
                    discoveredEnums,
                    savesConfigOnDisable,
                    Map.of(),
                    List.of(),
                    Map.of()
            );
        }

        public HarvestedArtifact(
                String artifactId,
                String displayName,
                String version,
                String loaderFamily,
                String jarSha512,
                String docSourceUrl,
                List<String> commands,
                List<String> permissions,
                List<String> dependencies,
                ReloadStrategy reloadStrategy,
                Map<String, String> embeddedConfigs,
                Map<String, Set<String>> readByClassIndex,
                Map<String, List<String>> discoveredEnums,
                boolean savesConfigOnDisable,
                Map<String, List<BytecodeConfigScanner.KeyCallSite>> keyCallSiteIndex
        ) {
            this(
                    artifactId,
                    displayName,
                    version,
                    loaderFamily,
                    jarSha512,
                    docSourceUrl,
                    commands,
                    permissions,
                    dependencies,
                    reloadStrategy,
                    embeddedConfigs,
                    readByClassIndex,
                    discoveredEnums,
                    savesConfigOnDisable,
                    keyCallSiteIndex,
                    List.of(),
                    Map.of()
            );
        }

        public HarvestedArtifact {
            Objects.requireNonNull(artifactId, "artifactId");
            Objects.requireNonNull(displayName, "displayName");
            version = version == null ? "unknown" : version;
            loaderFamily = loaderFamily == null ? "bukkit" : loaderFamily;
            jarSha512 = jarSha512 == null ? "" : jarSha512;
            docSourceUrl = docSourceUrl == null ? "" : docSourceUrl;
            commands = commands == null ? List.of() : List.copyOf(commands);
            permissions = permissions == null ? List.of() : List.copyOf(permissions);
            dependencies = dependencies == null ? List.of() : List.copyOf(dependencies);
            reloadStrategy = reloadStrategy == null ? ReloadStrategy.BUKKIT_FILECONFIG_INJECT : reloadStrategy;
            embeddedConfigs = embeddedConfigs == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(embeddedConfigs));
            readByClassIndex = readByClassIndex == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(readByClassIndex));
            discoveredEnums = discoveredEnums == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(discoveredEnums));
            keyCallSiteIndex = keyCallSiteIndex == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(keyCallSiteIndex));
            commandDescriptors = commandDescriptors == null ? List.of() : List.copyOf(commandDescriptors);
            embeddedPlayerDocs = embeddedPlayerDocs == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(embeddedPlayerDocs));
        }
    }

    private JarConfigScanner() {
    }

    /**
     * Scans a plugin or mod {@code .jar} archive off-thread using read-only {@link ZipFile} and
     * {@link BytecodeConfigScanner} without loading any class.
     *
     * @param jarPath path to the {@code .jar} file
     * @return harvested Plane 1 artifact record
     * @throws IOException if the archive cannot be read
     */
    public static HarvestedArtifact scanJar(Path jarPath) throws IOException {
        Objects.requireNonNull(jarPath, "jarPath");
        String sha512 = computeSha512Hex(jarPath);

        Map<String, String> descriptors = new LinkedHashMap<>();
        Map<String, String> embeddedConfigs = new LinkedHashMap<>();
        Map<String, String> embeddedPlayerDocs = new LinkedHashMap<>();
        List<BytecodeConfigScanner.ClassScanResult> classResults = new ArrayList<>();
        Map<String, List<String>> enumMap = new LinkedHashMap<>();
        boolean savesOnDisable = false;

        try (ZipFile zip = new ZipFile(jarPath.toFile())) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            int scannedClasses = 0;
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                String name = entry.getName();
                long size = entry.getSize();
                if (size > MAX_RESOURCE_BYTES) {
                    continue;
                }

                if (DESCRIPTOR_FILES.contains(name)) {
                    byte[] bytes = readBoundedBytes(zip, entry);
                    if (bytes != null) {
                        descriptors.put(name, new String(bytes, StandardCharsets.UTF_8));
                    }
                } else if (isCandidatePlayerDocResource(name)) {
                    byte[] bytes = readBoundedBytes(zip, entry);
                    if (bytes != null) {
                        String text = new String(bytes, StandardCharsets.UTF_8);
                        embeddedPlayerDocs.put(name, text);
                        if (isCandidateConfigResource(name)) {
                            embeddedConfigs.put(name, text);
                        }
                    }
                } else if (isCandidateConfigResource(name)) {
                    byte[] bytes = readBoundedBytes(zip, entry);
                    if (bytes != null) {
                        embeddedConfigs.put(name, new String(bytes, StandardCharsets.UTF_8));
                    }
                } else if (name.endsWith(".class") && scannedClasses < MAX_CLASSES_PER_JAR && !isShadedLibraryClass(name)) {
                    byte[] bytes = readBoundedBytes(zip, entry);
                    if (bytes != null) {
                        scannedClasses++;
                        BytecodeConfigScanner.ClassScanResult res = BytecodeConfigScanner.scanClassBytes(bytes);
                        if (res != null) {
                            classResults.add(res);
                            if (res.isEnum() && !res.enumConstants().isEmpty()) {
                                enumMap.put(res.className(), res.enumConstants());
                            }
                            if (res.hasSaveConfigOnDisable()) {
                                savesOnDisable = true;
                            }
                        }
                    }
                }
            }
        }

        DescriptorMeta meta = parseDescriptorMetadata(descriptors, jarPath.getFileName().toString());
        Map<String, Set<String>> readByClass = BytecodeConfigScanner.buildReadByClassIndex(classResults);
        Map<String, List<BytecodeConfigScanner.KeyCallSite>> keyCallSites = BytecodeConfigScanner.buildKeyCallSiteIndex(classResults);
        ReloadStrategy reloadStrategy = classifyReloadStrategy(meta, savesOnDisable);

        return new HarvestedArtifact(
                meta.artifactId,
                meta.displayName,
                meta.version,
                meta.loaderFamily,
                sha512,
                meta.website,
                meta.commands,
                meta.permissions,
                meta.dependencies,
                reloadStrategy,
                embeddedConfigs,
                readByClass,
                enumMap,
                savesOnDisable,
                keyCallSites,
                meta.commandDescriptors,
                embeddedPlayerDocs
        );
    }

    /**
     * Restores author comments from a pristine Plane 1 YAML template onto a live Plane 2 disk YAML
     * document whose comments were stripped by {@code JavaPlugin#saveConfig()} ({@code leafconfig-ADR-001} §1 &amp; §4).
     *
     * <p>Preserves all live disk scalar/list values and any keys added on disk while re-attaching
     * missing block comments from {@code jarDefaultYaml}.
     *
     * @param jarDefaultYaml pristine YAML content from inside the plugin JAR
     * @param liveDiskYaml   live YAML content on disk (potentially comment-stripped)
     * @return merged YAML string with live values and restored author comments
     */
    public static String restoreStrippedComments(String jarDefaultYaml, String liveDiskYaml) {
        if (liveDiskYaml == null || liveDiskYaml.isBlank()) {
            return jarDefaultYaml == null ? "" : jarDefaultYaml;
        }
        if (jarDefaultYaml == null || jarDefaultYaml.isBlank()) {
            return liveDiskYaml;
        }
        try {
            RtpYamlConfig defaults = RtpYamlConfig.parse(jarDefaultYaml);
            RtpYamlConfig live = RtpYamlConfig.parse(liveDiskYaml);
            for (String key : defaults.getKeys(true)) {
                if (!live.contains(key)) {
                    continue;
                }
                String liveComment = live.getComment(key);
                String defaultComment = defaults.getComment(key);
                if ((liveComment == null || liveComment.isBlank())
                        && defaultComment != null && !defaultComment.isBlank()) {
                    live.setComment(key, defaultComment);
                }
            }
            return live.saveToString();
        } catch (RuntimeException e) {
            return liveDiskYaml;
        }
    }

    /**
     * Counts how many comments would be restored on {@code liveDiskYaml} from {@code jarDefaultYaml}.
     *
     * @param jarDefaultYaml pristine Plane 1 YAML
     * @param liveDiskYaml   live Plane 2 YAML
     * @return number of keys in {@code liveDiskYaml} missing comments that exist in {@code jarDefaultYaml}
     */
    public static int countRestorableComments(String jarDefaultYaml, String liveDiskYaml) {
        if (jarDefaultYaml == null || jarDefaultYaml.isBlank() || liveDiskYaml == null || liveDiskYaml.isBlank()) {
            return 0;
        }
        try {
            RtpYamlConfig defaults = RtpYamlConfig.parse(jarDefaultYaml);
            RtpYamlConfig live = RtpYamlConfig.parse(liveDiskYaml);
            int count = 0;
            for (String key : defaults.getKeys(true)) {
                if (!live.contains(key)) continue;
                String liveComment = live.getComment(key);
                String defComment = defaults.getComment(key);
                if ((liveComment == null || liveComment.isBlank()) && defComment != null && !defComment.isBlank()) {
                    count++;
                }
            }
            return count;
        } catch (RuntimeException e) {
            return 0;
        }
    }

    private static boolean isCandidatePlayerDocResource(String entryName) {
        String low = entryName.toLowerCase(Locale.ROOT);
        if (low.startsWith("assets/") && (low.contains("/patchouli_books/") || low.contains("/lavender/entries/")
                || low.contains("/guidebook/") || low.contains("/lexicon/"))) {
            return low.endsWith(".json") || low.endsWith(".md") || low.endsWith(".txt");
        }
        if (low.startsWith("META-INF/") || low.startsWith("net/") || low.startsWith("com/")
                || low.startsWith("org/") || low.startsWith("io/")) {
            return false;
        }
        String fileName = low.contains("/") ? low.substring(low.lastIndexOf('/') + 1) : low;
        return "book.txt".equals(fileName)
                || "rules.txt".equals(fileName)
                || "motd.txt".equals(fileName)
                || "info.txt".equals(fileName)
                || "help.txt".equals(fileName)
                || "custom.txt".equals(fileName)
                || (low.startsWith("books/") && (low.endsWith(".yml") || low.endsWith(".yaml") || low.endsWith(".txt")));
    }

    private static boolean isCandidateConfigResource(String entryName) {
        if (entryName.startsWith("META-INF/") || entryName.startsWith("lang/") || entryName.startsWith("assets/")
                || entryName.startsWith("data/") || entryName.startsWith("net/") || entryName.startsWith("com/")
                || entryName.startsWith("org/") || entryName.startsWith("io/")) {
            return false;
        }
        String fileName = entryName.contains("/") ? entryName.substring(entryName.lastIndexOf('/') + 1) : entryName;
        if (fileName.startsWith(".") || DESCRIPTOR_FILES.contains(entryName)
                || "pack.mcmeta".equals(fileName) || "fabric.mod.json".equals(fileName)) {
            return false;
        }
        String low = fileName.toLowerCase(Locale.ROOT);
        return low.endsWith(".yml") || low.endsWith(".yaml") || low.endsWith(".toml") || low.endsWith(".properties");
    }

    private static boolean isShadedLibraryClass(String entryName) {
        return entryName.startsWith("META-INF/")
                || entryName.startsWith("org/slf4j/")
                || entryName.startsWith("com/google/")
                || entryName.startsWith("org/yaml/")
                || entryName.startsWith("org/jetbrains/")
                || entryName.startsWith("kotlin/")
                || entryName.startsWith("io/netty/");
    }

    private static ReloadStrategy classifyReloadStrategy(DescriptorMeta meta, boolean savesOnDisable) {
        String lowerId = meta.artifactId.toLowerCase(Locale.ROOT);
        if (lowerId.startsWith("plugin:leaf")) {
            return ReloadStrategy.NATIVE_SPI;
        }
        if (savesOnDisable) {
            return ReloadStrategy.DEFER_UNTIL_SHUTDOWN;
        }
        if (!meta.commands.isEmpty()) {
            return ReloadStrategy.COMMAND_DISPATCH;
        }
        return ReloadStrategy.BUKKIT_FILECONFIG_INJECT;
    }

    private record DescriptorMeta(
            String artifactId,
            String displayName,
            String version,
            String loaderFamily,
            String website,
            List<String> commands,
            List<String> permissions,
            List<String> dependencies,
            List<CommandDescriptor> commandDescriptors
    ) {
    }

    private static DescriptorMeta parseDescriptorMetadata(Map<String, String> descriptors, String fallbackJarName) {
        String yamlDesc = descriptors.getOrDefault("paper-plugin.yml", descriptors.get("plugin.yml"));
        if (yamlDesc == null) {
            yamlDesc = descriptors.get("bungee.yml");
        }
        if (yamlDesc != null) {
            try {
                RtpYamlConfig yml = RtpYamlConfig.parse(yamlDesc);
                String rawName = yml.getString("name", stripJarExtension(fallbackJarName));
                String version = yml.getString("version", "1.0.0");
                String website = yml.getString("website", "");
                String loader = descriptors.containsKey("paper-plugin.yml") ? "paper"
                        : (descriptors.containsKey("bungee.yml") ? "bungee" : "bukkit");

                List<String> perms = new ArrayList<>();
                Map<String, String> permDefaults = new LinkedHashMap<>();
                RtpYamlSection permSec = yml.getConfigurationSection("permissions");
                if (permSec != null) {
                    for (String permKey : permSec.getKeys(false)) {
                        perms.add(permKey);
                        String defVal = permSec.getString(permKey + ".default", "");
                        if (defVal != null && !defVal.isBlank()) {
                            permDefaults.put(permKey, defVal.trim().toLowerCase(Locale.ROOT));
                        }
                    }
                }

                List<String> commands = new ArrayList<>();
                List<CommandDescriptor> commandDescriptors = new ArrayList<>();
                RtpYamlSection cmdSec = yml.getConfigurationSection("commands");
                if (cmdSec != null) {
                    for (String cmdName : cmdSec.getKeys(false)) {
                        commands.add(cmdName);
                        String desc = cmdSec.getString(cmdName + ".description", "");
                        String usage = cmdSec.getString(cmdName + ".usage", "/" + cmdName);
                        List<String> aliases = new ArrayList<>(cmdSec.getStringList(cmdName + ".aliases"));
                        if (aliases.isEmpty()) {
                            String singleAlias = cmdSec.getString(cmdName + ".aliases", "");
                            if (singleAlias != null && !singleAlias.isBlank() && !singleAlias.startsWith("[")) {
                                aliases.add(singleAlias.trim());
                            }
                        }
                        String perm = cmdSec.getString(cmdName + ".permission", "");
                        String permDef = "";
                        if (perm != null && !perm.isBlank()) {
                            permDef = permDefaults.getOrDefault(perm, "");
                        }
                        if (permDef.isEmpty()) {
                            permDef = cmdSec.getString(cmdName + ".permission-default", "");
                        }
                        commandDescriptors.add(new CommandDescriptor(
                                cmdName,
                                rawName,
                                desc == null ? "" : desc,
                                usage == null ? "/" + cmdName : usage,
                                aliases,
                                perm == null ? "" : perm,
                                permDef == null ? "" : permDef
                        ));
                    }
                }

                Set<String> deps = new LinkedHashSet<>();
                deps.addAll(yml.getStringList("depend"));
                deps.addAll(yml.getStringList("softdepend"));

                String slug = normalizeSlug(rawName);
                return new DescriptorMeta(
                        "plugin:" + slug,
                        rawName,
                        version,
                        loader,
                        website,
                        commands,
                        perms,
                        new ArrayList<>(deps),
                        commandDescriptors
                );
            } catch (RuntimeException ignored) {
            }
        }

        if (descriptors.containsKey("velocity-plugin.json")) {
            String json = descriptors.get("velocity-plugin.json");
            String id = extractRegex(JSON_ID_RE, json, stripJarExtension(fallbackJarName));
            String name = extractRegex(JSON_NAME_RE, json, id);
            String ver = extractRegex(JSON_VERSION_RE, json, "1.0.0");
            String url = extractRegex(JSON_HOMEPAGE_RE, json, "");
            return new DescriptorMeta("plugin:" + normalizeSlug(id), name, ver, "velocity", url, List.of(), List.of(), List.of(), List.of());
        }

        if (descriptors.containsKey("fabric.mod.json")) {
            String json = descriptors.get("fabric.mod.json");
            String id = extractRegex(JSON_ID_RE, json, stripJarExtension(fallbackJarName));
            String name = extractRegex(JSON_NAME_RE, json, id);
            String ver = extractRegex(JSON_VERSION_RE, json, "1.0.0");
            String url = extractRegex(JSON_HOMEPAGE_RE, json, "");
            return new DescriptorMeta("mod:" + normalizeSlug(id), name, ver, "fabric", url, List.of(), List.of(), List.of(), List.of());
        }

        String toml = descriptors.getOrDefault("META-INF/neoforge.mods.toml", descriptors.get("META-INF/mods.toml"));
        if (toml != null) {
            String id = extractRegex(TOML_MOD_ID_RE, toml, stripJarExtension(fallbackJarName));
            String name = extractRegex(TOML_DISPLAY_NAME_RE, toml, id);
            String ver = extractRegex(TOML_VERSION_RE, toml, "1.0.0");
            return new DescriptorMeta("mod:" + normalizeSlug(id), name, ver, "neoforge", "", List.of(), List.of(), List.of(), List.of());
        }

        String fallbackName = stripJarExtension(fallbackJarName);
        return new DescriptorMeta(
                "plugin:" + normalizeSlug(fallbackName),
                fallbackName,
                "unknown",
                "bukkit",
                "",
                List.of(),
                List.of(),
                List.of(),
                List.of()
        );
    }

    private static String extractRegex(Pattern pattern, String input, String fallback) {
        if (input == null) return fallback;
        Matcher m = pattern.matcher(input);
        return m.find() ? m.group(1).trim() : fallback;
    }

    private static String stripJarExtension(String fileName) {
        if (fileName == null) return "unknown";
        String base = fileName.endsWith(".jar") ? fileName.substring(0, fileName.length() - 4) : fileName;
        int dashVer = base.indexOf('-');
        return dashVer > 0 ? base.substring(0, dashVer) : base;
    }

    static String normalizeSlug(String raw) {
        if (raw == null || raw.isBlank()) return "unknown";
        String cleaned = raw.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9_-]", "");
        return cleaned.isEmpty() ? "unknown" : cleaned;
    }

    private static byte[] readBoundedBytes(ZipFile zip, ZipEntry entry) throws IOException {
        try (InputStream in = zip.getInputStream(entry);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int total = 0;
            int r;
            while ((r = in.read(buf)) != -1) {
                total += r;
                if (total > MAX_RESOURCE_BYTES) {
                    return null;
                }
                out.write(buf, 0, r);
            }
            return out.toByteArray();
        }
    }

    static String computeSha512Hex(Path path) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            try (InputStream in = Files.newInputStream(path)) {
                byte[] buf = new byte[8192];
                int r;
                while ((r = in.read(buf)) != -1) {
                    md.update(buf, 0, r);
                }
            }
            return HexFormat.of().formatHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-512 unavailable", e);
        }
    }
}
