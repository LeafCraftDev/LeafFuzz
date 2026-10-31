package io.github.dailystruggle.rtp.common.bit.config.atlas;

import io.github.dailystruggle.rtp.common.configuration.yaml.RtpYamlConfig;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Zero-classloading JVM {@code .class} causal graph mapper and two-order claim delivery auditor
 * ({@code leaffuzz-ADR-001}, {@code ADR-125}, {@code corpus-atlas-ADR-002}).
 *
 * <p>Extracts three entry-point families from compiled plugin/mod archives without loading classes:
 * <ol>
 *   <li><b>Commands ({@link EntryPointKind#COMMAND}):</b> {@code onCommand}, {@code CommandExecutor},
 *       {@code CommandsAPICommand}, and Brigadier command lambdas.</li>
 *   <li><b>Events ({@link EntryPointKind#EVENT}):</b> {@code @EventHandler} and
 *       {@code @SubscribeEvent} listeners, distinguishing unconditional registration
 *       ({@link ListenerRegistrationMode#REGISTERED_UNCONDITIONAL}), generalized config/branch-gated
 *       registration ({@link ListenerRegistrationMode#REGISTERED_CONFIG_GATED} across inline
 *       {@code if} blocks, early-return guards, and gated helper methods), and unregistered dead
 *       listeners ({@link ListenerRegistrationMode#UNREGISTERED}).</li>
 *   <li><b>Suppliers &amp; Async Lambdas ({@link EntryPointKind#SUPPLIER}):</b> {@code Supplier#get},
 *       {@code Callable#call}, {@code Runnable#run}, {@code Consumer#accept}, and
 *       {@code invokedynamic} {@code BootstrapMethods} ({@code LambdaMetafactory}) edges.</li>
 * </ol>
 *
 * <p>Evaluates first-order (0-hop existence/registration wiring) and second-order ($k$-hop causal
 * chain to terminal effect sinks, $k \le 4$) invariants formatted as
 * {@code "Claims: <X> -> Does Not Deliver: <Y>"} with deterministic {@link ConfidenceTier}s.
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy ADR-126
 * @governedBy leaffuzz-ADR-001
 * @governedBy corpus-atlas-ADR-002
 * @trace REQ-CFG-ATLAS-001
 * @trace REQ-SLEUTH-FUZZ-004
 * @trace S-004
 * @trace S-005
 */
public final class BytecodeCausalGraphScanner {

    private static final Logger LOGGER = Logger.getLogger(BytecodeCausalGraphScanner.class.getName());
    private static final int CLASS_MAGIC = 0xCAFEBABE;
    private static final int MAX_CAUSAL_HOPS = 4;
    private static final int MAX_RESOURCE_BYTES = 1024 * 1024;
    private static final int MAX_CLASSES_PER_JAR = 4096;

    // Constant pool tags (JVMS 4.4)
    private static final int CONSTANT_Utf8 = 1;
    private static final int CONSTANT_Integer = 3;
    private static final int CONSTANT_Float = 4;
    private static final int CONSTANT_Long = 5;
    private static final int CONSTANT_Double = 6;
    private static final int CONSTANT_Class = 7;
    private static final int CONSTANT_String = 8;
    private static final int CONSTANT_Fieldref = 9;
    private static final int CONSTANT_Methodref = 10;
    private static final int CONSTANT_InterfaceMethodref = 11;
    private static final int CONSTANT_NameAndType = 12;
    private static final int CONSTANT_MethodHandle = 15;
    private static final int CONSTANT_MethodType = 16;
    private static final int CONSTANT_Dynamic = 17;
    private static final int CONSTANT_InvokeDynamic = 18;
    private static final int CONSTANT_Module = 19;
    private static final int CONSTANT_Package = 20;

    // Access flags
    private static final int ACC_INTERFACE = 0x0200;
    private static final int ACC_ABSTRACT = 0x0400;
    private static final int ACC_SYNTHETIC = 0x1000;
    private static final int ACC_ENUM = 0x4000;

    private static final Set<String> CONFIG_GETTER_METHODS = Set.of(
            "getBoolean", "getInt", "getLong", "getDouble", "getString",
            "getStringList", "getIntegerList", "getDoubleList", "getFloatList",
            "getMapList", "getList", "getConfigurationSection", "getObject",
            "getConfigValue", "getNumber", "getOrDefault",
            "getDuration", "resolveScalar",
            "parseSecondsDurationMillis", "parseDurationSetting",
            "resolveCapacity", "resolveCapacityInt", "getProperty"
    );

    private static final Set<String> DYNAMIC_CONFIG_ITERATION_METHODS = Set.of(
            "getKeys", "getValues", "getConfigurationSection", "getMapList"
    );

    private static final Set<String> QUEUE_PRODUCER_METHODS = Set.of(
            "offer", "offerLast", "offerFirst", "add", "addLast", "addFirst",
            "push", "put", "putIfAbsent", "computeIfAbsent", "enqueue"
    );

    private static final Set<String> QUEUE_CONSUMER_METHODS = Set.of(
            "poll", "pollFirst", "pollLast", "take", "remove", "removeFirst",
            "pop", "drainTo", "iterator", "forEach", "get", "values", "entrySet"
    );

    private static final Set<String> EVENT_DISPATCH_METHODS = Set.of(
            "callEvent", "post", "fire", "fireEvent", "dispatchEvent"
    );

    private static final Set<String> STRING_COMPARE_METHODS = Set.of(
            "equals", "equalsIgnoreCase", "startsWith", "contentEquals", "matches"
    );

    private static final Set<String> NON_SUBCOMMAND_LITERALS = Set.of(
            "true", "false", "null", "none", "default", "console", "player",
            "utf-8", "utf8", "yes", "no", "on", "off", "all"
    );

    private static final Set<String> REFLECTIVE_SCANNER_MARKERS = Set.of(
            "org/reflections/Reflections",
            "com/google/common/reflect/ClassPath",
            "io/github/classgraph/ClassGraph",
            "com/google/inject/Injector",
            "co/aikar/commands/PaperCommandManager",
            "co/aikar/commands/BukkitCommandManager",
            "org/incendo/cloud/CommandManager",
            "cloud/commandframework/CommandManager",
            "dev/rollczi/litecommands/LiteCommands"
    );

    private static final Set<String> BENIGN_CAUGHT_EXCEPTIONS = Set.of(
            "java/lang/NumberFormatException",
            "java/lang/IllegalArgumentException",
            "java/lang/IllegalStateException",
            "java/lang/RuntimeException",
            "java/lang/InterruptedException",
            "java/lang/ClassNotFoundException",
            "java/lang/NoClassDefFoundError",
            "java/lang/UnsatisfiedLinkError",
            "java/lang/LinkageError",
            "java/lang/NoSuchMethodError",
            "java/lang/NoSuchMethodException",
            "java/lang/NoSuchFieldError",
            "java/lang/NoSuchFieldException",
            "java/lang/ReflectiveOperationException",
            "java/lang/IllegalAccessException",
            "java/lang/InvocationTargetException",
            "java/lang/InstantiationException",
            "java/lang/UnsupportedOperationException",
            "java/lang/IndexOutOfBoundsException",
            "java/lang/ClassCastException",
            "java/lang/NullPointerException",
            "java/lang/Throwable",
            "java/util/concurrent/CancellationException"
    );

    /** Entry-point family in the plugin/mod causal graph. */
    public enum EntryPointKind {
        COMMAND,
        EVENT,
        SUPPLIER
    }

    /** Registration wiring mode for an event listener class. */
    public enum ListenerRegistrationMode {
        /** Instantiated and registered unconditionally on the plugin/mod startup path. */
        REGISTERED_UNCONDITIONAL,
        /** Instantiated and registered conditionally behind a configuration flag, early-return guard, or branch. */
        REGISTERED_CONFIG_GATED,
        /** Registered via reflective package scanning, DI container, or SPI hook. */
        REGISTERED_REFLECTIVE_OR_SPI,
        /** Concrete listener class with {@code @EventHandler}/{@code @SubscribeEvent} and 0 instantiation/registration sites. */
        UNREGISTERED,
        /** Not an event listener entry point. */
        NOT_APPLICABLE
    }

    /** Deterministic confidence tier for a {@link ClaimDeliveryFinding}. */
    public enum ConfidenceTier {
        CONFIRMED(100, "CONFIRMED 100%"),
        HIGH(90, "HIGH 90%"),
        MEDIUM(75, "MEDIUM 75%"),
        ADVISORY(55, "ADVISORY 55%");

        private final int defaultPercent;
        private final String badge;

        ConfidenceTier(int defaultPercent, String badge) {
            this.defaultPercent = defaultPercent;
            this.badge = badge;
        }

        public int defaultPercent() {
            return defaultPercent;
        }

        public String badge() {
            return badge;
        }
    }

    /** Category of a first-order or second-order claim delivery finding. */
    public enum FindingKind {
        /** Order 1: Concrete {@code @EventHandler}/{@code @SubscribeEvent} listener is never instantiated or registered. */
        CLAIM_UNREGISTERED_LISTENER,
        /** Order 1: Command declared in {@code plugin.yml} is never bound in {@code onEnable} or handled in {@code onCommand}. */
        CLAIM_UNWIRED_COMMAND,
        /** Order 1: Configuration key advertised in embedded {@code config.yml} has 0 bytecode readers in the JAR. */
        CLAIM_DEAD_CONFIG_KEY,
        /** Order 2: Configuration key is read into a class field, but that field has 0 {@code getfield}/{@code getstatic} readers. */
        CLAIM_UNREAD_CONFIG_FIELD,
        /** Order 2: {@code CompletableFuture.supplyAsync} or {@code Supplier} return value is immediately popped/discarded. */
        CLAIM_ORPHANED_SUPPLIER,
        /** Order 2: Exception handler catches an operational exception and returns immediately with 0 logs or user feedback ({@code S-004}). */
        CLAIM_SWALLOWED_FAILURE,
        /** Order 2: Async {@code Supplier}/{@code Runnable} invokes main-thread-only Bukkit world/chunk/entity mutators ({@code S-005}). */
        CLAIM_ASYNC_MAIN_THREAD_SINK,
        /** Order 2: Config key in seconds is added/compared against {@code System.currentTimeMillis()} without {@code * 1000L} scaling. */
        CLAIM_UNIT_MISMATCH,
        /** Order 2: Command advertises a world/teleport/GUI/economy action but its causal chain only sends chat messages. */
        CLAIM_HOLLOW_COMMAND,
        /** Order 2 (Advisory): Subscribed LLM semantic/guard-polarity mismatch grounded in closed-world AST symbols. */
        CLAIM_LLM_SEMANTIC_MISMATCH
    }

    /**
     * Structured first-order or second-order claim audit finding formatted as
     * {@code "Claims: <X> -> Does Not Deliver: <Y>"}.
     *
     * @param findingId         stable finding identifier (e.g. {@code CLAIM-1})
     * @param artifactName      owning plugin/mod or JAR name
     * @param order             investigation order ({@code 1} = 0-hop existence/wiring, {@code 2} = $k$-hop causal chain)
     * @param kind              finding category
     * @param confidenceTier    deterministic confidence tier
     * @param confidencePercent numeric confidence score ({@code 0..100})
     * @param entryPointSymbol  attributed {@code Class#method} or config key symbol
     * @param claims            advertised behavior from {@code plugin.yml}, {@code config.yml}, or annotations
     * @param doesNotDeliver    concrete 1st-order or 2nd-order proof of non-delivery
     * @param clearsWhen        exact developer remediation condition
     * @param causalChainSteps  extracted {@code Jminor}-style hop trace supporting the finding
     * @param llmExplanation    optional AST-grounded root-cause explanation from {@link LlmCausalChainAuditor}
     */
    public record ClaimDeliveryFinding(
            String findingId,
            String artifactName,
            int order,
            FindingKind kind,
            ConfidenceTier confidenceTier,
            int confidencePercent,
            String entryPointSymbol,
            String claims,
            String doesNotDeliver,
            String clearsWhen,
            List<String> causalChainSteps,
            String llmExplanation
    ) {
        public ClaimDeliveryFinding {
            findingId = (findingId == null || findingId.isBlank()) ? "CLAIM-0" : findingId.trim();
            artifactName = (artifactName == null || artifactName.isBlank()) ? "unknown" : artifactName.trim();
            order = order <= 1 ? 1 : 2;
            Objects.requireNonNull(kind, "kind");
            confidenceTier = confidenceTier != null ? confidenceTier : ConfidenceTier.HIGH;
            confidencePercent = Math.max(1, Math.min(100, confidencePercent));
            entryPointSymbol = (entryPointSymbol == null || entryPointSymbol.isBlank()) ? "<unknown>" : entryPointSymbol.trim();
            claims = (claims == null || claims.isBlank()) ? entryPointSymbol : claims.trim();
            doesNotDeliver = (doesNotDeliver == null || doesNotDeliver.isBlank()) ? "No downstream delivery sink" : doesNotDeliver.trim();
            clearsWhen = (clearsWhen == null || clearsWhen.isBlank()) ? "Wire the entry point to its downstream sink." : clearsWhen.trim();
            causalChainSteps = causalChainSteps == null ? List.of() : List.copyOf(causalChainSteps);
            llmExplanation = llmExplanation == null ? "" : llmExplanation.trim();
        }

        public ClaimDeliveryFinding withLlmExplanation(String explanation) {
            return new ClaimDeliveryFinding(
                    findingId,
                    artifactName,
                    order,
                    kind,
                    confidenceTier,
                    confidencePercent,
                    entryPointSymbol,
                    claims,
                    doesNotDeliver,
                    clearsWhen,
                    causalChainSteps,
                    explanation
            );
        }

        public ClaimDeliveryFinding withRuntimeCorroboration(int executions, int teleports, int menus) {
            if (executions <= 0) {
                return this;
            }
            String runtimeNote = String.format(
                    Locale.ROOT,
                    " Corroborated by Stage 2 live fuzzing: %d execution(s) observed %d teleports and %d menus.",
                    executions,
                    teleports,
                    menus
            );
            ConfidenceTier boostedTier = (confidenceTier == ConfidenceTier.MEDIUM)
                    ? ConfidenceTier.HIGH
                    : confidenceTier;
            int boostedPct = Math.min(98, Math.max(confidencePercent, 92));
            return new ClaimDeliveryFinding(
                    findingId,
                    artifactName,
                    order,
                    kind,
                    boostedTier,
                    boostedPct,
                    entryPointSymbol,
                    claims,
                    doesNotDeliver.contains("Corroborated by Stage 2") ? doesNotDeliver : (doesNotDeliver + runtimeNote),
                    clearsWhen,
                    causalChainSteps,
                    llmExplanation
            );
        }

        public String formatSummaryLine() {
            return String.format(
                    Locale.ROOT,
                    "[%s %d%%] (Order %d - %s) Claims: %s -> Does Not Deliver: %s",
                    confidenceTier.name(),
                    confidencePercent,
                    order,
                    kind.name(),
                    claims,
                    doesNotDeliver
            );
        }
    }

    /**
     * Method-scoped {@code Jminor}-style Hoare causal slice for an entry point ({@code corpus-atlas-ADR-002}).
     */
    public record CausalChainSlice(
            EntryPointKind kind,
            String entrySymbol,
            String advertisedClaim,
            ListenerRegistrationMode registrationMode,
            String gatingConfigKey,
            List<String> guards,
            List<String> readConfigKeys,
            List<String> readFields,
            List<String> mutatedFields,
            List<String> spawnedSuppliersAndLambdas,
            List<String> hopTrace,
            Set<String> reachableEffectSinks
    ) {
        public CausalChainSlice {
            Objects.requireNonNull(kind, "kind");
            entrySymbol = entrySymbol == null ? "<unknown>" : entrySymbol;
            advertisedClaim = advertisedClaim == null ? "" : advertisedClaim;
            registrationMode = registrationMode == null ? ListenerRegistrationMode.NOT_APPLICABLE : registrationMode;
            gatingConfigKey = gatingConfigKey == null ? "" : gatingConfigKey;
            guards = guards == null ? List.of() : List.copyOf(guards);
            readConfigKeys = readConfigKeys == null ? List.of() : List.copyOf(readConfigKeys);
            readFields = readFields == null ? List.of() : List.copyOf(readFields);
            mutatedFields = mutatedFields == null ? List.of() : List.copyOf(mutatedFields);
            spawnedSuppliersAndLambdas = spawnedSuppliersAndLambdas == null ? List.of() : List.copyOf(spawnedSuppliersAndLambdas);
            hopTrace = hopTrace == null ? List.of() : List.copyOf(hopTrace);
            reachableEffectSinks = reachableEffectSinks == null
                    ? Set.of()
                    : Collections.unmodifiableSet(new LinkedHashSet<>(reachableEffectSinks));
        }

        /**
         * Renders a compact {@code Jminor}-style causal slice suitable for LLM prompts (`~150-250` tokens).
         */
        public String toJminorPromptBlock() {
            StringBuilder sb = new StringBuilder();
            sb.append("CAUSAL_CHAIN [ENTRY_").append(kind.name()).append(": ")
                    .append(LlmConfigDocSynthesizer.stripPackagePrefixes(entrySymbol)).append("]:\n");
            if (!advertisedClaim.isBlank()) {
                sb.append("  CLAIM: ").append(advertisedClaim).append('\n');
            }
            if (kind == EntryPointKind.EVENT) {
                sb.append("  REGISTRATION: ").append(registrationMode.name());
                if (!gatingConfigKey.isBlank()) {
                    sb.append(" (gated by config: ").append(gatingConfigKey).append(')');
                }
                sb.append('\n');
            }
            if (!guards.isEmpty()) {
                sb.append("  GUARDS: ").append(String.join("; ", guards)).append('\n');
            }
            if (!readConfigKeys.isEmpty()) {
                sb.append("  READS_CONFIG: ").append(String.join(", ", readConfigKeys)).append('\n');
            }
            if (!readFields.isEmpty()) {
                sb.append("  READS_FIELDS: ").append(String.join(", ", readFields)).append('\n');
            }
            if (!mutatedFields.isEmpty()) {
                sb.append("  MUTATES_FIELDS: ").append(String.join(", ", mutatedFields)).append('\n');
            }
            if (!spawnedSuppliersAndLambdas.isEmpty()) {
                sb.append("  SPAWNS_SUPPLIERS: ").append(String.join(" -> ", spawnedSuppliersAndLambdas)).append('\n');
            }
            if (!hopTrace.isEmpty()) {
                sb.append("  HOPS:\n");
                for (String hop : hopTrace) {
                    sb.append("    -> ").append(LlmConfigDocSynthesizer.stripPackagePrefixes(hop)).append('\n');
                }
            }
            sb.append("  REACHABLE_SINKS: ").append(reachableEffectSinks.isEmpty() ? "[NO_OP]" : reachableEffectSinks).append('\n');
            return sb.toString();
        }
    }

    /**
     * White-box command schema extracted from bytecode branches, argument parsers, and framework
     * annotations ({@code leaffuzz-ADR-001}, {@code ADR-125}).
     *
     * @param rootCommand        canonical root command literal (e.g. {@code "wild"}, {@code "rtp"})
     * @param handlerSymbol      bytecode method symbol handling the command
     * @param subcommandLiterals literal subcommand/branch tokens compared against {@code args[i]} or declared via {@code @Subcommand}/{@code @Execute}
     * @param argumentParsers    inferred Brigadier-compatible argument parser kinds (e.g. {@code "brigadier:integer"}, {@code "minecraft:dimension"})
     * @param inlinePermissions  permission node literals checked via {@code hasPermission("...")} or {@code @CommandPermission}/{@code @Permission}
     */
    public record BytecodeCommandSchema(
            String rootCommand,
            String handlerSymbol,
            List<String> subcommandLiterals,
            List<String> argumentParsers,
            List<String> inlinePermissions
    ) {
        public BytecodeCommandSchema {
            rootCommand = (rootCommand == null || rootCommand.isBlank()) ? "cmd" : rootCommand.trim().toLowerCase(Locale.ROOT);
            handlerSymbol = handlerSymbol == null ? "<unknown>" : handlerSymbol;
            subcommandLiterals = subcommandLiterals == null ? List.of() : List.copyOf(subcommandLiterals);
            argumentParsers = argumentParsers == null ? List.of() : List.copyOf(argumentParsers);
            inlinePermissions = inlinePermissions == null ? List.of() : List.copyOf(inlinePermissions);
        }
    }

    /**
     * Complete causal graph and first/second-order claim audit report for a plugin/mod artifact.
     */
    public record CausalGraphReport(
            String artifactId,
            String displayName,
            List<CausalChainSlice> entryChains,
            Map<String, ListenerRegistrationMode> listenerRegistrations,
            Map<String, String> configGatedListeners,
            List<ClaimDeliveryFinding> findings,
            Set<String> closedWorldSymbols,
            List<BytecodeCommandSchema> commandSchemas
    ) {
        public CausalGraphReport {
            artifactId = (artifactId == null || artifactId.isBlank()) ? "plugin:unknown" : artifactId;
            displayName = (displayName == null || displayName.isBlank()) ? artifactId : displayName;
            entryChains = entryChains == null ? List.of() : List.copyOf(entryChains);
            listenerRegistrations = listenerRegistrations == null
                    ? Map.of()
                    : Collections.unmodifiableMap(new LinkedHashMap<>(listenerRegistrations));
            configGatedListeners = configGatedListeners == null
                    ? Map.of()
                    : Collections.unmodifiableMap(new LinkedHashMap<>(configGatedListeners));
            findings = findings == null ? List.of() : List.copyOf(findings);
            closedWorldSymbols = closedWorldSymbols == null
                    ? Set.of()
                    : Collections.unmodifiableSet(new LinkedHashSet<>(closedWorldSymbols));
            commandSchemas = commandSchemas == null ? List.of() : List.copyOf(commandSchemas);
        }

        public CausalGraphReport(
                String artifactId,
                String displayName,
                List<CausalChainSlice> entryChains,
                Map<String, ListenerRegistrationMode> listenerRegistrations,
                Map<String, String> configGatedListeners,
                List<ClaimDeliveryFinding> findings,
                Set<String> closedWorldSymbols
        ) {
            this(
                    artifactId,
                    displayName,
                    entryChains,
                    listenerRegistrations,
                    configGatedListeners,
                    findings,
                    closedWorldSymbols,
                    List.of()
            );
        }

        public static CausalGraphReport empty(String name) {
            return new CausalGraphReport(name, name, List.of(), Map.of(), Map.of(), List.of(), Set.of(), List.of());
        }
    }

    private record ExceptionEntry(
            int startPc,
            int endPc,
            int handlerPc,
            String catchClassInternal
    ) {
    }

    private record ParsedAnnotations(
            boolean isEventHandler,
            boolean isCommandEntry,
            List<String> commandRoots,
            List<String> subcommandLiterals,
            List<String> permissions,
            String description
    ) {
        static ParsedAnnotations empty() {
            return new ParsedAnnotations(false, false, List.of(), List.of(), List.of(), "");
        }

        ParsedAnnotations merge(ParsedAnnotations other) {
            if (other == null) {
                return this;
            }
            Set<String> roots = new LinkedHashSet<>(this.commandRoots);
            roots.addAll(other.commandRoots);
            Set<String> subs = new LinkedHashSet<>(this.subcommandLiterals);
            subs.addAll(other.subcommandLiterals);
            Set<String> perms = new LinkedHashSet<>(this.permissions);
            perms.addAll(other.permissions);
            String desc = !this.description.isBlank() ? this.description : other.description;
            return new ParsedAnnotations(
                    this.isEventHandler || other.isEventHandler,
                    this.isCommandEntry || other.isCommandEntry,
                    new ArrayList<>(roots),
                    new ArrayList<>(subs),
                    new ArrayList<>(perms),
                    desc
            );
        }
    }

    private record MethodNode(
            String ownerClass,
            String name,
            String descriptor,
            int accessFlags,
            boolean isEventHandler,
            String eventTypeSimpleName,
            boolean isCommandAnnotated,
            List<String> annotatedCommandRoots,
            List<String> subcommandLiterals,
            List<String> argumentParsers,
            List<String> inlinePermissions,
            String commandDescription,
            List<String> calledMethods,
            List<String> spawnedLambdas,
            List<String> orphanedSuppliers,
            Set<String> instantiatedClasses,
            Map<String, String> conditionalInstantiations,
            Map<String, String> conditionalMethodCalls,
            Set<String> readFields,
            Set<String> writtenFields,
            Set<String> producedQueueFields,
            Set<String> dispatchedEventTypes,
            Map<String, String> configKeyToAssignedField,
            Map<String, String> configKeyScalingHint,
            Set<String> referencedConfigKeys,
            Set<String> stringLiterals,
            List<String> guards,
            Set<String> directEffectSinks,
            Set<String> syncMainThreadCalls,
            List<String> swallowedExceptions,
            boolean callsCurrentTimeMillis,
            boolean multipliesBy1000Or20,
            boolean usesDynamicConfigIteration
    ) {
        String symbol() {
            return ownerClass + "#" + name;
        }
    }

    private record ParsedClass(
            String binaryClassName,
            String superClassName,
            int accessFlags,
            Set<String> interfaces,
            Set<String> declaredFields,
            Map<String, MethodNode> methods,
            boolean usesReflectiveScanner,
            ParsedAnnotations classAnnotations
    ) {
        boolean isConcrete() {
            return (accessFlags & (ACC_INTERFACE | ACC_ABSTRACT | ACC_ENUM)) == 0;
        }

        boolean implementsBukkitListener() {
            for (String iface : interfaces) {
                if (iface.endsWith("org.bukkit.event.Listener") || iface.endsWith("Listener")) {
                    return true;
                }
            }
            return false;
        }
    }

    private BytecodeCausalGraphScanner() {
    }

    /**
     * Scans a plugin or mod {@code .jar} file off-thread and produces its {@link CausalGraphReport}.
     *
     * @param jarPath path to the plugin/mod {@code .jar} archive
     * @return causal graph and first/second-order claim delivery findings
     * @throws IOException if the archive cannot be read
     */
    public static CausalGraphReport scanJar(Path jarPath) throws IOException {
        Objects.requireNonNull(jarPath, "jarPath");
        JarConfigScanner.HarvestedArtifact harvested = JarConfigScanner.scanJar(jarPath);
        List<byte[]> classBytePayloads = new ArrayList<>();
        try (ZipFile zip = new ZipFile(jarPath.toFile())) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            int count = 0;
            while (entries.hasMoreElements() && count < MAX_CLASSES_PER_JAR) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                String name = entry.getName();
                if (name.endsWith(".class") && !isShadedLibraryClass(name)) {
                    byte[] bytes = readBoundedBytes(zip, entry);
                    if (bytes != null) {
                        classBytePayloads.add(bytes);
                        count++;
                    }
                }
            }
        }
        return analyzeClasses(
                harvested.artifactId(),
                harvested.displayName(),
                classBytePayloads,
                harvested.commandDescriptors(),
                harvested.embeddedConfigs()
        );
    }

    /**
     * Analyzes an in-memory collection of raw {@code .class} byte arrays alongside optional
     * {@code plugin.yml} command descriptors and embedded YAML configuration files.
     *
     * @param artifactId         canonical artifact ID
     * @param displayName        plugin/mod display name
     * @param classBytePayloads  raw {@code .class} byte arrays
     * @param commandDescriptors advertised commands from {@code plugin.yml} / {@code paper-plugin.yml}
     * @param embeddedConfigs    map of embedded config file name to raw YAML content
     * @return completed {@link CausalGraphReport}
     */
    public static CausalGraphReport analyzeClasses(
            String artifactId,
            String displayName,
            Collection<byte[]> classBytePayloads,
            List<JarConfigScanner.CommandDescriptor> commandDescriptors,
            Map<String, String> embeddedConfigs
    ) {
        String effId = (artifactId == null || artifactId.isBlank()) ? "plugin:unknown" : artifactId.trim();
        String effName = (displayName == null || displayName.isBlank()) ? effId : displayName.trim();
        List<JarConfigScanner.CommandDescriptor> cmds = commandDescriptors == null ? List.of() : commandDescriptors;
        Map<String, String> configs = embeddedConfigs == null ? Map.of() : embeddedConfigs;

        Map<String, ParsedClass> classesByName = new LinkedHashMap<>();
        Map<String, MethodNode> methodsBySymbol = new LinkedHashMap<>();
        Map<String, List<MethodNode>> methodsByName = new LinkedHashMap<>();
        List<MethodNode> allMethods = new ArrayList<>();
        Set<String> closedWorldSymbols = new LinkedHashSet<>();
        boolean jarUsesReflectiveScanner = false;
        boolean jarUsesDynamicConfigIteration = false;

        if (classBytePayloads != null) {
            for (byte[] bytes : classBytePayloads) {
                ParsedClass pc = parseClassBytes(bytes);
                if (pc == null) {
                    continue;
                }
                classesByName.put(pc.binaryClassName(), pc);
                closedWorldSymbols.add(pc.binaryClassName());
                closedWorldSymbols.add(simpleClassName(pc.binaryClassName()));
                if (pc.usesReflectiveScanner()) {
                    jarUsesReflectiveScanner = true;
                }
                for (String field : pc.declaredFields()) {
                    closedWorldSymbols.add(pc.binaryClassName() + "#" + field);
                    closedWorldSymbols.add(simpleClassName(pc.binaryClassName()) + "#" + field);
                }
                for (var me : pc.methods().entrySet()) {
                    MethodNode m = me.getValue();
                    allMethods.add(m);
                    methodsBySymbol.putIfAbsent(m.symbol(), m);
                    methodsBySymbol.put(pc.binaryClassName() + "#" + me.getKey(), m);
                    methodsByName.computeIfAbsent(m.name(), k -> new ArrayList<>()).add(m);
                    closedWorldSymbols.add(m.symbol());
                    closedWorldSymbols.add(simpleClassName(pc.binaryClassName()) + "#" + m.name());
                    closedWorldSymbols.addAll(m.referencedConfigKeys());
                    if (m.usesDynamicConfigIteration()) {
                        jarUsesDynamicConfigIteration = true;
                    }
                }
            }
        }

        // Collect global sets across all methods in the JAR
        Set<String> allInstantiatedClasses = new LinkedHashSet<>();
        Map<String, String> conditionalInstantiatedClasses = new LinkedHashMap<>();
        Map<String, String> conditionallyCalledMethods = new LinkedHashMap<>();
        Set<String> allGloballyReadFields = new LinkedHashSet<>();
        Set<String> allGloballyReadFieldNames = new LinkedHashSet<>();
        Set<String> allReferencedConfigKeys = new LinkedHashSet<>();
        Set<String> allStringLiterals = new LinkedHashSet<>();
        Map<String, Set<String>> fieldToReaderMethods = new LinkedHashMap<>();
        Set<String> allAsyncSpawnedLambdas = new LinkedHashSet<>();

        for (MethodNode m : allMethods) {
            allInstantiatedClasses.addAll(m.instantiatedClasses());
            for (var ce : m.conditionalInstantiations().entrySet()) {
                conditionalInstantiatedClasses.putIfAbsent(ce.getKey(), ce.getValue());
            }
            for (var cm : m.conditionalMethodCalls().entrySet()) {
                conditionallyCalledMethods.putIfAbsent(cm.getKey(), cm.getValue());
            }
            for (String rf : m.readFields()) {
                allGloballyReadFields.add(rf);
                int hash = rf.indexOf('#');
                String shortField = hash >= 0 ? rf.substring(hash + 1) : rf;
                allGloballyReadFieldNames.add(shortField);
                if (!m.name().equals("<init>") && !m.name().equals("<clinit>")) {
                    fieldToReaderMethods.computeIfAbsent(rf, k -> new LinkedHashSet<>()).add(m.symbol());
                    fieldToReaderMethods.computeIfAbsent(shortField, k -> new LinkedHashSet<>()).add(m.symbol());
                }
            }
            allReferencedConfigKeys.addAll(m.referencedConfigKeys());
            allStringLiterals.addAll(m.stringLiterals());
            if (m.directEffectSinks().contains("ASYNC_SCHEDULER")) {
                allAsyncSpawnedLambdas.addAll(m.spawnedLambdas());
            }
        }

        // Propagate caller-gated helper methods (e.g. `if (cfgFlag) registerOptionalListeners();`)
        // to any listener classes instantiated inside that helper method
        for (var cm : conditionallyCalledMethods.entrySet()) {
            MethodNode targetHelper = findMethodNodeFlexible(methodsBySymbol, methodsByName, null, cm.getKey());
            if (targetHelper != null) {
                for (String instCls : targetHelper.instantiatedClasses()) {
                    conditionalInstantiatedClasses.putIfAbsent(instCls, cm.getValue());
                }
            }
        }

        // Also mark any superclass of an instantiated class as instantiated
        Set<String> transitiveInstantiated = new LinkedHashSet<>(allInstantiatedClasses);
        for (String inst : allInstantiatedClasses) {
            ParsedClass cur = classesByName.get(inst);
            int guard = 0;
            while (cur != null && cur.superClassName() != null && guard++ < 8) {
                transitiveInstantiated.add(cur.superClassName());
                cur = classesByName.get(cur.superClassName());
            }
        }

        List<ClaimDeliveryFinding> findings = new ArrayList<>();
        int findingSeq = 1;

        // =========================================================================
        // 1. Evaluate Event Listener Registration (Order 1) + Config-Gated Carve-Out
        // =========================================================================
        Map<String, ListenerRegistrationMode> listenerRegistrations = new LinkedHashMap<>();
        Map<String, String> configGatedListeners = new LinkedHashMap<>();

        for (ParsedClass pc : classesByName.values()) {
            if (!pc.isConcrete()) {
                continue;
            }
            List<MethodNode> eventMethods = new ArrayList<>();
            for (MethodNode m : pc.methods().values()) {
                if (m.isEventHandler()) {
                    eventMethods.add(m);
                }
            }
            if (eventMethods.isEmpty()) {
                continue;
            }

            boolean selfRegisters = pc.methods().values().stream().anyMatch(m ->
                    m.calledMethods().stream().anyMatch(c ->
                            c.endsWith("#registerEvents") || c.contains("EventBus#register") || c.endsWith("#register")));
            boolean isInlineAnonymous = pc.binaryClassName().matches(".*\\$\\d+$");
            ListenerRegistrationMode regMode;
            String gatingKey = "";
            if (conditionalInstantiatedClasses.containsKey(pc.binaryClassName())) {
                regMode = ListenerRegistrationMode.REGISTERED_CONFIG_GATED;
                gatingKey = conditionalInstantiatedClasses.get(pc.binaryClassName());
                configGatedListeners.put(pc.binaryClassName(), gatingKey);
            } else if (transitiveInstantiated.contains(pc.binaryClassName()) || selfRegisters || isInlineAnonymous) {
                regMode = ListenerRegistrationMode.REGISTERED_UNCONDITIONAL;
            } else if (jarUsesReflectiveScanner) {
                regMode = ListenerRegistrationMode.REGISTERED_REFLECTIVE_OR_SPI;
            } else {
                regMode = ListenerRegistrationMode.UNREGISTERED;
            }
            listenerRegistrations.put(pc.binaryClassName(), regMode);

            if (regMode == ListenerRegistrationMode.UNREGISTERED) {
                MethodNode firstEv = eventMethods.get(0);
                String evLabel = firstEv.eventTypeSimpleName().isEmpty()
                        ? "@EventHandler"
                        : ("@EventHandler " + firstEv.eventTypeSimpleName());
                findings.add(new ClaimDeliveryFinding(
                        "CLAIM-" + (findingSeq++),
                        effName,
                        1,
                        FindingKind.CLAIM_UNREGISTERED_LISTENER,
                        ConfidenceTier.CONFIRMED,
                        100,
                        firstEv.symbol(),
                        simpleClassName(pc.binaryClassName()) + "#" + firstEv.name() + " handles " + evLabel,
                        simpleClassName(pc.binaryClassName())
                                + " is never instantiated or passed to PluginManager#registerEvents in " + effName + ".",
                        "Instantiate and register " + simpleClassName(pc.binaryClassName())
                                + " via getServer().getPluginManager().registerEvents(new "
                                + simpleClassName(pc.binaryClassName()) + "(...), this) in onEnable().",
                        List.of(firstEv.symbol() + " [UNREGISTERED]"),
                        ""
                ));
            }
        }

        // =========================================================================
        // 2. Evaluate Order 1: Advertised Commands in plugin.yml vs Bytecode Wiring
        // =========================================================================
        boolean hasAnyOnCommandOverride = false;
        boolean hasGetCommandCall = false;
        Set<String> annotatedCommandRoots = new LinkedHashSet<>();
        for (ParsedClass pc : classesByName.values()) {
            for (String r : pc.classAnnotations().commandRoots()) {
                annotatedCommandRoots.add(r.toLowerCase(Locale.ROOT));
            }
        }
        for (MethodNode m : allMethods) {
            if ("onCommand".equals(m.name()) || "execute".equals(m.name()) || m.isCommandAnnotated()) {
                hasAnyOnCommandOverride = true;
            }
            for (String r : m.annotatedCommandRoots()) {
                annotatedCommandRoots.add(r.toLowerCase(Locale.ROOT));
            }
            for (String call : m.calledMethods()) {
                if (call.endsWith("#getCommand") || call.endsWith("#registerCommand") || call.endsWith("#register")) {
                    hasGetCommandCall = true;
                }
            }
        }

        for (JarConfigScanner.CommandDescriptor cmd : cmds) {
            String cmdLower = cmd.name().toLowerCase(Locale.ROOT);
            closedWorldSymbols.add("/" + cmdLower);
            boolean wiredInLiterals = allStringLiterals.stream()
                    .anyMatch(s -> s.equalsIgnoreCase(cmd.name())
                            || cmd.aliases().stream().anyMatch(a -> a.equalsIgnoreCase(s)));
            boolean wiredInAnnotations = annotatedCommandRoots.contains(cmdLower)
                    || cmd.aliases().stream().anyMatch(a -> annotatedCommandRoots.contains(a.toLowerCase(Locale.ROOT)))
                    || !annotatedCommandRoots.isEmpty();
            boolean wired = wiredInLiterals
                    || wiredInAnnotations
                    || (cmds.size() == 1 && hasAnyOnCommandOverride && !hasGetCommandCall)
                    || jarUsesReflectiveScanner;
            if (!wired && (!hasAnyOnCommandOverride || hasGetCommandCall)) {
                String desc = cmd.description().isBlank() ? ("Executes /" + cmd.name()) : cmd.description();
                findings.add(new ClaimDeliveryFinding(
                        "CLAIM-" + (findingSeq++),
                        effName,
                        1,
                        FindingKind.CLAIM_UNWIRED_COMMAND,
                        ConfidenceTier.CONFIRMED,
                        100,
                        "/" + cmd.name(),
                        "plugin.yml advertises command '/" + cmd.name() + "' (\"" + desc + "\")",
                        "No getCommand(\"" + cmd.name() + "\").setExecutor(...) call or command branch found in " + effName + " bytecode.",
                        "Bind getCommand(\"" + cmd.name() + "\").setExecutor(...) in onEnable() or handle \"" + cmd.name() + "\" in onCommand().",
                        List.of("plugin.yml:/" + cmd.name() + " -> [UNWIRED]"),
                        ""
                ));
            }
        }

        // =========================================================================
        // 3. Evaluate Order 1: Dead Config Keys in Embedded config.yml
        // =========================================================================
        Map<String, String> advertisedConfigComments = new LinkedHashMap<>();
        Map<String, Object> advertisedConfigDefaults = new LinkedHashMap<>();
        for (var cfgEntry : configs.entrySet()) {
            String fileName = cfgEntry.getKey();
            String yamlBody = cfgEntry.getValue();
            if (!fileName.endsWith("config.yml") || yamlBody == null || yamlBody.isBlank()) {
                continue;
            }
            RtpYamlConfig yaml = RtpYamlConfig.parse(yamlBody);
            for (String key : yaml.getKeys(true)) {
                Object val = yaml.get(key);
                if (val instanceof io.github.dailystruggle.rtp.common.configuration.yaml.RtpYamlSection) {
                    continue;
                }
                closedWorldSymbols.add(key);
                advertisedConfigDefaults.put(key, val);
                String comment = yaml.getComment(key);
                if (comment != null && !comment.isBlank()) {
                    advertisedConfigComments.put(key, comment.replaceAll("(?m)^\\s*#\\s*", "").replace('\n', ' ').trim());
                }
            }
        }

        if (!jarUsesDynamicConfigIteration && !advertisedConfigDefaults.isEmpty()) {
            for (var entry : advertisedConfigDefaults.entrySet()) {
                String key = entry.getKey();
                String leaf = SchemaInferrer.extractLeaf(key);
                String camelLeaf = BytecodeConfigScanner.toCamelCaseIdentifier(leaf);
                boolean referenced = allReferencedConfigKeys.contains(key)
                        || allReferencedConfigKeys.contains(leaf)
                        || allStringLiterals.contains(key)
                        || allStringLiterals.contains(leaf)
                        || (!camelLeaf.isEmpty() && allGloballyReadFieldNames.contains(camelLeaf));
                // Also check if any prefix section is referenced
                if (!referenced && key.contains(".")) {
                    String prefix = key.substring(0, key.lastIndexOf('.'));
                    if (allStringLiterals.contains(prefix) && jarUsesDynamicConfigIteration) {
                        referenced = true;
                    }
                }
                if (!referenced) {
                    String commentDesc = advertisedConfigComments.getOrDefault(key, "");
                    String claimStr = "config.yml key '" + key + ": " + entry.getValue() + "'"
                            + (commentDesc.isEmpty() ? "" : (" (\"" + commentDesc + "\")"));
                    findings.add(new ClaimDeliveryFinding(
                            "CLAIM-" + (findingSeq++),
                            effName,
                            1,
                            FindingKind.CLAIM_DEAD_CONFIG_KEY,
                            ConfidenceTier.CONFIRMED,
                            100,
                            key,
                            claimStr,
                            "Key '" + key + "' has 0 getBoolean/getInt/getString/getDouble bytecode references in " + effName + ".",
                            "Read '" + key + "' via getConfig() and wire it to the target runtime behavior, or remove the dead key from config.yml.",
                            List.of("config.yml:" + key + " -> [0 BYTECODE READERS]"),
                            ""
                    ));
                }
            }
        }

        // =========================================================================
        // 4. Evaluate Order 2: Unread Config Fields, Unit Mismatch, Orphaned Suppliers,
        //    Swallowed Failures (S-004), and Async Main-Thread Sinks (S-005)
        // =========================================================================
        Set<String> reportedUnreadFields = new LinkedHashSet<>();
        for (MethodNode m : allMethods) {
            // 4a. Unread config field (Order 2)
            for (var kf : m.configKeyToAssignedField().entrySet()) {
                String configKey = kf.getKey();
                String fieldRef = kf.getValue();
                int hash = fieldRef.indexOf('#');
                String shortField = hash >= 0 ? fieldRef.substring(hash + 1) : fieldRef;
                Set<String> readers = new LinkedHashSet<>();
                readers.addAll(fieldToReaderMethods.getOrDefault(fieldRef, Set.of()));
                readers.addAll(fieldToReaderMethods.getOrDefault(shortField, Set.of()));
                readers.remove(m.symbol());
                if (readers.isEmpty() && reportedUnreadFields.add(fieldRef)) {
                    String commentDesc = advertisedConfigComments.getOrDefault(configKey, "");
                    String claimStr = "config.yml key '" + configKey + "'"
                            + (commentDesc.isEmpty() ? "" : (" (\"" + commentDesc + "\")"))
                            + " loaded in " + simpleMethodRef(m.symbol());
                    findings.add(new ClaimDeliveryFinding(
                            "CLAIM-" + (findingSeq++),
                            effName,
                            2,
                            FindingKind.CLAIM_UNREAD_CONFIG_FIELD,
                            ConfidenceTier.CONFIRMED,
                            100,
                            fieldRef,
                            claimStr,
                            "Assigned to field " + simpleMethodRef(fieldRef)
                                    + ", which has 0 getfield/getstatic read sites in any command, event, or supplier chain across " + effName + ".",
                            "Read " + simpleMethodRef(fieldRef) + " in the corresponding command or event handler.",
                            List.of(m.symbol() + " --[putfield " + shortField + "]--> [0 READERS]"),
                            ""
                    ));
                } else if (!readers.isEmpty()) {
                    // 4b. Check Unit Mismatch (seconds added/compared to currentTimeMillis without * 1000L)
                    String keyLower = configKey.toLowerCase(Locale.ROOT);
                    boolean looksLikeSeconds = (keyLower.contains("second") || keyLower.endsWith("-sec")
                            || keyLower.contains("warmup") || keyLower.contains("cooldown"))
                            && !keyLower.contains("ms") && !keyLower.contains("millis") && !keyLower.contains("tick");
                    String loadScaling = m.configKeyScalingHint().get(configKey);
                    if (looksLikeSeconds && loadScaling == null) {
                        for (String readerSym : readers) {
                            MethodNode readerNode = methodsBySymbol.get(readerSym);
                            if (readerNode != null
                                    && readerNode.callsCurrentTimeMillis()
                                    && !readerNode.multipliesBy1000Or20()) {
                                findings.add(new ClaimDeliveryFinding(
                                        "CLAIM-" + (findingSeq++),
                                        effName,
                                        2,
                                        FindingKind.CLAIM_UNIT_MISMATCH,
                                        ConfidenceTier.HIGH,
                                        90,
                                        readerNode.symbol(),
                                        "Config key '" + configKey + "' specifies a duration in seconds",
                                        simpleMethodRef(readerNode.symbol()) + " combines unscaled '" + shortField
                                                + "' directly with System.currentTimeMillis() without * 1000L conversion (treating seconds as milliseconds).",
                                        "Multiply " + shortField + " by 1000L (or use TimeUnit.SECONDS.toMillis) before comparing with System.currentTimeMillis().",
                                        List.of(
                                                m.symbol() + " [loads " + configKey + " -> " + shortField + " (scaling: NONE)]",
                                                readerNode.symbol() + " [System.currentTimeMillis() + unscaled " + shortField + "]"
                                        ),
                                        ""
                                ));
                            }
                        }
                    }
                }
            }

            // 4c. Direct in-method unit mismatch (key read directly in method that calls currentTimeMillis without * 1000)
            for (String configKey : m.referencedConfigKeys()) {
                if (m.configKeyToAssignedField().containsKey(configKey)) {
                    continue;
                }
                String keyLower = configKey.toLowerCase(Locale.ROOT);
                boolean looksLikeSeconds = (keyLower.contains("second") || keyLower.endsWith("-sec"))
                        && !keyLower.contains("ms") && !keyLower.contains("millis") && !keyLower.contains("tick");
                if (looksLikeSeconds
                        && m.configKeyScalingHint().get(configKey) == null
                        && m.callsCurrentTimeMillis()
                        && !m.multipliesBy1000Or20()) {
                    findings.add(new ClaimDeliveryFinding(
                            "CLAIM-" + (findingSeq++),
                            effName,
                            2,
                            FindingKind.CLAIM_UNIT_MISMATCH,
                            ConfidenceTier.HIGH,
                            90,
                            m.symbol(),
                            "Config key '" + configKey + "' specifies a duration in seconds",
                            simpleMethodRef(m.symbol()) + " reads '" + configKey
                                    + "' and combines it with System.currentTimeMillis() without * 1000L scaling.",
                            "Multiply '" + configKey + "' by 1000L before adding or comparing against System.currentTimeMillis().",
                            List.of(m.symbol() + " [getInt(\"" + configKey + "\") + System.currentTimeMillis() (unscaled)]"),
                            ""
                    ));
                }
            }

            // 4d. Orphaned Supplier / CompletableFuture continuation (Order 2)
            for (String orphaned : m.orphanedSuppliers()) {
                MethodNode targetLambda = findMethodNodeFlexible(methodsBySymbol, methodsByName, m.ownerClass(), orphaned);
                boolean lambdaSelfDelivers = targetLambda != null && hasTerminalDeliverySink(targetLambda.directEffectSinks());
                if (!lambdaSelfDelivers) {
                    findings.add(new ClaimDeliveryFinding(
                            "CLAIM-" + (findingSeq++),
                            effName,
                            2,
                            FindingKind.CLAIM_ORPHANED_SUPPLIER,
                            ConfidenceTier.CONFIRMED,
                            100,
                            m.symbol(),
                            simpleMethodRef(m.symbol()) + " spawns supplier/future " + simpleMethodRef(orphaned),
                            "Return value of " + simpleMethodRef(orphaned)
                                    + " is immediately popped off the stack (POP opcode) without chaining .thenAccept/.whenComplete or consuming the result.",
                            "Chain CompletableFuture#thenAccept / #whenComplete (or consume Supplier#get) to deliver the computed result to the player/world sink.",
                            List.of(m.symbol() + " --[spawns]--> " + orphaned + " --[POP return value]--> [DISCARDED]"),
                            ""
                    ));
                }
            }

            // 4e. Swallowed operational failure (S-004, Order 2)
            boolean isEntryOrIoHandler = classifyEntryPoint(m, classesByName.get(m.ownerClass()), allAsyncSpawnedLambdas) != null
                    || m.name().startsWith("lambda$")
                    || m.swallowedExceptions().stream().anyMatch(ex ->
                    ex.endsWith("IOException") || ex.endsWith("SQLException"));
            String mNameLow = m.name().toLowerCase(Locale.ROOT);
            if (!m.swallowedExceptions().isEmpty()
                    && isEntryOrIoHandler
                    && ((m.accessFlags() & 0x0002) == 0 || m.name().startsWith("lambda$"))
                    && m.descriptor().endsWith(")V")
                    && !m.name().equals("onDisable")
                    && !m.name().equals("close")
                    && !m.name().equals("<clinit>")
                    && !mNameLow.contains("shutdown")
                    && !mNameLow.contains("prune")
                    && !mNameLow.contains("paint")
                    && !m.name().startsWith("safe")
                    && !m.name().startsWith("try")
                    && !m.name().startsWith("is")
                    && !m.name().startsWith("has")
                    && !m.name().startsWith("delete")
                    && !m.name().startsWith("cleanup")) {
                for (String excType : m.swallowedExceptions()) {
                    findings.add(new ClaimDeliveryFinding(
                            "CLAIM-" + (findingSeq++),
                            effName,
                            2,
                            FindingKind.CLAIM_SWALLOWED_FAILURE,
                            ConfidenceTier.CONFIRMED,
                            100,
                            m.symbol(),
                            simpleMethodRef(m.symbol()) + " executes operational pipeline with try/catch(" + simpleClassName(excType) + ")",
                            "Exception handler for " + simpleClassName(excType) + " in " + simpleMethodRef(m.symbol())
                                    + " executes an empty catch/return with 0 log calls, 0 user feedback messages, and 0 fallback actions (violates S-004).",
                            "Log the exception via logger/RTP.log(Level.WARNING, ...) and notify the caller or roll back state.",
                            List.of(m.symbol() + " --[catch (" + simpleClassName(excType) + ")]--> [EMPTY_RETURN (S-004)]"),
                            ""
                    ));
                }
            }
        }

        // 4f. Async Supplier/Runnable calling synchronous main-thread Bukkit APIs (S-005, Order 2)
        for (String asyncLambdaSym : allAsyncSpawnedLambdas) {
            MethodNode asyncNode = findMethodNodeFlexible(methodsBySymbol, methodsByName, null, asyncLambdaSym);
            if (asyncNode == null) {
                continue;
            }
            Set<String> mainThreadViolations = new LinkedHashSet<>(asyncNode.syncMainThreadCalls());
            for (String hop1 : asyncNode.calledMethods()) {
                MethodNode hopNode = findMethodNodeFlexible(methodsBySymbol, methodsByName, asyncNode.ownerClass(), hop1);
                if (hopNode != null) {
                    mainThreadViolations.addAll(hopNode.syncMainThreadCalls());
                }
            }
            if (!mainThreadViolations.isEmpty()) {
                findings.add(new ClaimDeliveryFinding(
                        "CLAIM-" + (findingSeq++),
                        effName,
                        2,
                        FindingKind.CLAIM_ASYNC_MAIN_THREAD_SINK,
                        ConfidenceTier.CONFIRMED,
                        100,
                        asyncNode.symbol(),
                        "Async task/supplier " + simpleMethodRef(asyncNode.symbol()) + " executes off the main server thread",
                        "Directly invokes synchronous main-thread-only API " + mainThreadViolations
                                + " from an async thread (violates S-005 / regional threading).",
                        "Use asynchronous APIs (e.g. getChunkAtAsync / teleportAsync) or marshal world mutations back to the region/main thread scheduler.",
                        List.of("ASYNC_SPAWN -> " + asyncNode.symbol() + " -> " + mainThreadViolations),
                        ""
                ));
            }
        }

        // =========================================================================
        // 5. Build Bounded k-Hop Causal Chains for Entry Points & Check Hollow Commands
        // =========================================================================
        Map<String, List<MethodNode>> registeredEventHandlersByEventType = new LinkedHashMap<>();
        for (MethodNode m : allMethods) {
            if (!m.isEventHandler() || m.eventTypeSimpleName().isEmpty()) {
                continue;
            }
            ListenerRegistrationMode rm = listenerRegistrations.get(m.ownerClass());
            if (rm == ListenerRegistrationMode.UNREGISTERED) {
                continue;
            }
            registeredEventHandlersByEventType
                    .computeIfAbsent(m.eventTypeSimpleName(), k -> new ArrayList<>())
                    .add(m);
        }

        List<CausalChainSlice> entryChains = new ArrayList<>();
        List<BytecodeCommandSchema> commandSchemas = new ArrayList<>();
        Set<String> evaluatedCommandSymbols = new LinkedHashSet<>();
        for (MethodNode m : allMethods) {
            if ((m.accessFlags() & (ACC_SYNTHETIC | 0x0040)) != 0 && !m.name().startsWith("lambda$")) {
                continue;
            }
            ParsedClass ownerPc = classesByName.get(m.ownerClass());
            EntryPointKind epKind = classifyEntryPoint(m, ownerPc, allAsyncSpawnedLambdas);
            if (epKind == null) {
                continue;
            }
            if (epKind == EntryPointKind.COMMAND && !evaluatedCommandSymbols.add(m.symbol())) {
                continue;
            }
            CausalChainSlice slice = buildCausalSlice(
                    epKind,
                    m,
                    ownerPc,
                    methodsBySymbol,
                    methodsByName,
                    fieldToReaderMethods,
                    registeredEventHandlersByEventType,
                    cmds,
                    listenerRegistrations,
                    configGatedListeners
            );
            entryChains.add(slice);

            if (epKind == EntryPointKind.COMMAND) {
                commandSchemas.addAll(extractCommandSchemasForEntry(m, ownerPc, methodsBySymbol, methodsByName, cmds));
            }

            if (epKind == EntryPointKind.COMMAND
                    && !jarUsesReflectiveScanner
                    && ownerPc != null
                    && ownerPc.isConcrete()) {
                boolean hasCosmeticOrOrphanedOnly = (!slice.reachableEffectSinks().isEmpty()
                        && isHollowMessageOnlySinkSet(slice.reachableEffectSinks()))
                        || (!m.orphanedSuppliers().isEmpty() && isHollowMessageOnlySinkSet(slice.reachableEffectSinks()));
                if (claimsActionableEffect(slice.advertisedClaim()) && hasCosmeticOrOrphanedOnly) {
                    findings.add(new ClaimDeliveryFinding(
                            "CLAIM-" + (findingSeq++),
                            effName,
                            2,
                            FindingKind.CLAIM_HOLLOW_COMMAND,
                            ConfidenceTier.HIGH,
                            85,
                            m.symbol(),
                            slice.advertisedClaim().isBlank()
                                    ? ("Command handler " + simpleMethodRef(m.symbol()))
                                    : slice.advertisedClaim(),
                            "Across the " + MAX_CAUSAL_HOPS + "-hop bytecode causal chain (including spawned lambdas/suppliers), "
                                    + "reachable sinks are "
                                    + (slice.reachableEffectSinks().isEmpty() ? "[NO_OP]" : slice.reachableEffectSinks())
                                    + " with 0 teleport, world, inventory, economy, storage, or state mutations.",
                            "Invoke the downstream domain effect sink (e.g. teleportAsync, openInventory, economy transaction, or state mutation) from "
                                    + simpleMethodRef(m.symbol()) + ".",
                            slice.hopTrace(),
                            ""
                    ));
                }
            }
        }

        return new CausalGraphReport(
                effId,
                effName,
                entryChains,
                listenerRegistrations,
                configGatedListeners,
                findings,
                closedWorldSymbols,
                commandSchemas
        );
    }

    private static EntryPointKind classifyEntryPoint(
            MethodNode m,
            ParsedClass owner,
            Set<String> allAsyncSpawnedLambdas
    ) {
        if (m.isEventHandler()) {
            return EntryPointKind.EVENT;
        }
        if (m.isCommandAnnotated()
                || "onCommand".equals(m.name())
                || (owner != null && owner.interfaces().stream().anyMatch(i ->
                i.endsWith("CommandExecutor") || i.endsWith("CommandsAPICommand") || i.endsWith("TreeCommand"))
                && ("onCommand".equals(m.name()) || "execute".equals(m.name())))) {
            return EntryPointKind.COMMAND;
        }
        if (allAsyncSpawnedLambdas.contains(m.symbol())
                || (owner != null && owner.interfaces().stream().anyMatch(i ->
                i.endsWith("Supplier") || i.endsWith("Callable")) && ("get".equals(m.name()) || "call".equals(m.name())))) {
            return EntryPointKind.SUPPLIER;
        }
        return null;
    }

    private static CausalChainSlice buildCausalSlice(
            EntryPointKind kind,
            MethodNode root,
            ParsedClass rootOwner,
            Map<String, MethodNode> methodsBySymbol,
            Map<String, List<MethodNode>> methodsByName,
            Map<String, Set<String>> fieldToReaderMethods,
            Map<String, List<MethodNode>> registeredEventHandlersByEventType,
            List<JarConfigScanner.CommandDescriptor> commandDescriptors,
            Map<String, ListenerRegistrationMode> listenerRegistrations,
            Map<String, String> configGatedListeners
    ) {
        Set<String> visited = new LinkedHashSet<>();
        Deque<MethodHop> queue = new ArrayDeque<>();
        queue.add(new MethodHop(root, 0));
        visited.add(root.symbol());

        List<String> guards = new ArrayList<>(root.guards());
        Set<String> readConfigs = new LinkedHashSet<>(root.referencedConfigKeys());
        Set<String> readFields = new LinkedHashSet<>();
        Set<String> mutatedFields = new LinkedHashSet<>();
        List<String> spawnedLambdas = new ArrayList<>();
        List<String> hopTrace = new ArrayList<>();
        Set<String> reachableSinks = new LinkedHashSet<>();

        while (!queue.isEmpty()) {
            MethodHop current = queue.poll();
            MethodNode node = current.node();
            int depth = current.depth();

            for (String rf : node.readFields()) {
                readFields.add(simpleMethodRef(rf));
            }
            for (String wf : node.writtenFields()) {
                mutatedFields.add(simpleMethodRef(wf));
                reachableSinks.add("STATE_MUTATION");
            }
            for (String qf : node.producedQueueFields()) {
                mutatedFields.add(simpleMethodRef(qf) + " [queue]");
            }
            readConfigs.addAll(node.referencedConfigKeys());
            for (String g : node.guards()) {
                if (!guards.contains(g)) {
                    guards.add(g);
                }
            }
            reachableSinks.addAll(node.directEffectSinks());

            String hopSummary = "Hop " + depth + ": " + simpleMethodRef(node.symbol())
                    + (node.directEffectSinks().isEmpty() ? "" : (" -> sinks=" + node.directEffectSinks()));
            hopTrace.add(hopSummary);

            if (depth >= MAX_CAUSAL_HOPS || visited.size() >= 256) {
                continue;
            }

            // Follow direct method calls
            for (String called : node.calledMethods()) {
                MethodNode target = findMethodNodeFlexible(methodsBySymbol, methodsByName, node.ownerClass(), called);
                if (target != null && visited.add(target.symbol())) {
                    queue.add(new MethodHop(target, depth + 1));
                }
            }

            // Follow invokedynamic spawned lambdas / suppliers
            for (String lambdaSym : node.spawnedLambdas()) {
                if (!spawnedLambdas.contains(simpleMethodRef(lambdaSym))) {
                    spawnedLambdas.add(simpleMethodRef(lambdaSym));
                }
                // Only traverse into a spawned lambda if its return value was not immediately popped!
                if (!node.orphanedSuppliers().contains(lambdaSym)) {
                    MethodNode target = findMethodNodeFlexible(methodsBySymbol, methodsByName, node.ownerClass(), lambdaSym);
                    if (target != null && visited.add(target.symbol())) {
                        queue.add(new MethodHop(target, depth + 1));
                    }
                }
            }

            // Follow instantiated Runnable/Supplier/Callable task classes when scheduled
            for (String instCls : node.instantiatedClasses()) {
                for (String taskEntry : List.of("run", "get", "call", "accept")) {
                    MethodNode taskMethod = methodsBySymbol.get(instCls + "#" + taskEntry);
                    if (taskMethod != null && visited.add(taskMethod.symbol())) {
                        queue.add(new MethodHop(taskMethod, depth + 1));
                    }
                }
            }

            // Follow decoupled custom event dispatch edges (NEW CustomEvent + callEvent/post -> registered @EventHandler)
            Set<String> candidateEvents = new LinkedHashSet<>(node.dispatchedEventTypes());
            if (node.directEffectSinks().contains("EVENT_DISPATCH")) {
                for (String instCls : node.instantiatedClasses()) {
                    candidateEvents.add(simpleClassName(instCls));
                }
            }
            for (String evSimple : candidateEvents) {
                for (MethodNode evHandler : registeredEventHandlersByEventType.getOrDefault(evSimple, List.of())) {
                    String handoffLabel = "event:" + evSimple + "->" + simpleMethodRef(evHandler.symbol());
                    if (!spawnedLambdas.contains(handoffLabel)) {
                        spawnedLambdas.add(handoffLabel);
                    }
                    if (visited.add(evHandler.symbol())) {
                        queue.add(new MethodHop(evHandler, depth + 1));
                    }
                }
            }

            // Follow 1-hop field dataflow (putfield -> reader method) and queue producer -> consumer dataflow
            Set<String> dataflowFields = new LinkedHashSet<>(node.writtenFields());
            for (String qf : node.producedQueueFields()) {
                dataflowFields.add(qf);
                int hash = qf.indexOf('#');
                if (hash >= 0) {
                    dataflowFields.add(qf.substring(hash + 1));
                }
            }
            for (String wf : dataflowFields) {
                for (String readerSym : fieldToReaderMethods.getOrDefault(wf, Set.of())) {
                    MethodNode readerNode = methodsBySymbol.get(readerSym);
                    if (readerNode != null && visited.add(readerNode.symbol())) {
                        queue.add(new MethodHop(readerNode, depth + 1));
                    }
                }
            }
        }

        String claim = resolveAdvertisedClaim(kind, root, rootOwner, commandDescriptors);
        ListenerRegistrationMode regMode = kind == EntryPointKind.EVENT
                ? listenerRegistrations.getOrDefault(root.ownerClass(), ListenerRegistrationMode.REGISTERED_UNCONDITIONAL)
                : ListenerRegistrationMode.NOT_APPLICABLE;
        String gatingKey = kind == EntryPointKind.EVENT
                ? configGatedListeners.getOrDefault(root.ownerClass(), "")
                : "";

        return new CausalChainSlice(
                kind,
                root.symbol(),
                claim,
                regMode,
                gatingKey,
                guards,
                new ArrayList<>(readConfigs),
                new ArrayList<>(readFields),
                new ArrayList<>(mutatedFields),
                spawnedLambdas,
                hopTrace,
                reachableSinks
        );
    }

    private record MethodHop(MethodNode node, int depth) {
    }

    private static List<BytecodeCommandSchema> extractCommandSchemasForEntry(
            MethodNode root,
            ParsedClass ownerPc,
            Map<String, MethodNode> methodsBySymbol,
            Map<String, List<MethodNode>> methodsByName,
            List<JarConfigScanner.CommandDescriptor> commandDescriptors
    ) {
        Set<String> roots = new LinkedHashSet<>(root.annotatedCommandRoots());
        if (ownerPc != null) {
            roots.addAll(ownerPc.classAnnotations().commandRoots());
        }
        String simpleCls = simpleClassName(root.ownerClass()).toLowerCase(Locale.ROOT);
        for (JarConfigScanner.CommandDescriptor cd : commandDescriptors) {
            String cmdLow = cd.name().toLowerCase(Locale.ROOT);
            if (simpleCls.contains(cmdLow) || root.stringLiterals().contains(cd.name()) || commandDescriptors.size() == 1) {
                roots.add(cmdLow);
            }
        }
        if (roots.isEmpty()) {
            String fallback = simpleCls.replaceAll("command|cmd|executor|handler", "").trim();
            roots.add(fallback.isEmpty() ? "cmd" : fallback);
        }

        Set<String> subcommands = new LinkedHashSet<>(root.subcommandLiterals());
        Set<String> argParsers = new LinkedHashSet<>(root.argumentParsers());
        Set<String> inlinePerms = new LinkedHashSet<>();
        if (ownerPc != null) {
            inlinePerms.addAll(ownerPc.classAnnotations().permissions());
        }
        inlinePerms.addAll(root.inlinePermissions());

        // Merge 1-hop helper methods in the same plugin JAR
        for (String called : root.calledMethods()) {
            MethodNode hop1 = findMethodNodeFlexible(methodsBySymbol, methodsByName, root.ownerClass(), called);
            if (hop1 != null) {
                subcommands.addAll(hop1.subcommandLiterals());
                argParsers.addAll(hop1.argumentParsers());
                inlinePerms.addAll(hop1.inlinePermissions());
            }
        }

        List<BytecodeCommandSchema> out = new ArrayList<>(roots.size());
        for (String r : roots) {
            if (r == null || r.isBlank()) {
                continue;
            }
            out.add(new BytecodeCommandSchema(
                    r,
                    root.symbol(),
                    new ArrayList<>(subcommands),
                    new ArrayList<>(argParsers),
                    new ArrayList<>(inlinePerms)
            ));
        }
        return out;
    }

    private static String resolveAdvertisedClaim(
            EntryPointKind kind,
            MethodNode root,
            ParsedClass rootOwner,
            List<JarConfigScanner.CommandDescriptor> commandDescriptors
    ) {
        if (kind == EntryPointKind.COMMAND) {
            List<String> annRoots = new ArrayList<>(root.annotatedCommandRoots());
            if (annRoots.isEmpty() && rootOwner != null) {
                annRoots.addAll(rootOwner.classAnnotations().commandRoots());
            }
            String annDesc = !root.commandDescription().isBlank()
                    ? root.commandDescription()
                    : (rootOwner != null ? rootOwner.classAnnotations().description() : "");
            if (!annRoots.isEmpty()) {
                String primaryRoot = annRoots.get(0);
                String subSuffix = root.subcommandLiterals().isEmpty()
                        ? ""
                        : (" " + root.subcommandLiterals().get(0));
                for (JarConfigScanner.CommandDescriptor cd : commandDescriptors) {
                    if (cd.name().equalsIgnoreCase(primaryRoot)
                            || cd.aliases().stream().anyMatch(a -> a.equalsIgnoreCase(primaryRoot))) {
                        String desc = !annDesc.isBlank()
                                ? annDesc
                                : (cd.description().isBlank() ? ("Executes /" + primaryRoot + subSuffix) : cd.description());
                        return "/" + primaryRoot + subSuffix + " — \"" + desc + "\"";
                    }
                }
                String desc = !annDesc.isBlank() ? annDesc : ("Executes /" + primaryRoot + subSuffix);
                return "/" + primaryRoot + subSuffix + " — \"" + desc + "\"";
            }

            String simpleCls = simpleClassName(root.ownerClass()).toLowerCase(Locale.ROOT);
            for (JarConfigScanner.CommandDescriptor cd : commandDescriptors) {
                String cmdLow = cd.name().toLowerCase(Locale.ROOT);
                if (simpleCls.contains(cmdLow) || root.stringLiterals().contains(cd.name()) || commandDescriptors.size() == 1) {
                    String desc = cd.description().isBlank() ? ("Executes /" + cd.name()) : cd.description();
                    return "/" + cd.name() + " — \"" + desc + "\"";
                }
            }
            return "Command handler " + simpleMethodRef(root.symbol());
        }
        if (kind == EntryPointKind.EVENT) {
            return simpleMethodRef(root.symbol()) + " (@EventHandler " + root.eventTypeSimpleName() + ")";
        }
        return "Supplier/Lambda " + simpleMethodRef(root.symbol());
    }

    private static boolean claimsActionableEffect(String claim) {
        if (claim == null || claim.isBlank()) {
            return false;
        }
        String low = claim.toLowerCase(Locale.ROOT);
        return low.contains("teleport")
                || low.contains("wild")
                || low.contains("rtp")
                || low.contains("warp")
                || low.contains("spawn")
                || low.contains("home")
                || low.contains("menu")
                || low.contains("gui")
                || low.contains("inventory")
                || low.contains("shop")
                || low.contains("withdraw")
                || low.contains("deposit")
                || low.contains("economy")
                || low.contains("heal")
                || low.contains("feed");
    }

    private static boolean isHollowMessageOnlySinkSet(Set<String> sinks) {
        if (sinks == null || sinks.isEmpty()) {
            return true;
        }
        for (String s : sinks) {
            if (!"MESSAGE_ONLY".equals(s)
                    && !"SOUND_PARTICLE_ONLY".equals(s)
                    && !"ASYNC_SCHEDULER".equals(s)
                    && !"SCHEDULER_TASK".equals(s)
                    && !"EVENT_DISPATCH".equals(s)
                    && !"QUEUE_HANDOFF".equals(s)) {
                return false;
            }
        }
        return true;
    }

    private static boolean hasTerminalDeliverySink(Set<String> sinks) {
        if (sinks == null || sinks.isEmpty()) {
            return false;
        }
        for (String s : sinks) {
            if ("TELEPORT".equals(s)
                    || "INVENTORY_MENU".equals(s)
                    || "WORLD_MUTATION".equals(s)
                    || "ECONOMY".equals(s)
                    || "STORAGE_IO".equals(s)
                    || "STATE_MUTATION".equals(s)
                    || "EVENT_CANCEL".equals(s)) {
                return true;
            }
        }
        return false;
    }

    private static MethodNode findMethodNodeFlexible(
            Map<String, MethodNode> methodsBySymbol,
            Map<String, List<MethodNode>> methodsByName,
            String defaultOwner,
            String ref
    ) {
        if (ref == null || ref.isEmpty()) {
            return null;
        }
        MethodNode exact = methodsBySymbol.get(ref);
        if (exact != null) {
            return exact;
        }
        if (!ref.contains("#") && defaultOwner != null) {
            MethodNode sameOwner = methodsBySymbol.get(defaultOwner + "#" + ref);
            if (sameOwner != null) {
                return sameOwner;
            }
        }
        int hash = ref.indexOf('#');
        String methodName = hash >= 0 ? ref.substring(hash + 1) : ref;
        String ownerSuffix = hash >= 0 ? ref.substring(0, hash) : "";
        List<MethodNode> byName = methodsByName != null ? methodsByName.get(methodName) : null;
        if (byName != null) {
            for (MethodNode cand : byName) {
                if (ownerSuffix.isEmpty() || cand.ownerClass().endsWith(ownerSuffix)) {
                    return cand;
                }
            }
            return null;
        }
        for (var e : methodsBySymbol.entrySet()) {
            MethodNode cand = e.getValue();
            if (cand.name().equals(methodName)
                    && (ownerSuffix.isEmpty() || cand.ownerClass().endsWith(ownerSuffix))) {
                return cand;
            }
        }
        return null;
    }

    /**
     * Parses a raw {@code .class} byte array into a {@link ParsedClass} with constant pool,
     * method bodies, exception tables, annotations, and {@code BootstrapMethods} lambda links.
     */
    private static ParsedClass parseClassBytes(byte[] classBytes) {
        if (classBytes == null || classBytes.length < 24) {
            return null;
        }
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(classBytes))) {
            if (in.readInt() != CLASS_MAGIC) {
                return null;
            }
            in.readUnsignedShort(); // minor
            in.readUnsignedShort(); // major
            int cpCount = in.readUnsignedShort();
            if (cpCount <= 1 || cpCount > 65535) {
                return null;
            }

            String[] utf8Pool = new String[cpCount];
            String[] numericPool = new String[cpCount];
            int[] classNameIdx = new int[cpCount];
            int[] stringUtf8Idx = new int[cpCount];
            int[] fieldClassIdx = new int[cpCount];
            int[] fieldNatIdx = new int[cpCount];
            int[] methodClassIdx = new int[cpCount];
            int[] methodNatIdx = new int[cpCount];
            int[] natNameIdx = new int[cpCount];
            int[] natDescIdx = new int[cpCount];
            int[] methodHandleRefIdx = new int[cpCount];
            int[] indyBootstrapIdx = new int[cpCount];
            int[] indyNatIdx = new int[cpCount];

            for (int i = 1; i < cpCount; i++) {
                int tag = in.readUnsignedByte();
                switch (tag) {
                    case CONSTANT_Utf8 -> utf8Pool[i] = in.readUTF();
                    case CONSTANT_Integer -> numericPool[i] = Integer.toString(in.readInt());
                    case CONSTANT_Float -> numericPool[i] = Float.toString(in.readFloat());
                    case CONSTANT_Long -> {
                        numericPool[i] = Long.toString(in.readLong());
                        i++;
                    }
                    case CONSTANT_Double -> {
                        numericPool[i] = Double.toString(in.readDouble());
                        i++;
                    }
                    case CONSTANT_Class -> classNameIdx[i] = in.readUnsignedShort();
                    case CONSTANT_String -> stringUtf8Idx[i] = in.readUnsignedShort();
                    case CONSTANT_Fieldref -> {
                        fieldClassIdx[i] = in.readUnsignedShort();
                        fieldNatIdx[i] = in.readUnsignedShort();
                    }
                    case CONSTANT_Methodref, CONSTANT_InterfaceMethodref -> {
                        methodClassIdx[i] = in.readUnsignedShort();
                        methodNatIdx[i] = in.readUnsignedShort();
                    }
                    case CONSTANT_NameAndType -> {
                        natNameIdx[i] = in.readUnsignedShort();
                        natDescIdx[i] = in.readUnsignedShort();
                    }
                    case CONSTANT_MethodHandle -> {
                        in.readUnsignedByte(); // reference_kind
                        methodHandleRefIdx[i] = in.readUnsignedShort();
                    }
                    case CONSTANT_MethodType, CONSTANT_Module, CONSTANT_Package -> in.skipBytes(2);
                    case CONSTANT_Dynamic -> in.skipBytes(4);
                    case CONSTANT_InvokeDynamic -> {
                        indyBootstrapIdx[i] = in.readUnsignedShort();
                        indyNatIdx[i] = in.readUnsignedShort();
                    }
                    default -> {
                        return null;
                    }
                }
            }

            int accessFlags = in.readUnsignedShort();
            int thisClass = in.readUnsignedShort();
            int superClass = in.readUnsignedShort();

            String internalName = resolveClassName(thisClass, classNameIdx, utf8Pool);
            if (internalName == null || internalName.isEmpty()) {
                return null;
            }
            String binaryClassName = internalName.replace('/', '.');
            String superInternal = resolveClassName(superClass, classNameIdx, utf8Pool);
            String superBinary = superInternal != null ? superInternal.replace('/', '.') : null;

            int interfacesCount = in.readUnsignedShort();
            Set<String> interfaces = new LinkedHashSet<>();
            for (int i = 0; i < interfacesCount; i++) {
                int ifaceIdx = in.readUnsignedShort();
                String ifaceInternal = resolveClassName(ifaceIdx, classNameIdx, utf8Pool);
                if (ifaceInternal != null) {
                    interfaces.add(ifaceInternal.replace('/', '.'));
                }
            }

            boolean usesReflectiveScanner = false;
            for (int i = 1; i < cpCount; i++) {
                String clsInternal = resolveClassName(i, classNameIdx, utf8Pool);
                if (clsInternal != null && REFLECTIVE_SCANNER_MARKERS.contains(clsInternal)) {
                    usesReflectiveScanner = true;
                }
            }

            int fieldsCount = in.readUnsignedShort();
            Set<String> declaredFields = new LinkedHashSet<>();
            for (int f = 0; f < fieldsCount; f++) {
                in.readUnsignedShort(); // flags
                int fNameIdx = in.readUnsignedShort();
                in.readUnsignedShort(); // desc
                String fName = safeUtf8(utf8Pool, fNameIdx);
                if (fName != null) {
                    declaredFields.add(fName);
                }
                int attrsCount = in.readUnsignedShort();
                for (int a = 0; a < attrsCount; a++) {
                    in.readUnsignedShort();
                    int len = in.readInt();
                    if (len > 0) {
                        in.skipBytes(len);
                    }
                }
            }

            // Read raw methods first so we can parse class-level BootstrapMethods before analyzing Code
            int methodsCount = in.readUnsignedShort();
            List<RawMethodData> rawMethods = new ArrayList<>(methodsCount);
            for (int m = 0; m < methodsCount; m++) {
                int mFlags = in.readUnsignedShort();
                int mNameIdx = in.readUnsignedShort();
                int mDescIdx = in.readUnsignedShort();
                String mName = safeUtf8(utf8Pool, mNameIdx);
                String mDesc = safeUtf8(utf8Pool, mDescIdx);
                ParsedAnnotations methodAnnotations = ParsedAnnotations.empty();
                byte[] codeBytes = null;
                List<ExceptionEntry> exceptionEntries = new ArrayList<>();

                int attrsCount = in.readUnsignedShort();
                for (int a = 0; a < attrsCount; a++) {
                    int attrNameIdx = in.readUnsignedShort();
                    int attrLen = in.readInt();
                    String attrName = safeUtf8(utf8Pool, attrNameIdx);
                    if ("Code".equals(attrName) && attrLen >= 8 && attrLen <= 262_144) {
                        byte[] attrData = new byte[attrLen];
                        in.readFully(attrData);
                        int codeLen = readInt(attrData, 4);
                        if (codeLen > 0 && 8 + codeLen <= attrData.length) {
                            codeBytes = new byte[codeLen];
                            System.arraycopy(attrData, 8, codeBytes, 0, codeLen);
                            int exOffset = 8 + codeLen;
                            if (exOffset + 2 <= attrData.length) {
                                int exCount = readUnsignedShort(attrData, exOffset);
                                int cur = exOffset + 2;
                                for (int e = 0; e < exCount && cur + 8 <= attrData.length; e++) {
                                    int startPc = readUnsignedShort(attrData, cur);
                                    int endPc = readUnsignedShort(attrData, cur + 2);
                                    int handlerPc = readUnsignedShort(attrData, cur + 4);
                                    int catchTypeIdx = readUnsignedShort(attrData, cur + 6);
                                    String catchCls = catchTypeIdx == 0
                                            ? null
                                            : resolveClassName(catchTypeIdx, classNameIdx, utf8Pool);
                                    exceptionEntries.add(new ExceptionEntry(startPc, endPc, handlerPc, catchCls));
                                    cur += 8;
                                }
                            }
                        }
                    } else if (("RuntimeVisibleAnnotations".equals(attrName)
                            || "RuntimeInvisibleAnnotations".equals(attrName)) && attrLen > 0 && attrLen <= 65536) {
                        byte[] annData = new byte[attrLen];
                        in.readFully(annData);
                        methodAnnotations = methodAnnotations.merge(extractAnnotationsFromAttribute(annData, utf8Pool, true));
                    } else if (attrLen > 0) {
                        in.skipBytes(attrLen);
                    }
                }
                if (mName != null) {
                    rawMethods.add(new RawMethodData(
                            mName,
                            mDesc != null ? mDesc : "()V",
                            mFlags,
                            methodAnnotations,
                            codeBytes,
                            exceptionEntries
                    ));
                }
            }

            // Parse class-level BootstrapMethods and class-level annotations
            Map<Integer, String> bootstrapTargetMethod = new LinkedHashMap<>();
            ParsedAnnotations classAnnotations = ParsedAnnotations.empty();
            int classAttrsCount = in.readUnsignedShort();
            for (int a = 0; a < classAttrsCount; a++) {
                int attrNameIdx = in.readUnsignedShort();
                int attrLen = in.readInt();
                String attrName = safeUtf8(utf8Pool, attrNameIdx);
                if ("BootstrapMethods".equals(attrName) && attrLen >= 2 && attrLen <= 262_144) {
                    byte[] bsmBytes = new byte[attrLen];
                    in.readFully(bsmBytes);
                    int numBsm = readUnsignedShort(bsmBytes, 0);
                    int cur = 2;
                    for (int b = 0; b < numBsm && cur + 4 <= bsmBytes.length; b++) {
                        int bsmRef = readUnsignedShort(bsmBytes, cur);
                        int numArgs = readUnsignedShort(bsmBytes, cur + 2);
                        cur += 4;
                        for (int argIdx = 0; argIdx < numArgs && cur + 2 <= bsmBytes.length; argIdx++) {
                            int argCpIdx = readUnsignedShort(bsmBytes, cur);
                            cur += 2;
                            if (argCpIdx > 0 && argCpIdx < cpCount && methodHandleRefIdx[argCpIdx] > 0) {
                                int targetRef = methodHandleRefIdx[argCpIdx];
                                String owner = resolveClassName(methodClassIdx[targetRef], classNameIdx, utf8Pool);
                                String name = resolveMethodName(targetRef, methodNatIdx, natNameIdx, utf8Pool);
                                if (owner != null && name != null) {
                                    bootstrapTargetMethod.put(b, owner.replace('/', '.') + "#" + name);
                                }
                            }
                        }
                        // Unused variable warning prevention
                        if (bsmRef < 0) {
                            break;
                        }
                    }
                } else if (("RuntimeVisibleAnnotations".equals(attrName)
                        || "RuntimeInvisibleAnnotations".equals(attrName)) && attrLen > 0 && attrLen <= 65536) {
                    byte[] annData = new byte[attrLen];
                    in.readFully(annData);
                    classAnnotations = classAnnotations.merge(extractAnnotationsFromAttribute(annData, utf8Pool, false));
                } else if (attrLen > 0) {
                    in.skipBytes(attrLen);
                }
            }

            Map<String, MethodNode> parsedMethods = new LinkedHashMap<>();
            for (RawMethodData rm : rawMethods) {
                MethodNode node = analyzeMethodBytecode(
                        binaryClassName,
                        rm,
                        classAnnotations,
                        utf8Pool,
                        numericPool,
                        classNameIdx,
                        stringUtf8Idx,
                        fieldClassIdx,
                        fieldNatIdx,
                        methodClassIdx,
                        methodNatIdx,
                        natNameIdx,
                        natDescIdx,
                        indyBootstrapIdx,
                        indyNatIdx,
                        bootstrapTargetMethod
                );
                String key = parsedMethods.containsKey(rm.name())
                        ? (rm.name() + rm.descriptor())
                        : rm.name();
                parsedMethods.put(key, node);
            }

            return new ParsedClass(
                    binaryClassName,
                    superBinary,
                    accessFlags,
                    interfaces,
                    declaredFields,
                    parsedMethods,
                    usesReflectiveScanner,
                    classAnnotations
            );
        } catch (IOException | RuntimeException e) {
            LOGGER.log(Level.FINE, "[LeafConfig] Skipping unreadable or non-standard .class payload", e);
            return null;
        }
    }

    private record RawMethodData(
            String name,
            String descriptor,
            int accessFlags,
            ParsedAnnotations annotations,
            byte[] code,
            List<ExceptionEntry> exceptionTable
    ) {
        boolean isEventHandler() {
            return annotations != null && annotations.isEventHandler();
        }
    }

    /**
     * Parses a JVMS 4.7.16 {@code RuntimeVisibleAnnotations} / {@code RuntimeInvisibleAnnotations}
     * attribute payload to extract {@code @EventHandler}/{@code @SubscribeEvent} markers and
     * annotation-driven command framework metadata ({@code ACF}, {@code Incendo Cloud},
     * {@code LiteCommands}, {@code Lamp}, {@code Triumph}).
     */
    private static ParsedAnnotations extractAnnotationsFromAttribute(
            byte[] annData,
            String[] utf8Pool,
            boolean isMethodTarget
    ) {
        if (annData == null || annData.length < 2) {
            return ParsedAnnotations.empty();
        }
        boolean isEventHandler = false;
        boolean isCommandEntry = false;
        Set<String> commandRoots = new LinkedHashSet<>();
        Set<String> subcommandLiterals = new LinkedHashSet<>();
        Set<String> permissions = new LinkedHashSet<>();
        StringBuilder descBuilder = new StringBuilder();

        int numAnn = readUnsignedShort(annData, 0);
        int pos = 2;
        for (int a = 0; a < numAnn && pos + 4 <= annData.length; a++) {
            int typeIdx = readUnsignedShort(annData, pos);
            int numPairs = readUnsignedShort(annData, pos + 2);
            pos += 4;
            String typeDesc = safeUtf8(utf8Pool, typeIdx);
            String simpleAnn = extractSimpleAnnotationName(typeDesc);

            if ("EventHandler".equals(simpleAnn)
                    || "SubscribeEvent".equals(simpleAnn)
                    || "Subscribe".equals(simpleAnn)) {
                isEventHandler = true;
            }
            if (isMethodTarget && ("CommandAlias".equals(simpleAnn)
                    || "Subcommand".equals(simpleAnn)
                    || "SubCommand".equals(simpleAnn)
                    || "CommandMethod".equals(simpleAnn)
                    || "Command".equals(simpleAnn)
                    || "Execute".equals(simpleAnn)
                    || "Default".equals(simpleAnn)
                    || "CatchUnknown".equals(simpleAnn)
                    || "HelpCommand".equals(simpleAnn))) {
                isCommandEntry = true;
            }

            for (int p = 0; p < numPairs && pos + 3 <= annData.length; p++) {
                int elemNameIdx = readUnsignedShort(annData, pos);
                String elemName = safeUtf8(utf8Pool, elemNameIdx);
                pos += 2;
                List<String> values = new ArrayList<>();
                pos = parseAnnotationElementValue(annData, pos, utf8Pool, values);
                if (values.isEmpty()) {
                    continue;
                }
                if ("CommandAlias".equals(simpleAnn) || "RootCommand".equals(simpleAnn)) {
                    for (String val : values) {
                        parsePipeAndSpaceCommandTokens(val, commandRoots, subcommandLiterals, true);
                    }
                } else if ("Command".equals(simpleAnn) || "CommandMethod".equals(simpleAnn)) {
                    boolean isSubField = "subcommand".equalsIgnoreCase(elemName);
                    for (String val : values) {
                        parsePipeAndSpaceCommandTokens(val, commandRoots, subcommandLiterals, !isSubField);
                    }
                } else if ("Subcommand".equals(simpleAnn) || "SubCommand".equals(simpleAnn) || "Execute".equals(simpleAnn)) {
                    for (String val : values) {
                        parsePipeAndSpaceCommandTokens(val, commandRoots, subcommandLiterals, false);
                    }
                } else if ("CommandPermission".equals(simpleAnn) || "Permission".equals(simpleAnn)) {
                    for (String val : values) {
                        for (String part : val.split("[|,\\s]+")) {
                            String trimmed = part.trim();
                            if (!trimmed.isEmpty()) {
                                permissions.add(trimmed);
                            }
                        }
                    }
                } else if ("CommandDescription".equals(simpleAnn) || "Description".equals(simpleAnn)) {
                    for (String val : values) {
                        if (!val.isBlank()) {
                            if (descBuilder.length() > 0) {
                                descBuilder.append(' ');
                            }
                            descBuilder.append(val.trim());
                        }
                    }
                }
            }
        }

        // Fallback constant-pool scan if bytecode used non-standard nested event annotations
        if (!isEventHandler) {
            for (int i = 0; i + 1 < annData.length; i++) {
                int idx = readUnsignedShort(annData, i);
                String s = safeUtf8(utf8Pool, idx);
                if (s != null && (s.contains("EventHandler") || s.contains("SubscribeEvent"))) {
                    isEventHandler = true;
                    break;
                }
            }
        }

        return new ParsedAnnotations(
                isEventHandler,
                isCommandEntry,
                new ArrayList<>(commandRoots),
                new ArrayList<>(subcommandLiterals),
                new ArrayList<>(permissions),
                descBuilder.toString()
        );
    }

    private static String extractSimpleAnnotationName(String typeDesc) {
        if (typeDesc == null || typeDesc.isEmpty()) {
            return "";
        }
        String s = typeDesc;
        if (s.startsWith("L") && s.endsWith(";")) {
            s = s.substring(1, s.length() - 1);
        }
        int slash = s.lastIndexOf('/');
        if (slash >= 0) {
            s = s.substring(slash + 1);
        }
        int dollar = s.lastIndexOf('$');
        if (dollar >= 0) {
            s = s.substring(dollar + 1);
        }
        return s;
    }

    private static void parsePipeAndSpaceCommandTokens(
            String raw,
            Set<String> outRoots,
            Set<String> outSubcommands,
            boolean firstTokenIsRoot
    ) {
        if (raw == null || raw.isBlank()) {
            return;
        }
        for (String pipeBranch : raw.split("\\|")) {
            String trimmed = pipeBranch.trim();
            if (trimmed.startsWith("/")) {
                trimmed = trimmed.substring(1).trim();
            }
            if (trimmed.isEmpty()) {
                continue;
            }
            String[] words = trimmed.split("\\s+");
            for (int i = 0; i < words.length; i++) {
                String tok = words[i].trim();
                if (tok.isEmpty() || tok.startsWith("<") || tok.startsWith("[") || tok.startsWith("-")) {
                    continue;
                }
                if (i == 0 && firstTokenIsRoot) {
                    outRoots.add(tok.toLowerCase(Locale.ROOT));
                } else if (isCandidateSubcommandLiteral(tok)) {
                    outSubcommands.add(tok.toLowerCase(Locale.ROOT));
                }
            }
        }
    }

    private static int parseAnnotationElementValue(
            byte[] data,
            int pos,
            String[] utf8Pool,
            List<String> outStrings
    ) {
        if (pos >= data.length) {
            return data.length;
        }
        int tag = data[pos++] & 0xFF;
        return switch (tag) {
            case 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z', 'c' -> Math.min(data.length, pos + 2);
            case 's' -> {
                if (pos + 2 > data.length) {
                    yield data.length;
                }
                String s = safeUtf8(utf8Pool, readUnsignedShort(data, pos));
                if (s != null && !s.isBlank()) {
                    outStrings.add(s.trim());
                }
                yield pos + 2;
            }
            case 'e' -> Math.min(data.length, pos + 4);
            case '@' -> {
                if (pos + 4 > data.length) {
                    yield data.length;
                }
                int nestedPairs = readUnsignedShort(data, pos + 2);
                int cur = pos + 4;
                for (int i = 0; i < nestedPairs && cur + 3 <= data.length; i++) {
                    cur += 2;
                    cur = parseAnnotationElementValue(data, cur, utf8Pool, outStrings);
                }
                yield cur;
            }
            case '[' -> {
                if (pos + 2 > data.length) {
                    yield data.length;
                }
                int numVals = readUnsignedShort(data, pos);
                int cur = pos + 2;
                for (int i = 0; i < numVals && cur < data.length; i++) {
                    cur = parseAnnotationElementValue(data, cur, utf8Pool, outStrings);
                }
                yield cur;
            }
            default -> data.length;
        };
    }

    private static MethodNode analyzeMethodBytecode(
            String binaryClassName,
            RawMethodData rm,
            ParsedAnnotations classAnnotations,
            String[] utf8Pool,
            String[] numericPool,
            int[] classNameIdx,
            int[] stringUtf8Idx,
            int[] fieldClassIdx,
            int[] fieldNatIdx,
            int[] methodClassIdx,
            int[] methodNatIdx,
            int[] natNameIdx,
            int[] natDescIdx,
            int[] indyBootstrapIdx,
            int[] indyNatIdx,
            Map<Integer, String> bootstrapTargetMethod
    ) {
        ParsedAnnotations methodAnn = rm.annotations() != null ? rm.annotations() : ParsedAnnotations.empty();
        ParsedAnnotations clsAnn = classAnnotations != null ? classAnnotations : ParsedAnnotations.empty();
        String eventTypeSimpleName = rm.isEventHandler() ? extractFirstParamSimpleType(rm.descriptor()) : "";
        Set<String> mergedCommandRoots = new LinkedHashSet<>(methodAnn.commandRoots());
        if (mergedCommandRoots.isEmpty()) {
            mergedCommandRoots.addAll(clsAnn.commandRoots());
        }
        Set<String> subcommandLiterals = new LinkedHashSet<>(methodAnn.subcommandLiterals());
        Set<String> argumentParsers = new LinkedHashSet<>();
        if (methodAnn.isCommandEntry()) {
            argumentParsers.addAll(extractDescriptorArgumentParsers(rm.descriptor()));
        }
        Set<String> inlinePermissions = new LinkedHashSet<>(clsAnn.permissions());
        inlinePermissions.addAll(methodAnn.permissions());
        String cmdDesc = !methodAnn.description().isBlank() ? methodAnn.description() : clsAnn.description();

        byte[] code = rm.code();
        if (code == null || code.length == 0) {
            return new MethodNode(
                    binaryClassName,
                    rm.name(),
                    rm.descriptor(),
                    rm.accessFlags(),
                    rm.isEventHandler(),
                    eventTypeSimpleName,
                    methodAnn.isCommandEntry(),
                    new ArrayList<>(mergedCommandRoots),
                    new ArrayList<>(subcommandLiterals),
                    new ArrayList<>(argumentParsers),
                    new ArrayList<>(inlinePermissions),
                    cmdDesc,
                    List.of(),
                    List.of(),
                    List.of(),
                    Set.of(),
                    Map.of(),
                    Map.of(),
                    Set.of(),
                    Set.of(),
                    Set.of(),
                    Set.of(),
                    Map.of(),
                    Map.of(),
                    Set.of(),
                    Set.of(),
                    List.of(),
                    Set.of(),
                    Set.of(),
                    List.of(),
                    false,
                    false,
                    false
            );
        }

        List<String> calledMethods = new ArrayList<>();
        List<String> spawnedLambdas = new ArrayList<>();
        List<String> orphanedSuppliers = new ArrayList<>();
        Set<String> instantiatedClasses = new LinkedHashSet<>();
        Map<String, String> conditionalInstantiations = new LinkedHashMap<>();
        Map<String, String> conditionalMethodCalls = new LinkedHashMap<>();
        Set<String> readFields = new LinkedHashSet<>();
        Set<String> writtenFields = new LinkedHashSet<>();
        Set<String> producedQueueFields = new LinkedHashSet<>();
        Set<String> dispatchedEventTypes = new LinkedHashSet<>();
        Map<String, String> configKeyToAssignedField = new LinkedHashMap<>();
        Map<String, String> configKeyScalingHint = new LinkedHashMap<>();
        Set<String> referencedConfigKeys = new LinkedHashSet<>();
        Set<String> stringLiterals = new LinkedHashSet<>();
        List<String> guards = new ArrayList<>();
        for (String annPerm : inlinePermissions) {
            guards.add("hasPermission(" + annPerm + ")");
        }
        Set<String> directEffectSinks = new LinkedHashSet<>();
        Set<String> syncMainThreadCalls = new LinkedHashSet<>();
        boolean callsCurrentTimeMillis = false;
        boolean multipliesBy1000Or20 = false;
        boolean usesDynamicConfigIteration = false;

        // Pass 1: Record conditional jump spans [branchPc -> targetPc] and early-return guard PCs
        // (`if (!flag) return;`) to detect generalized config/branch-gated listener registration.
        List<int[]> forwardConditionalSpans = new ArrayList<>();
        int firstEarlyReturnGuardPc = Integer.MAX_VALUE;
        int scanPc = 0;
        while (scanPc < code.length) {
            int op = code[scanPc] & 0xFF;
            int len = instructionLength(code, scanPc);
            if (len <= 0) {
                break;
            }
            if (((op >= 0x99 && op <= 0xA6) || op == 0xC6 || op == 0xC7) && scanPc + 2 < code.length) {
                short rel = (short) (((code[scanPc + 1] & 0xFF) << 8) | (code[scanPc + 2] & 0xFF));
                int targetPc = scanPc + rel;
                if (targetPc > scanPc) {
                    forwardConditionalSpans.add(new int[]{scanPc, targetPc});
                    // Check if the skipped block `[scanPc + len .. targetPc)` ends in an early `return` (0xB1)
                    int preTargetPc = targetPc - 1;
                    if (preTargetPc >= scanPc + len && preTargetPc < code.length && (code[preTargetPc] & 0xFF) == 0xB1) {
                        firstEarlyReturnGuardPc = Math.min(firstEarlyReturnGuardPc, preTargetPc);
                    }
                }
            }
            scanPc += len;
        }

        String recentConfigKey = null;
        String recentReadField = null;
        String recentReadFullField = null;
        String recentReadFieldDesc = null;
        String recentStringLiteral = null;
        String recentInstantiatedSimpleClass = null;
        String recentIndyLambdaTarget = null;
        int pc = 0;

        while (pc < code.length) {
            int op = code[pc] & 0xFF;
            int insLen = instructionLength(code, pc);
            if (insLen <= 0) {
                break;
            }

            // Detect numeric constants 1000 or 20 used for unit scaling
            String pushedConst = extractPushedConstant(code, pc, numericPool, stringUtf8Idx, utf8Pool);
            if ("1000".equals(pushedConst) || "1000.0".equals(pushedConst)
                    || "20".equals(pushedConst) || "20.0".equals(pushedConst)) {
                multipliesBy1000Or20 = true;
            }

            // String literals & config keys
            String strLiteral = null;
            if (op == 0x12 && pc + 1 < code.length) { // ldc
                int idx = code[pc + 1] & 0xFF;
                if (idx > 0 && idx < stringUtf8Idx.length && stringUtf8Idx[idx] > 0) {
                    strLiteral = safeUtf8(utf8Pool, stringUtf8Idx[idx]);
                }
            } else if (op == 0x13 && pc + 2 < code.length) { // ldc_w
                int idx = readUnsignedShort(code, pc + 1);
                if (idx > 0 && idx < stringUtf8Idx.length && stringUtf8Idx[idx] > 0) {
                    strLiteral = safeUtf8(utf8Pool, stringUtf8Idx[idx]);
                }
            } else if (op == 0xB2 && pc + 2 < code.length) { // getstatic *Keys/*Params enum
                int fCpIdx = readUnsignedShort(code, pc + 1);
                String enumKey = resolveConfigEnumKey(fCpIdx, fieldClassIdx, fieldNatIdx, classNameIdx, natNameIdx, utf8Pool);
                if (enumKey != null) {
                    strLiteral = enumKey;
                }
            }

            if (strLiteral != null && !strLiteral.isBlank()) {
                stringLiterals.add(strLiteral);
                recentStringLiteral = strLiteral;
                if (isCandidateSubcommandLiteral(strLiteral)
                        && lookaheadStringComparison(
                        code,
                        pc + insLen,
                        methodClassIdx,
                        methodNatIdx,
                        classNameIdx,
                        natNameIdx,
                        utf8Pool
                )) {
                    subcommandLiterals.add(strLiteral.toLowerCase(Locale.ROOT));
                }
                if (BytecodeConfigScanner.isPlausibleConfigKeyLiteral(strLiteral)) {
                    LookaheadConfigRead look = lookaheadConfigGetter(
                            code,
                            pc + insLen,
                            numericPool,
                            stringUtf8Idx,
                            fieldClassIdx,
                            fieldNatIdx,
                            methodClassIdx,
                            methodNatIdx,
                            classNameIdx,
                            natNameIdx,
                            utf8Pool
                    );
                    if (look.invokedGetter != null) {
                        referencedConfigKeys.add(strLiteral);
                        recentConfigKey = strLiteral;
                        if (look.scalingHint != null) {
                            configKeyScalingHint.put(strLiteral, look.scalingHint);
                            multipliesBy1000Or20 = true;
                        }
                        if (look.assignedField != null) {
                            configKeyToAssignedField.put(strLiteral, binaryClassName + "#" + look.assignedField);
                        }
                    }
                }
            }

            // Object instantiation: NEW (0xBB)
            if (op == 0xBB && pc + 2 < code.length) {
                int clsIdx = readUnsignedShort(code, pc + 1);
                String instInternal = resolveClassName(clsIdx, classNameIdx, utf8Pool);
                if (instInternal != null) {
                    String instBinary = instInternal.replace('/', '.');
                    instantiatedClasses.add(instBinary);
                    recentInstantiatedSimpleClass = simpleClassName(instBinary);
                    if (isInsideConditionalSpan(pc, forwardConditionalSpans) || pc > firstEarlyReturnGuardPc) {
                        String gateLabel = resolveGateLabel(recentConfigKey, referencedConfigKeys, recentReadField);
                        conditionalInstantiations.put(instBinary, gateLabel);
                    }
                }
            }

            // Field reads & writes: GETSTATIC (0xB2), PUTSTATIC (0xB3), GETFIELD (0xB4), PUTFIELD (0xB5)
            if ((op >= 0xB2 && op <= 0xB5) && pc + 2 < code.length) {
                int fCpIdx = readUnsignedShort(code, pc + 1);
                String fOwner = (fCpIdx > 0 && fCpIdx < fieldClassIdx.length)
                        ? resolveClassName(fieldClassIdx[fCpIdx], classNameIdx, utf8Pool)
                        : null;
                String fName = resolveFieldName(fCpIdx, fieldNatIdx, natNameIdx, utf8Pool);
                String fDesc = resolveMethodDesc(fCpIdx, fieldNatIdx, natDescIdx, utf8Pool);
                if (fOwner != null && fName != null && !fName.startsWith("$")) {
                    String fullField = fOwner.replace('/', '.') + "#" + fName;
                    if (op == 0xB2 || op == 0xB4) {
                        readFields.add(fullField);
                        recentReadField = fName;
                        recentReadFullField = fullField;
                        recentReadFieldDesc = fDesc;
                    } else {
                        writtenFields.add(fullField);
                    }
                }
            }

            // Method invocations: INVOKEVIRTUAL (0xB6), INVOKESPECIAL (0xB7), INVOKESTATIC (0xB8), INVOKEINTERFACE (0xB9)
            if ((op >= 0xB6 && op <= 0xB9) && pc + 2 < code.length) {
                int mCpIdx = readUnsignedShort(code, pc + 1);
                String mOwnerInternal = (mCpIdx > 0 && mCpIdx < methodClassIdx.length)
                        ? resolveClassName(methodClassIdx[mCpIdx], classNameIdx, utf8Pool)
                        : null;
                String mName = resolveMethodName(mCpIdx, methodNatIdx, natNameIdx, utf8Pool);
                String mDesc = resolveMethodDesc(mCpIdx, methodNatIdx, natDescIdx, utf8Pool);
                if (mOwnerInternal != null && mName != null) {
                    String mOwnerBinary = mOwnerInternal.replace('/', '.');
                    String callRef = mOwnerBinary + "#" + mName;
                    if (!"<init>".equals(mName) && !calledMethods.contains(callRef)) {
                        calledMethods.add(callRef);
                    }
                    if (!"<init>".equals(mName)
                            && (isInsideConditionalSpan(pc, forwardConditionalSpans) || pc > firstEarlyReturnGuardPc)) {
                        String gateLabel = resolveGateLabel(recentConfigKey, referencedConfigKeys, recentReadField);
                        conditionalMethodCalls.putIfAbsent(callRef, gateLabel);
                    }
                    if ("<init>".equals(mName)) {
                        instantiatedClasses.add(mOwnerBinary);
                        recentInstantiatedSimpleClass = simpleClassName(mOwnerBinary);
                        if (isInsideConditionalSpan(pc, forwardConditionalSpans) || pc > firstEarlyReturnGuardPc) {
                            String gateLabel = resolveGateLabel(recentConfigKey, referencedConfigKeys, recentReadField);
                            conditionalInstantiations.putIfAbsent(mOwnerBinary, gateLabel);
                        }
                    }

                    // Track custom event dispatch (`callEvent`, `EventBus#post`, `fireEvent`)
                    if (EVENT_DISPATCH_METHODS.contains(mName)) {
                        directEffectSinks.add("EVENT_DISPATCH");
                        if (recentInstantiatedSimpleClass != null && !recentInstantiatedSimpleClass.isEmpty()) {
                            dispatchedEventTypes.add(recentInstantiatedSimpleClass);
                        }
                    }

                    // Track collection/queue producer writes (`getfield queue` + `offer`/`add`/`put`/`push`)
                    if (recentReadFullField != null && QUEUE_PRODUCER_METHODS.contains(mName)) {
                        boolean isQueueLikeOwner = mOwnerInternal.contains("Queue")
                                || mOwnerInternal.contains("Deque")
                                || mOwnerInternal.contains("RingBuffer")
                                || (recentReadFieldDesc != null && (recentReadFieldDesc.contains("Queue")
                                || recentReadFieldDesc.contains("Deque")
                                || recentReadFieldDesc.contains("RingBuffer")));
                        if (isQueueLikeOwner) {
                            producedQueueFields.add(recentReadFullField);
                            directEffectSinks.add("QUEUE_HANDOFF");
                        } else if (mOwnerInternal.startsWith("java/util/") || mOwnerInternal.contains("Map") || mOwnerInternal.contains("Collection") || mOwnerInternal.contains("List") || mOwnerInternal.contains("Set")) {
                            writtenFields.add(recentReadFullField);
                        }
                    }

                    // Track white-box argument parser calls
                    String inferredParser = classifyArgumentParserCall(mOwnerInternal, mName);
                    if (inferredParser != null) {
                        argumentParsers.add(inferredParser);
                    }

                    if ("java/lang/System".equals(mOwnerInternal) && "currentTimeMillis".equals(mName)) {
                        callsCurrentTimeMillis = true;
                    }
                    if (mOwnerInternal.contains("TimeUnit") || mOwnerInternal.contains("Duration")
                            || "parseSecondsDurationMillis".equals(mName) || "parseDurationSetting".equals(mName)) {
                        multipliesBy1000Or20 = true;
                    }
                    if (DYNAMIC_CONFIG_ITERATION_METHODS.contains(mName)) {
                        usesDynamicConfigIteration = true;
                    }
                    if ("hasPermission".equals(mName) || "checkPermission".equals(mName)) {
                        if (recentStringLiteral != null && isPlausiblePermissionLiteral(recentStringLiteral)) {
                            inlinePermissions.add(recentStringLiteral);
                            String permGuard = "hasPermission(" + recentStringLiteral + ")";
                            if (!guards.contains(permGuard)) {
                                guards.add(permGuard);
                            }
                        } else if (!guards.contains("hasPermission")) {
                            guards.add("hasPermission");
                        }
                    }

                    classifyEffectSinkAndThreadSafety(
                            mOwnerInternal,
                            mName,
                            mDesc,
                            directEffectSinks,
                            syncMainThreadCalls
                    );

                    // Check if CompletableFuture.supplyAsync or Supplier.get is immediately followed by POP (0x57) or POP2 (0x58)
                    int nextPc = pc + insLen;
                    if (nextPc < code.length) {
                        int nextOp = code[nextPc] & 0xFF;
                        if (nextOp == 0x57 || nextOp == 0x58) {
                            boolean isSupplyAsync = mOwnerInternal.endsWith("CompletableFuture") && "supplyAsync".equals(mName);
                            boolean isSupplierGet = ("get".equals(mName) && mOwnerInternal.toLowerCase(Locale.ROOT).contains("supplier"))
                                    || (mDesc != null && mDesc.endsWith(")Ljava/util/concurrent/CompletableFuture;")
                                    && ("get".equals(mName) || mName.startsWith("supply") || mName.startsWith("compute")
                                    || mName.startsWith("locate") || mName.startsWith("fetch")));
                            if (isSupplyAsync || isSupplierGet) {
                                String orphanTarget = (isSupplyAsync && recentIndyLambdaTarget != null)
                                        ? recentIndyLambdaTarget
                                        : callRef;
                                if (!orphanedSuppliers.contains(orphanTarget)) {
                                    orphanedSuppliers.add(orphanTarget);
                                }
                            }
                        }
                    }
                    recentIndyLambdaTarget = null;
                }
            }

            // INVOKEDYNAMIC (0xBA): link to BootstrapMethods target lambda/method-reference
            if (op == 0xBA && pc + 2 < code.length) {
                int indyCpIdx = readUnsignedShort(code, pc + 1);
                if (indyCpIdx > 0 && indyCpIdx < indyBootstrapIdx.length) {
                    int bsmIdx = indyBootstrapIdx[indyCpIdx];
                    String targetLambda = bootstrapTargetMethod.get(bsmIdx);
                    if (targetLambda != null) {
                        if (!spawnedLambdas.contains(targetLambda)) {
                            spawnedLambdas.add(targetLambda);
                        }
                        recentIndyLambdaTarget = targetLambda;
                    }
                }
            }

            pc += insLen;
        }

        // Check exception table for empty catch blocks (S-004 CLAIM_SWALLOWED_FAILURE)
        List<String> swallowedExceptions = new ArrayList<>();
        for (ExceptionEntry ex : rm.exceptionTable()) {
            if (ex.catchClassInternal() == null || BENIGN_CAUGHT_EXCEPTIONS.contains(ex.catchClassInternal())) {
                continue;
            }
            if (isSilentCatchHandler(code, ex.handlerPc())) {
                String caughtBinary = ex.catchClassInternal().replace('/', '.');
                if (!swallowedExceptions.contains(caughtBinary)) {
                    swallowedExceptions.add(caughtBinary);
                }
            }
        }

        return new MethodNode(
                binaryClassName,
                rm.name(),
                rm.descriptor(),
                rm.accessFlags(),
                rm.isEventHandler(),
                eventTypeSimpleName,
                methodAnn.isCommandEntry(),
                new ArrayList<>(mergedCommandRoots),
                new ArrayList<>(subcommandLiterals),
                new ArrayList<>(argumentParsers),
                new ArrayList<>(inlinePermissions),
                cmdDesc,
                calledMethods,
                spawnedLambdas,
                orphanedSuppliers,
                instantiatedClasses,
                conditionalInstantiations,
                conditionalMethodCalls,
                readFields,
                writtenFields,
                producedQueueFields,
                dispatchedEventTypes,
                configKeyToAssignedField,
                configKeyScalingHint,
                referencedConfigKeys,
                stringLiterals,
                guards,
                directEffectSinks,
                syncMainThreadCalls,
                swallowedExceptions,
                callsCurrentTimeMillis,
                multipliesBy1000Or20,
                usesDynamicConfigIteration
        );
    }

    private record LookaheadConfigRead(
            String invokedGetter,
            String assignedField,
            String scalingHint
    ) {
    }

    private static LookaheadConfigRead lookaheadConfigGetter(
            byte[] code,
            int startPc,
            String[] numericPool,
            int[] stringUtf8Idx,
            int[] fieldClassIdx,
            int[] fieldNatIdx,
            int[] methodClassIdx,
            int[] methodNatIdx,
            int[] classNameIdx,
            int[] natNameIdx,
            String[] utf8Pool
    ) {
        int pc = startPc;
        int steps = 0;
        String getter = null;
        String assignedField = null;
        String scalingHint = null;

        while (pc < code.length && steps < 16) {
            int op = code[pc] & 0xFF;
            int len = instructionLength(code, pc);
            if (len <= 0) {
                break;
            }
            if (getter == null && (op == 0x12 || op == 0x13 || op == 0xB3 || op == 0xB5 || (op >= 0xAC && op <= 0xB1))) {
                break;
            }
            String c = extractPushedConstant(code, pc, numericPool, stringUtf8Idx, utf8Pool);
            if (getter != null && c != null) {
                if ("1000".equals(c) || "1000.0".equals(c)) {
                    scalingHint = "*1000_MS";
                } else if ("20".equals(c) || "20.0".equals(c)) {
                    scalingHint = "*20_TICKS";
                }
            }
            if ((op == 0xB6 || op == 0xB8 || op == 0xB9) && pc + 2 < code.length) {
                int mCpIdx = readUnsignedShort(code, pc + 1);
                String mName = resolveMethodName(mCpIdx, methodNatIdx, natNameIdx, utf8Pool);
                if (mName != null && CONFIG_GETTER_METHODS.contains(mName) && getter == null) {
                    getter = mName;
                    if ("parseSecondsDurationMillis".equals(mName) || "parseDurationSetting".equals(mName)) {
                        scalingHint = "*1000_MS";
                    }
                }
            } else if ((op == 0xB3 || op == 0xB5) && pc + 2 < code.length && getter != null) {
                int fCpIdx = readUnsignedShort(code, pc + 1);
                String candidateField = resolveFieldName(fCpIdx, fieldNatIdx, natNameIdx, utf8Pool);
                if (candidateField != null
                        && !(candidateField.equals(candidateField.toUpperCase(Locale.ROOT)) && candidateField.contains("_"))) {
                    assignedField = candidateField;
                }
                break;
            }
            pc += len;
            steps++;
        }
        return new LookaheadConfigRead(getter, assignedField, scalingHint);
    }

    private static String resolveGateLabel(
            String recentConfigKey,
            Set<String> referencedConfigKeys,
            String recentReadField
    ) {
        if (recentConfigKey != null && !recentConfigKey.isBlank()) {
            return recentConfigKey;
        }
        if (referencedConfigKeys != null && !referencedConfigKeys.isEmpty()) {
            return referencedConfigKeys.iterator().next();
        }
        if (recentReadField != null && !recentReadField.isBlank()) {
            return recentReadField;
        }
        return "conditional-branch";
    }

    private static boolean isInsideConditionalSpan(int pc, List<int[]> spans) {
        for (int[] span : spans) {
            if (pc > span[0] && pc < span[1]) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks whether a catch block at {@code handlerPc} immediately discards the exception and
     * returns (`RETURN` or `ACONST_NULL + ARETURN`) without invoking any
     * logging, messaging, or recovery method (`S-004`).
     */
    private static boolean isSilentCatchHandler(byte[] code, int handlerPc) {
        if (handlerPc < 0 || handlerPc >= code.length) {
            return false;
        }
        int pc = handlerPc;
        int op0 = code[pc] & 0xFF;
        int len0 = instructionLength(code, pc);
        if (len0 <= 0) {
            return false;
        }
        // Exception object on stack is stored (`astore` 0x3A or `astore_0..3` 0x4B..0x4E) or popped (`pop` 0x57)
        boolean storesOrPopsException = (op0 == 0x3A) || (op0 >= 0x4B && op0 <= 0x4E) || (op0 == 0x57);
        if (!storesOrPopsException) {
            return false;
        }
        int nextPc = pc + len0;
        if (nextPc >= code.length) {
            return false;
        }
        int op1 = code[nextPc] & 0xFF;
        // Immediate `return` (0xB1)
        if (op1 == 0xB1) {
            return true;
        }
        // Immediate `aconst_null` (0x01) + `areturn` (0xB0)
        if (op1 == 0x01 && nextPc + 1 < code.length) {
            int op2 = code[nextPc + 1] & 0xFF;
            return op2 == 0xB0;
        }
        return false;
    }

    private static void classifyEffectSinkAndThreadSafety(
            String ownerInternal,
            String methodName,
            String methodDesc,
            Set<String> directEffectSinks,
            Set<String> syncMainThreadCalls
    ) {
        String combined = (ownerInternal + "#" + methodName).toLowerCase(Locale.ROOT);
        if (combined.contains("teleport")) {
            directEffectSinks.add("TELEPORT");
            if ("teleport".equals(methodName)
                    && (ownerInternal.contains("org/bukkit/entity") || ownerInternal.contains("Player") || ownerInternal.contains("Entity"))) {
                syncMainThreadCalls.add(simpleClassName(ownerInternal) + "#teleport");
            }
        }
        if (combined.contains("openinventory") || combined.contains("openbook") || combined.contains("showmenu")
                || combined.contains("createinventory") || combined.contains("openmenu")
                || (ownerInternal.contains("menu") && ("open".equals(methodName) || "stage".equals(methodName) || "redeem".equals(methodName)))) {
            directEffectSinks.add("INVENTORY_MENU");
        }
        if (combined.contains("settype") || combined.contains("setblockdata") || combined.contains("breaknaturally")
                || combined.contains("spawnentity") || combined.contains("createexplosion")
                || combined.contains("sethealth") || combined.contains("setfoodlevel")) {
            directEffectSinks.add("WORLD_MUTATION");
            if (ownerInternal.startsWith("org/bukkit/")) {
                syncMainThreadCalls.add(simpleClassName(ownerInternal) + "#" + methodName);
            }
        }
        if (("getchunkat".equals(methodName.toLowerCase(Locale.ROOT)) || "loadchunk".equals(methodName.toLowerCase(Locale.ROOT)))
                && !methodName.toLowerCase(Locale.ROOT).contains("async")) {
            directEffectSinks.add("CHUNK_IO");
            syncMainThreadCalls.add(simpleClassName(ownerInternal) + "#" + methodName);
        } else if (combined.contains("getchunkatasync")) {
            directEffectSinks.add("CHUNK_IO");
        }
        if (combined.contains("withdraw") || combined.contains("deposit") || combined.contains("economy")) {
            directEffectSinks.add("ECONOMY");
        }
        if (combined.contains("executeupdate") || combined.contains("executequery") || combined.contains("saveconfig")
                || combined.contains("writestring") || combined.contains("files#write")
                || combined.contains("export") || combined.contains("writebytes")) {
            directEffectSinks.add("STORAGE_IO");
        }
        if ("setcancelled".equals(methodName.toLowerCase(Locale.ROOT))) {
            directEffectSinks.add("EVENT_CANCEL");
        }
        if (combined.contains("runtaskasynchronously") || combined.contains("supplyasync")
                || combined.contains("runasync") || combined.contains("asyncscheduler")) {
            directEffectSinks.add("ASYNC_SCHEDULER");
        } else if (combined.contains("runtask") || combined.contains("schedule")) {
            directEffectSinks.add("SCHEDULER_TASK");
        }
        if ("sendmessage".equals(methodName.toLowerCase(Locale.ROOT)) || combined.contains("sendactionbar")
                || combined.contains("sendtitle")) {
            directEffectSinks.add("MESSAGE_ONLY");
        }
        if (combined.contains("playsound") || combined.contains("spawnparticle")) {
            directEffectSinks.add("SOUND_PARTICLE_ONLY");
        }
        boolean isQueueType = ownerInternal.contains("Queue")
                || ownerInternal.contains("Deque")
                || ownerInternal.contains("RingBuffer");
        if (!isQueueType && ((methodDesc != null && methodDesc.startsWith("()V") && methodName.startsWith("set") && methodName.length() > 3)
                || "put".equals(methodName) || "putIfAbsent".equals(methodName) || "computeIfAbsent".equals(methodName)
                || "add".equals(methodName) || "offer".equals(methodName) || "push".equals(methodName)
                || "remove".equals(methodName) || "clear".equals(methodName) || "complete".equals(methodName)
                || "submitCommand".equals(methodName) || "dispatchCommand".equals(methodName)
                || "performCommand".equals(methodName) || "accept".equals(methodName)
                || "apply".equals(methodName) || "execute".equals(methodName))) {
            directEffectSinks.add("STATE_MUTATION");
        }
    }

    private static boolean isCandidateSubcommandLiteral(String literal) {
        if (literal == null || literal.length() < 2 || literal.length() > 24) {
            return false;
        }
        String low = literal.toLowerCase(Locale.ROOT);
        if (NON_SUBCOMMAND_LITERALS.contains(low)) {
            return false;
        }
        char first = low.charAt(0);
        if (first < 'a' || first > 'z') {
            return false;
        }
        for (int i = 1; i < low.length(); i++) {
            char c = low.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private static boolean isPlausiblePermissionLiteral(String literal) {
        if (literal == null || literal.length() < 3 || literal.length() > 80 || !literal.contains(".")) {
            return false;
        }
        for (int i = 0; i < literal.length(); i++) {
            char c = literal.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || c == '.'
                    || c == '_'
                    || c == '-'
                    || c == '*';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private static boolean lookaheadStringComparison(
            byte[] code,
            int startPc,
            int[] methodClassIdx,
            int[] methodNatIdx,
            int[] classNameIdx,
            int[] natNameIdx,
            String[] utf8Pool
    ) {
        int pc = startPc;
        int steps = 0;
        while (pc < code.length && steps < 6 && (pc - startPc) <= 16) {
            int op = code[pc] & 0xFF;
            int len = instructionLength(code, pc);
            if (len <= 0) {
                break;
            }
            if ((op >= 0xB6 && op <= 0xB9) && pc + 2 < code.length) {
                int mCpIdx = readUnsignedShort(code, pc + 1);
                String mOwner = resolveClassName(methodClassIdx[mCpIdx], classNameIdx, utf8Pool);
                String mName = resolveMethodName(mCpIdx, methodNatIdx, natNameIdx, utf8Pool);
                if (mOwner != null && mName != null) {
                    if ("java/lang/String".equals(mOwner) && STRING_COMPARE_METHODS.contains(mName)) {
                        return true;
                    }
                    break;
                }
            }
            pc += len;
            steps++;
        }
        return false;
    }

    private static String classifyArgumentParserCall(String ownerInternal, String methodName) {
        if (ownerInternal == null || methodName == null) {
            return null;
        }
        if ("java/lang/Integer".equals(ownerInternal)
                && ("parseInt".equals(methodName) || "valueOf".equals(methodName) || "decode".equals(methodName))) {
            return "brigadier:integer";
        }
        if ("java/lang/Long".equals(ownerInternal)
                && ("parseLong".equals(methodName) || "valueOf".equals(methodName))) {
            return "brigadier:long";
        }
        if ("java/lang/Double".equals(ownerInternal)
                && ("parseDouble".equals(methodName) || "valueOf".equals(methodName))) {
            return "brigadier:double";
        }
        if ("java/lang/Float".equals(ownerInternal)
                && ("parseFloat".equals(methodName) || "valueOf".equals(methodName))) {
            return "brigadier:float";
        }
        if ("java/lang/Boolean".equals(ownerInternal) && "parseBoolean".equals(methodName)) {
            return "brigadier:bool";
        }
        if ("java/util/UUID".equals(ownerInternal) && "fromString".equals(methodName)) {
            return "minecraft:uuid";
        }
        if ((ownerInternal.endsWith("Bukkit") || ownerInternal.endsWith("Server"))
                && ("getPlayer".equals(methodName) || "getPlayerExact".equals(methodName) || "getOfflinePlayer".equals(methodName))) {
            return "minecraft:game_profile";
        }
        if ((ownerInternal.endsWith("Bukkit") || ownerInternal.endsWith("Server")) && "getWorld".equals(methodName)) {
            return "minecraft:dimension";
        }
        if (ownerInternal.endsWith("Material")
                && ("matchMaterial".equals(methodName) || "getMaterial".equals(methodName) || "valueOf".equals(methodName))) {
            return "minecraft:item_stack";
        }
        return null;
    }

    private static List<String> extractDescriptorArgumentParsers(String desc) {
        if (desc == null || !desc.startsWith("(")) {
            return List.of();
        }
        int endParams = desc.indexOf(')');
        if (endParams <= 1) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        int idx = 1;
        int paramPos = 0;
        while (idx < endParams) {
            char c = desc.charAt(idx);
            if (c == '[') {
                idx++;
                continue;
            }
            if (c == 'L') {
                int semi = desc.indexOf(';', idx);
                if (semi < 0 || semi > endParams) {
                    break;
                }
                String internal = desc.substring(idx + 1, semi);
                idx = semi + 1;
                // Skip leading CommandSender/Player/Context parameter at slot 0
                if (paramPos == 0 && (internal.contains("CommandSender")
                        || internal.contains("Player")
                        || internal.contains("Context")
                        || internal.contains("CommandIssuer")
                        || internal.contains("CommandSource"))) {
                    paramPos++;
                    continue;
                }
                if ("java/lang/Integer".equals(internal)) {
                    out.add("brigadier:integer");
                } else if ("java/lang/Long".equals(internal)) {
                    out.add("brigadier:long");
                } else if ("java/lang/Double".equals(internal)) {
                    out.add("brigadier:double");
                } else if ("java/lang/Float".equals(internal)) {
                    out.add("brigadier:float");
                } else if ("java/lang/Boolean".equals(internal)) {
                    out.add("brigadier:bool");
                } else if (internal.endsWith("World")) {
                    out.add("minecraft:dimension");
                } else if (internal.endsWith("Player") || internal.endsWith("OfflinePlayer")) {
                    out.add("minecraft:game_profile");
                } else if (internal.endsWith("Material")) {
                    out.add("minecraft:item_stack");
                } else if ("java/util/UUID".equals(internal)) {
                    out.add("minecraft:uuid");
                }
                paramPos++;
            } else {
                idx++;
                if (c == 'I' || c == 'S' || c == 'B') {
                    out.add("brigadier:integer");
                } else if (c == 'J') {
                    out.add("brigadier:long");
                } else if (c == 'D') {
                    out.add("brigadier:double");
                } else if (c == 'F') {
                    out.add("brigadier:float");
                } else if (c == 'Z') {
                    out.add("brigadier:bool");
                }
                paramPos++;
            }
        }
        return out;
    }

    private static String extractFirstParamSimpleType(String desc) {
        if (desc == null || !desc.startsWith("(L")) {
            return "";
        }
        int semi = desc.indexOf(';');
        if (semi <= 2) {
            return "";
        }
        String internal = desc.substring(2, semi);
        return simpleClassName(internal);
    }

    private static String simpleClassName(String name) {
        if (name == null || name.isEmpty()) {
            return "";
        }
        String norm = name.replace('/', '.');
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

    private static String resolveClassName(int classCpIdx, int[] classNameIdx, String[] utf8Pool) {
        if (classCpIdx <= 0 || classCpIdx >= classNameIdx.length) {
            return null;
        }
        int utfIdx = classNameIdx[classCpIdx];
        return safeUtf8(utf8Pool, utfIdx);
    }

    private static String resolveFieldName(int fieldCpIdx, int[] fieldNatIdx, int[] natNameIdx, String[] utf8Pool) {
        if (fieldCpIdx <= 0 || fieldCpIdx >= fieldNatIdx.length) {
            return null;
        }
        int nat = fieldNatIdx[fieldCpIdx];
        if (nat <= 0 || nat >= natNameIdx.length) {
            return null;
        }
        return safeUtf8(utf8Pool, natNameIdx[nat]);
    }

    private static String resolveMethodName(int methodCpIdx, int[] methodNatIdx, int[] natNameIdx, String[] utf8Pool) {
        if (methodCpIdx <= 0 || methodCpIdx >= methodNatIdx.length) {
            return null;
        }
        int nat = methodNatIdx[methodCpIdx];
        if (nat <= 0 || nat >= natNameIdx.length) {
            return null;
        }
        return safeUtf8(utf8Pool, natNameIdx[nat]);
    }

    private static String resolveMethodDesc(int methodCpIdx, int[] methodNatIdx, int[] natDescIdx, String[] utf8Pool) {
        if (methodCpIdx <= 0 || methodCpIdx >= methodNatIdx.length) {
            return null;
        }
        int nat = methodNatIdx[methodCpIdx];
        if (nat <= 0 || nat >= natDescIdx.length) {
            return null;
        }
        return safeUtf8(utf8Pool, natDescIdx[nat]);
    }

    private static String resolveConfigEnumKey(
            int fieldCpIdx,
            int[] fieldClassIdx,
            int[] fieldNatIdx,
            int[] classNameIdx,
            int[] natNameIdx,
            String[] utf8Pool
    ) {
        if (fieldCpIdx <= 0 || fieldCpIdx >= fieldNatIdx.length) {
            return null;
        }
        int nat = fieldNatIdx[fieldCpIdx];
        if (nat <= 0 || nat >= natNameIdx.length) {
            return null;
        }
        String ownerInternal = resolveClassName(fieldClassIdx[fieldCpIdx], classNameIdx, utf8Pool);
        String fieldName = safeUtf8(utf8Pool, natNameIdx[nat]);
        if (ownerInternal == null || fieldName == null || fieldName.startsWith("$")) {
            return null;
        }
        int slash = ownerInternal.lastIndexOf('/');
        String simpleOwner = slash >= 0 ? ownerInternal.substring(slash + 1) : ownerInternal;
        if ((simpleOwner.endsWith("Keys") || simpleOwner.endsWith("Params") || simpleOwner.endsWith("Settings"))
                && !simpleOwner.equals("Keys")) {
            return BytecodeConfigScanner.isPlausibleConfigKeyLiteral(fieldName) ? fieldName : null;
        }
        return null;
    }

    private static String safeUtf8(String[] utf8Pool, int index) {
        if (index <= 0 || index >= utf8Pool.length) {
            return null;
        }
        return utf8Pool[index];
    }

    private static String extractPushedConstant(
            byte[] code,
            int pc,
            String[] numericPool,
            int[] stringUtf8Idx,
            String[] utf8Pool
    ) {
        int op = code[pc] & 0xFF;
        return switch (op) {
            case 0x02 -> "-1";
            case 0x03, 0x09 -> "0";
            case 0x04, 0x0A -> "1";
            case 0x05 -> "2";
            case 0x06 -> "3";
            case 0x07 -> "4";
            case 0x08 -> "5";
            case 0x10 -> pc + 1 < code.length ? Integer.toString(code[pc + 1]) : null;
            case 0x11 -> pc + 2 < code.length ? Integer.toString((short) readUnsignedShort(code, pc + 1)) : null;
            case 0x12 -> {
                if (pc + 1 >= code.length) {
                    yield null;
                }
                int idx = code[pc + 1] & 0xFF;
                if (idx > 0 && idx < numericPool.length && numericPool[idx] != null) {
                    yield numericPool[idx];
                }
                if (idx > 0 && idx < stringUtf8Idx.length && stringUtf8Idx[idx] > 0) {
                    yield safeUtf8(utf8Pool, stringUtf8Idx[idx]);
                }
                yield null;
            }
            case 0x13, 0x14 -> {
                if (pc + 2 >= code.length) {
                    yield null;
                }
                int idx = readUnsignedShort(code, pc + 1);
                if (idx > 0 && idx < numericPool.length && numericPool[idx] != null) {
                    yield numericPool[idx];
                }
                if (op == 0x13 && idx > 0 && idx < stringUtf8Idx.length && stringUtf8Idx[idx] > 0) {
                    yield safeUtf8(utf8Pool, stringUtf8Idx[idx]);
                }
                yield null;
            }
            default -> null;
        };
    }

    private static int instructionLength(byte[] code, int pc) {
        int op = code[pc] & 0xFF;
        return switch (op) {
            case 0x10, 0x12, 0x15, 0x16, 0x17, 0x18, 0x19, 0x36, 0x37, 0x38, 0x39, 0x3A, 0xA9, 0xBC -> 2;
            case 0x11, 0x13, 0x14, 0x84, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4,
                    0xA5, 0xA6, 0xA7, 0xA8, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xBB, 0xBD, 0xC0, 0xC1, 0xC6, 0xC7 -> 3;
            case 0xC5 -> 4;
            case 0xB9, 0xBA, 0xC8, 0xC9 -> 5;
            case 0xAA -> { // tableswitch
                int aligned = (pc + 4) & ~3;
                if (aligned + 12 > code.length) {
                    yield -1;
                }
                int low = readInt(code, aligned + 4);
                int high = readInt(code, aligned + 8);
                long count = (long) high - (long) low + 1L;
                if (count < 0 || count > 16384) {
                    yield -1;
                }
                yield (aligned - pc) + 12 + (int) (count * 4);
            }
            case 0xAB -> { // lookupswitch
                int aligned = (pc + 4) & ~3;
                if (aligned + 8 > code.length) {
                    yield -1;
                }
                int npairs = readInt(code, aligned + 4);
                if (npairs < 0 || npairs > 16384) {
                    yield -1;
                }
                yield (aligned - pc) + 8 + (npairs * 8);
            }
            case 0xC4 -> { // wide
                if (pc + 1 >= code.length) {
                    yield -1;
                }
                int nextOp = code[pc + 1] & 0xFF;
                yield nextOp == 0x84 ? 6 : 4;
            }
            default -> 1;
        };
    }

    private static int readUnsignedShort(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    private static int readInt(byte[] b, int off) {
        return ((b[off] & 0xFF) << 24)
                | ((b[off + 1] & 0xFF) << 16)
                | ((b[off + 2] & 0xFF) << 8)
                | (b[off + 3] & 0xFF);
    }

    private static byte[] readBoundedBytes(ZipFile zip, ZipEntry entry) throws IOException {
        long size = entry.getSize();
        if (size > MAX_RESOURCE_BYTES) {
            return null;
        }
        try (InputStream in = zip.getInputStream(entry);
             ByteArrayOutputStream out = new ByteArrayOutputStream(size > 0 ? (int) size : 4096)) {
            byte[] buf = new byte[8192];
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

    private static boolean isShadedLibraryClass(String entryName) {
        return entryName.startsWith("META-INF/")
                || entryName.startsWith("kotlin/")
                || entryName.startsWith("kotlinx/")
                || entryName.startsWith("org/slf4j/")
                || entryName.startsWith("com/google/")
                || entryName.startsWith("io/netty/")
                || entryName.startsWith("org/yaml/snakeyaml/")
                || entryName.startsWith("com/zaxxer/hikari/")
                || entryName.startsWith("org/sqlite/")
                || entryName.startsWith("org/mariadb/")
                || entryName.startsWith("com/mysql/")
                || entryName.startsWith("org/bstats/");
    }
}
