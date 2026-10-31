package net.leaf.sleuth.common.fuzz;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit and edge-case tests for {@link JarClassOwnershipIndex}
 * ({@code REQ-SLEUTH-FUZZ-001}, {@code ADR-125}, {@code leafsleuth-ADR-006}).
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy ADR-129
 * @governedBy leafsleuth-ADR-006
 * @trace REQ-SLEUTH-FUZZ-001
 * @trace S-005
 */
class JarClassOwnershipIndexTest {

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-001: JarClassOwnershipIndex maps unique classes to owning JAR, filters multi-JAR shaded classes, and skips self and corrupt JARs")
    void scansPluginJarsFiltersShadedCollisionsAndSkipsCorruptArchives(@TempDir Path pluginsDir) throws IOException {
        // 1. Plugin A with unique classes + shaded Gson + nested jarjar
        byte[] nestedJar = buildJarBytes(Map.of(
                "com/example/alpha/nested/EmbeddedHelper.class", new byte[]{(byte) 0xCA, (byte) 0xFE}
        ));
        writeJar(pluginsDir.resolve("AlphaPlugin-1.2.jar"), Map.of(
                "plugin.yml", ("name: AlphaPlugin\ndepend: [Vault]\nsoftdepend:\n  - PlaceholderAPI\n").getBytes(StandardCharsets.UTF_8),
                "com/example/alpha/AlphaMain.class", new byte[]{1, 2, 3},
                "com/example/alpha/session/AlphaSession.class", new byte[]{1, 2, 3},
                "com/google/gson/Gson.class", new byte[]{4, 5, 6},
                "org/bstats/bukkit/Metrics.class", new byte[]{7, 8, 9},
                "META-INF/jars/alpha-nested.jar", nestedJar
        ));

        // 2. Plugin B with unique classes + same shaded Gson and bStats + multi-release class entry
        writeJar(pluginsDir.resolve("BetaTeleports-2.0.jar"), Map.of(
                "paper-plugin.yml", ("name: BetaTeleports\n").getBytes(StandardCharsets.UTF_8),
                "com/example/beta/BetaService.class", new byte[]{1, 2, 3},
                "META-INF/versions/17/com/example/beta/Java17FastPath.class", new byte[]{1, 2, 3},
                "com/google/gson/Gson.class", new byte[]{4, 5, 6},
                "org/bstats/bukkit/Metrics.class", new byte[]{7, 8, 9}
        ));

        // 3. Self diagnostic JAR (must be skipped when selfJarPrefix = "LeafSleuth")
        writeJar(pluginsDir.resolve("LeafSleuth-0.1.0.jar"), Map.of(
                "plugin.yml", ("name: LeafSleuth\n").getBytes(StandardCharsets.UTF_8),
                "net/leaf/sleuth/paper/LeafSleuthPaperPlugin.class", new byte[]{1},
                "com/example/alpha/AlphaMain.class", new byte[]{1}
        ));

        // 4. Corrupt / truncated JAR in plugins/ (must be skipped with warning without aborting scan)
        Files.writeString(pluginsDir.resolve("CorruptBroken.jar"), "not-a-valid-zip-archive", StandardCharsets.UTF_8);

        JarClassOwnershipIndex index = JarClassOwnershipIndex.scanPluginsDirectory(pluginsDir, "LeafSleuth");

        assertEquals(2, index.indexedJarCount(), "Expected only AlphaPlugin and BetaTeleports to be indexed");
        assertTrue(index.descriptors().containsKey("AlphaPlugin-1.2.jar"));
        assertTrue(index.descriptors().containsKey("BetaTeleports-2.0.jar"));
        assertEquals("AlphaPlugin", index.descriptors().get("AlphaPlugin-1.2.jar").pluginId());
        assertEquals(List.of("Vault"), index.descriptors().get("AlphaPlugin-1.2.jar").hardDepends());
        assertEquals(List.of("PlaceholderAPI"), index.descriptors().get("AlphaPlugin-1.2.jar").softDepends());

        // Unique plugin classes resolve to their owning JAR (including inner/lambda/array forms and nested JARs)
        assertEquals(
                Optional.of("AlphaPlugin-1.2.jar"),
                index.ownerJarForClass("com.example.alpha.AlphaMain")
        );
        assertEquals(
                Optional.of("AlphaPlugin-1.2.jar"),
                index.ownerJarForClass("com.example.alpha.session.AlphaSession$ PendingTask$$Lambda/0x0000000801".replace(" ", ""))
        );
        assertEquals(
                Optional.of("AlphaPlugin-1.2.jar"),
                index.ownerJarForClass("[Lcom.example.alpha.session.AlphaSession;")
        );
        assertEquals(
                Optional.of("AlphaPlugin-1.2.jar"),
                index.ownerJarForClass("com.example.alpha.nested.EmbeddedHelper")
        );
        assertEquals(
                Optional.of("BetaTeleports-2.0.jar"),
                index.ownerJarForClass("com.example.beta.Java17FastPath")
        );

        // Multi-JAR shaded classes are marked shared and NEVER blamed on a single JAR
        Set<String> shared = index.sharedClasses();
        assertTrue(shared.contains("com.google.gson.Gson"));
        assertTrue(shared.contains("org.bstats.bukkit.Metrics"));
        assertEquals(Optional.empty(), index.ownerJarForClass("com.google.gson.Gson"));
        assertEquals(Optional.empty(), index.ownerJarForClass("org.bstats.bukkit.Metrics"));
        assertEquals(
                Set.of("AlphaPlugin-1.2.jar", "BetaTeleports-2.0.jar"),
                index.allOwnersForClass("com.google.gson.Gson")
        );

        // Stack trace attribution skips JDK/server and shared shaded frames to identify the first unique plugin JAR
        List<String> stackTrace = List.of(
                "at java.base/java.util.HashMap.putNode(HashMap.java:631)",
                "at com.google.gson.Gson.toJson(Gson.java:712)",
                "at BetaTeleports-2.0.jar//com.example.beta.BetaService.teleportPlayer(BetaService.java:142)",
                "at com.example.alpha.AlphaMain.onCommand(AlphaMain.java:55)"
        );
        assertEquals(
                Optional.of("BetaTeleports-2.0.jar"),
                index.firstSuspectJar(stackTrace)
        );
        assertFalse(index.ownerJarForClass("java.util.HashMap").isPresent());
    }

    private static void writeJar(Path path, Map<String, byte[]> entries) throws IOException {
        Files.write(path, buildJarBytes(entries));
    }

    private static byte[] buildJarBytes(Map<String, byte[]> entries) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                ZipEntry ze = new ZipEntry(e.getKey());
                zos.putNextEntry(ze);
                zos.write(e.getValue());
                zos.closeEntry();
            }
        }
        return baos.toByteArray();
    }
}
