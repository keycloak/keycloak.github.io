import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Delete all documentation directories not specified in archive/active-docs-versions.txt file.
 * This file is generated in keycloak-web project.
 *
 * The file will be deleted after it is processed.
 *
 * If the file doesn't exist no action is taken.
 */
public class DeleteUnlinkedDocs {

    public static String ACTIVE_DOCS_VERSIONS = "archive/active-archive-versions.txt";

    public static final String[] docDirs = {"docs", "docs-api"};
    public static final Set<String> activeVersions = new HashSet<>();

    public static void main(String[] args) throws IOException {

        File activeDocsVersions = new File(ACTIVE_DOCS_VERSIONS);
        if (!activeDocsVersions.exists() || !activeDocsVersions.canRead()) {
            System.out.printf("No spec file %s. Nothing to delete.%n", ACTIVE_DOCS_VERSIONS);
            return;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(activeDocsVersions))) {
            String line;
            while ((line = br.readLine()) != null) {
                activeVersions.add(line);
            }
        }

        for (String dir : docDirs) {
            deleteUnlinkedDocs(dir);
        }

    }

    public static void deleteUnlinkedDocs(String dir) throws IOException {
        Path docsDir = Paths.get(dir);

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(docsDir)) {
            for (Path entry : stream) {
                if (Files.isDirectory(entry)) {
                    System.out.print("Dir: " + entry.getFileName());
                    if (!activeVersions.contains(entry.getFileName().toString())) {
                        System.out.println(" deleted");
                        deletePath(entry);
                    } else {
                        System.out.println();
                    }
                }
            }
        }

    }

    private static void deletePath(Path toDelete) throws IOException {
        try (Stream<Path> walk = Files.walk(toDelete)) {
            walk.sorted(Comparator.reverseOrder())
                    .forEach(path -> {
                        try {
                            Files.delete(path);
                        } catch (IOException e) {
                            System.err.printf("Failed to delete %s : %s%n", path, e.getMessage());
                        }
                    });
        }
    }

}
