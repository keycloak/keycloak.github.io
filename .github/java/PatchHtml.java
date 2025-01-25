import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.regex.Matcher;

/**
 * Patch HTML files to have a Google Analytics so we can track their use,
 * robot exclusion for the nightly build,
 * and a canonical URL to avoid duplicate content at Google that is pointing to the latest build of the file if it exists.
 */
public class PatchHtml {
    public static void main(String[] args) throws IOException {
        // Either pass the files on the CLI, or stream then in the input.
        if (args.length > 0) {
            for (String file : args) {
                patch(file);
            }
        } else {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            while(reader.ready()) {
                String file = reader.readLine();
                patch(file);
            }
        }
    }

    private static void patch(String file) throws IOException {
        String original = Files.readString(Path.of(file));
        String content = original;
        content = content.replaceAll("(?ms)<!-- CUSTOM HEADER START.*CUSTOM HEADER END -->\n*", "");

        String canonical = file;
        canonical = canonical.replaceAll("^docs/[^/]*", "docs/latest");
        canonical = canonical.replaceAll("^docs-api/[^/]*", "docs-api/latest");
        if (!canonical.endsWith(".html")) {
            canonical = "";
        } else if (Files.exists(Path.of(canonical))) {
            canonical = "<link rel=\"canonical\" href=\"https://www.keycloak.org/" + canonical + "\">\n";
        } else if (canonical.endsWith("securing_apps/index.html")) {
            canonical = "docs/25.0.6/securing_apps/index.html";
            canonical = "<link rel=\"canonical\" href=\"https://www.keycloak.org/" + canonical + "\">\n";
        } else {
            canonical = "";
        }

        String robots;
        if (file.contains("nightly")) {
            robots = "<meta name=\"robots\" content=\"noindex\">\n";
        } else {
            robots = "";
        }

        content = content.replaceAll("<head>", Matcher.quoteReplacement("""
                <head>
                <!-- CUSTOM HEADER START -->
                """ +
                canonical +
                robots +
                """
                <script async src="https://www.googletagmanager.com/gtag/js?id=G-0J2P9316N6"></script>
                <script>
                    window.dataLayer = window.dataLayer || [];
                    function gtag(){dataLayer.push(arguments);}
                    gtag('js', new Date());
                    gtag('config', 'G-0J2P9316N6');
                </script>
                <!-- CUSTOM HEADER END -->"""));
        if (!Objects.equals(original, content)) {
            System.out.println("Patched " + file);
            Files.writeString(Path.of(file), content);
        }
    }
}