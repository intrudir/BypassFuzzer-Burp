package com.bypassfuzzer.core.payloads;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UrlPayloadProcessorTest {

    @Test
    void expandCaseVariants_noHexLettersReturnsOriginalOnly() {
        assertEquals(List.of("../"), UrlPayloadProcessor.expandCaseVariants("../"));
        assertEquals(List.of("%20%23"), UrlPayloadProcessor.expandCaseVariants("%20%23"));
    }

    @Test
    void expandCaseVariants_singleLetterProducesBothCases() {
        List<String> variants = UrlPayloadProcessor.expandCaseVariants("%2e");
        assertTrue(variants.contains("%2e"));
        assertTrue(variants.contains("%2E"));
        assertEquals(2, variants.size());
    }

    @Test
    void expandCaseVariants_percentUFiveArgFormNotTouched() {
        // %u002e is IIS-style Unicode escape (not a real percent-encoding). The '%u'
        // prefix is not a valid %XX triplet, so the expander leaves it verbatim.
        // To exercise both cases we rely on the hand-written %U002E variant in the file.
        List<String> variants = UrlPayloadProcessor.expandCaseVariants("%u002e");
        assertEquals(List.of("%u002e"), variants);
    }

    @Test
    void expandCaseVariants_doubleEncodedTripletHandled() {
        // The trailing '2e' of %252e is the hex payload of a double-encoded dot.
        // Expander must toggle its 'e' to cover decoder-case bugs on the 2nd level
        // (e.g. React %252F vs %252f).
        List<String> variants = UrlPayloadProcessor.expandCaseVariants("%252e");
        assertTrue(variants.contains("%252e"));
        assertTrue(variants.contains("%252E"));
        assertEquals(2, variants.size());
    }

    @Test
    void expandCaseVariants_multiLetterCartesian() {
        List<String> variants = UrlPayloadProcessor.expandCaseVariants("%2e%2f");
        assertTrue(variants.contains("%2e%2f"));
        assertTrue(variants.contains("%2E%2f"));
        assertTrue(variants.contains("%2e%2F"));
        assertTrue(variants.contains("%2E%2F"));
        assertEquals(4, variants.size());
    }

    @Test
    void expandCaseVariants_aboveCapFallsBackToJustAllLowerAndAllUpper() {
        // %ef%bc%8f has 5 hex letters (e,f,b,c,f) > LETTER_CAP=4.
        List<String> variants = UrlPayloadProcessor.expandCaseVariants("%ef%bc%8f");
        assertTrue(variants.contains("%ef%bc%8f"));
        assertTrue(variants.contains("%EF%BC%8F"));
        assertTrue(variants.size() <= 3);
    }

    @Test
    void expandCaseVariants_preservesNonLetterBytes() {
        List<String> variants = UrlPayloadProcessor.expandCaseVariants("/%2e%2e/admin");
        for (String v : variants) {
            assertTrue(v.startsWith("/") && v.endsWith("/admin"),
                    "non-hex bytes should be untouched: " + v);
        }
    }

    @Test
    void parseClassifiedPayload_untaggedGetsDefaultThreeClasses() {
        UrlPayloadProcessor.Classified c = UrlPayloadProcessor.parseClassifiedPayload("../");
        assertEquals("../", c.payload);
        assertTrue(c.classes.contains(UrlPayloadProcessor.InjectionClass.PREFIX));
        assertTrue(c.classes.contains(UrlPayloadProcessor.InjectionClass.SUFFIX));
        assertTrue(c.classes.contains(UrlPayloadProcessor.InjectionClass.SANDWICH));
        assertFalse(c.classes.contains(UrlPayloadProcessor.InjectionClass.BETWEEN));
    }

    @Test
    void parseClassifiedPayload_suffixOnlyTagParsed() {
        UrlPayloadProcessor.Classified c = UrlPayloadProcessor.parseClassifiedPayload("[s]?admin");
        assertEquals("?admin", c.payload);
        assertEquals(1, c.classes.size());
        assertTrue(c.classes.contains(UrlPayloadProcessor.InjectionClass.SUFFIX));
    }

    @Test
    void parseClassifiedPayload_betweenTagParsed() {
        UrlPayloadProcessor.Classified c = UrlPayloadProcessor.parseClassifiedPayload("[b]..;");
        assertEquals("..;", c.payload);
        assertEquals(Set.of(UrlPayloadProcessor.InjectionClass.BETWEEN), c.classes);
    }

    @Test
    void parseClassifiedPayload_allTagExpandsToAllClasses() {
        UrlPayloadProcessor.Classified c = UrlPayloadProcessor.parseClassifiedPayload("[a]..");
        assertEquals(UrlPayloadProcessor.InjectionClass.values().length, c.classes.size());
    }

    @Test
    void parseClassifiedPayload_multiCharTagParsed() {
        UrlPayloadProcessor.Classified c = UrlPayloadProcessor.parseClassifiedPayload("[pb]..");
        assertEquals(Set.of(
                UrlPayloadProcessor.InjectionClass.PREFIX,
                UrlPayloadProcessor.InjectionClass.BETWEEN), c.classes);
    }

    @Test
    void parseClassifiedPayload_bracketInPayloadNotInterpretedAsTag() {
        // A real payload can't start with '[xxx]' where xxx are all pswba chars,
        // but a payload like [xyz]... has invalid flag chars so the whole thing
        // should be treated as the raw payload (no match).
        UrlPayloadProcessor.Classified c = UrlPayloadProcessor.parseClassifiedPayload("[xyz]foo");
        assertEquals("[xyz]foo", c.payload);
        assertEquals(UrlPayloadProcessor.InjectionClass.PREFIX,
                c.classes.iterator().next()); // has default classes
    }

    @Test
    void expandCharEncodedVariants_singleAndDoubleLevelPerChar() {
        List<String> variants = UrlPayloadProcessor.expandCharEncodedVariants("admin");
        assertTrue(variants.contains("%61dmin"), "single-encoded first char");
        assertTrue(variants.contains("a%64min"), "single-encoded second char");
        assertTrue(variants.contains("adm%69n"), "single-encoded fourth char");
        assertTrue(variants.contains("admi%6e"), "single-encoded last char");
        assertTrue(variants.contains("%2561dmin"), "double-encoded first char");
        assertTrue(variants.contains("a%2564min"), "double-encoded second char");
        assertTrue(variants.contains("%61%64%6d%69%6e"), "fully-encoded segment");
    }

    @Test
    void generator_perCharEncodedUrlsLandOnTarget() throws Exception {
        UrlPayloadProcessor p = new UrlPayloadProcessor("https://example.com/admin");
        List<String> out = p.generateUrlPayloads(List.of());
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/%61dmin")),
                "expected /%61dmin in output; got " + out);
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/adm%69n")),
                "expected /adm%69n in output; got " + out);
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/%61%64%6d%69%6e")
                        || u.endsWith("/%61%64%6d%69%6E")
                        || u.endsWith("/%61%64%6D%69%6e")
                        || u.endsWith("/%61%64%6D%69%6E")),
                "expected fully encoded /admin in some hex case; got " + out);
    }

    @Test
    void isTraversalLike_catchesKnownForms() {
        assertTrue(UrlPayloadProcessor.isTraversalLike("../"));
        assertTrue(UrlPayloadProcessor.isTraversalLike("..;/"));
        assertTrue(UrlPayloadProcessor.isTraversalLike("%2e%2e"));
        assertTrue(UrlPayloadProcessor.isTraversalLike("%2E%2E%2F"));
        assertTrue(UrlPayloadProcessor.isTraversalLike("%252e%252e"));
        assertTrue(UrlPayloadProcessor.isTraversalLike("%c0%ae%c0%ae"));
        assertTrue(UrlPayloadProcessor.isTraversalLike("%ef%bc%8e%ef%bc%8e"));
        assertTrue(UrlPayloadProcessor.isTraversalLike("x/.."));
        assertTrue(UrlPayloadProcessor.isTraversalLike(".%2e"));
    }

    @Test
    void isTraversalLike_rejectsSingleDotAndOtherNonTraversals() {
        assertFalse(UrlPayloadProcessor.isTraversalLike("."));
        assertFalse(UrlPayloadProcessor.isTraversalLike("%2e"));
        assertFalse(UrlPayloadProcessor.isTraversalLike("/"));
        assertFalse(UrlPayloadProcessor.isTraversalLike(";"));
        assertFalse(UrlPayloadProcessor.isTraversalLike("%09"));
        assertFalse(UrlPayloadProcessor.isTraversalLike(".html"));
    }

    @Test
    void generator_traversalPrefixRestrictedToSegmentZero() throws Exception {
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/api/admin/users");
        List<String> out = processor.generateUrlPayloads(List.of("../"));
        // Segment-0 prefix should be present:
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/../api/admin/users")),
                "traversal PREFIX on seg 0 should still emit; got " + out);
        // Mid-path prefixes would reroute off-target — must not appear:
        assertFalse(out.stream().anyMatch(u -> u.contains("/api/../admin/users")),
                "traversal PREFIX on seg 1 reroutes off-target; must be skipped; got " + out);
        assertFalse(out.stream().anyMatch(u -> u.contains("/api/admin/../users")),
                "traversal PREFIX on seg 2 reroutes off-target; must be skipped; got " + out);
    }

    @Test
    void generator_traversalSuffixAndSandwichSkipped() throws Exception {
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/api/admin/users");
        List<String> out = processor.generateUrlPayloads(List.of("../"));
        assertFalse(out.stream().anyMatch(u -> u.contains("/api../")),
                "traversal SUFFIX produces literal 'api..' segment — off-target; got " + out);
        assertFalse(out.stream().anyMatch(u -> u.contains("/users../")),
                "traversal SUFFIX on last segment — off-target; got " + out);
    }

    @Test
    void generator_nonTraversalPrefixStillHitsAllSegments() throws Exception {
        // ';' is not traversal — should still be PREFIX-injected at every segment.
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/api/admin/users");
        List<String> out = processor.generateUrlPayloads(List.of(";"));
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/;api/admin/users")),
                "non-traversal PREFIX seg 0; got " + out);
        assertTrue(out.stream().anyMatch(u -> u.contains("/api/;admin/users")),
                "non-traversal PREFIX seg 1 must still emit; got " + out);
    }

    @Test
    void generator_insertsStandaloneSemicolonSegmentsAtEveryPathBoundary() throws Exception {
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/v1/console/plus?mode=full");
        List<String> out = processor.generateUrlPayloads(List.of());

        assertTrue(out.contains("https://example.com/v1/;/console/plus?mode=full"));
        assertTrue(out.contains("https://example.com/v1/console/;/plus?mode=full"));
        assertTrue(out.contains("https://example.com/v1/;/console/;/plus?mode=full"));
        assertTrue(out.contains("https://example.com/v1/%3b/console/plus?mode=full"));
        assertTrue(out.contains("https://example.com/v1/console/%3b/plus?mode=full"));
        assertTrue(out.contains("https://example.com/v1/%3b/console/%3b/plus?mode=full"));
    }

    @Test
    void generator_surroundsEachPathSegmentWithStandaloneSemicolonSegments() throws Exception {
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/api/v2/admin/users/profile");
        List<String> out = processor.generateUrlPayloads(List.of());

        assertTrue(out.contains("https://example.com/api/;/v2/;/admin/users/profile"));
        assertTrue(out.contains("https://example.com/api/v2/;/admin/;/users/profile"));
        assertTrue(out.contains("https://example.com/api/v2/admin/;/users/;/profile"));
        assertTrue(out.contains("https://example.com/;/api/;/v2/admin/users/profile"));
        assertTrue(out.contains("https://example.com/api/v2/admin/users/;/profile/;"));
        assertTrue(out.contains("https://example.com/api/%3b/v2/%3b/admin/users/profile"));
    }

    @Test
    void generator_surroundsSegmentsWithDotEncodedAndUnicodeMarkerVariants() throws Exception {
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/api/v2/admin");
        List<String> out = processor.generateUrlPayloads(List.of());

        assertTrue(out.contains("https://example.com/api/./v2/./admin"));
        assertTrue(out.contains("https://example.com/api/%2e/v2/%2e/admin"));
        assertTrue(out.contains("https://example.com/api/%2E/v2/%2E/admin"));
        assertTrue(out.contains("https://example.com/api/%252e/v2/%252e/admin"));
        assertTrue(out.contains("https://example.com/api/%u002e/v2/%u002e/admin"));
        assertTrue(out.contains("https://example.com/api/%U002E/v2/%U002E/admin"));
        assertTrue(out.contains("https://example.com/api/%253b/v2/%253b/admin"));
        assertTrue(out.contains("https://example.com/api/%u003b/v2/%u003b/admin"));
        assertTrue(out.contains("https://example.com/api/%U003B/v2/%U003B/admin"));
    }

    @Test
    void generator_realWorldTripleSlashBypassEmitted() throws Exception {
        // Real engagement: POST /api/v1/users was 403 (ACL blocking user
        // registration). Same request to POST /api///v1/users returned 201
        // and created an admin user. Our // payload SUFFIX-injected on
        // segment 0 produces exactly this shape.
        UrlPayloadProcessor p = new UrlPayloadProcessor("https://target.example/api/v1/users");
        List<String> out = p.generateUrlPayloads(List.of("//"));
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/api///v1/users")),
            "expected /api///v1/users (real-world production bypass); got " + out.size() + " URLs");
    }

    @Test
    void generator_orangeNuxeoRceChainShapeEmitted() throws Exception {
        // Orange Tsai BH 2018: /nuxeo/login.jsp;/..;/create_file.xhtml.
        // Composite matrix+traversal+matrix shape. For target /create_file.xhtml
        // we want the sacrificial prefix "x;/..;/" to HEAD-insert correctly.
        UrlPayloadProcessor p = new UrlPayloadProcessor("https://example.com/create_file.xhtml");
        List<String> out = p.generateUrlPayloads(List.of("[h]x;/..;/"));
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/x;/..;//create_file.xhtml")),
            "expected /x;/..;/ composite; got " + out);
    }

    @Test
    void generator_orangeMultiSegmentMatrixShapeEmitted() throws Exception {
        // Orange Tsai BH 2018: /login;foo/bar;quz. Sacrificial chain with
        // matrix params on two placeholder segments before the traversal.
        UrlPayloadProcessor p = new UrlPayloadProcessor("https://example.com/admin");
        List<String> out = p.generateUrlPayloads(List.of("[h]x;a=1/y;b=2/.."));
        assertTrue(out.stream().anyMatch(u -> u.contains("x;a=1/y;b=2/..")),
            "expected x;a=1/y;b=2/.. multi-matrix HEAD chain; got " + out);
    }

    @Test
    void generator_tiurinCacheDeceptionExtensionsEmitted() throws Exception {
        // Tiurin ZeroNights 2018 / Gil BH 2017 — cache deception via
        // Varnish/Cloudflare regex bypass. For target /admin, suffix
        // payloads like /admin?.jpg and /admin/.css must be emitted.
        UrlPayloadProcessor p = new UrlPayloadProcessor("https://example.com/admin");
        List<String> out = p.generateUrlPayloads(List.of());
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/admin?.jpg")),
            "expected /admin?.jpg cache-deception suffix; got " + out.size() + " URLs");
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/admin/.css")),
            "expected /admin/.css Cloudflare-style suffix");
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/admin;.js")),
            "expected /admin;.js CF matrix extension suffix");
    }

    @Test
    void generator_matrixFormatSuffixesCoverAuthzParserDifferentials() throws Exception {
        // Real-world miss: /something was 401, but /something;.json routed to
        // the same handler after framework matrix-param stripping and returned
        // 200. Cover the exact shape plus nearby encoded/reversed variants.
        UrlPayloadProcessor p = new UrlPayloadProcessor("https://example.com/something");
        List<String> out = p.generateUrlPayloads(List.of());
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/something;.json")),
            "expected exact matrix JSON suffix /something;.json");
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/something%3b.json"))
                || out.stream().anyMatch(u -> u.endsWith("/something%3B.json")),
            "expected encoded semicolon JSON suffix");
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/something;.html")),
            "expected matrix HTML suffix sibling");
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/something;.xml")),
            "expected matrix XML suffix sibling");
        for (String extension : PayloadLoader.loadPayloads("extension_payloads.txt")) {
            assertTrue(out.stream().anyMatch(u -> u.endsWith("/something;" + extension)),
                "expected matrix suffix for extension payload " + extension);
        }
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/something.json;")),
            "expected reversed extension-then-matrix suffix");
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/something.bak;")),
            "expected reversed extension-then-matrix suffix for non-API extension");
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/something.json;jsessionid=1")),
            "expected extension-then-named-matrix suffix");
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/something.tar.gz;foo=bar")),
            "expected named matrix suffix for compound extension");
    }

    @Test
    void generator_tiurinHashPrefixBypassEmitted() throws Exception {
        // Nginx + Weblogic bypass from Tiurin (ZeroNights 2018): /#/../<target>.
        // Nginx treats # as fragment, but Weblogic parses it as a path byte and
        // normalizes the traversal.
        UrlPayloadProcessor p = new UrlPayloadProcessor("https://example.com/Login.jsp");
        List<String> out = p.generateUrlPayloads(List.of("[h]#/..", "[h]#/../"));
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/#/../Login.jsp")),
            "expected /#/../Login.jsp (Tiurin Nginx+Weblogic bypass); got " + out);
    }

    @Test
    void generator_tiurinDoubleSlashDotSegmentCombosEmitted() throws Exception {
        // Tiurin Apache-rewrite bypass family: /x/..//target, /x//./../target,
        // /x/.//../target. All must fire as HEAD-insertions. The join adds a
        // '/' between the payload and the first segment, so a trailing slash
        // in the payload becomes '//' before the target — both shapes are
        // meaningful against different parsers.
        UrlPayloadProcessor p = new UrlPayloadProcessor("https://example.com/admin");
        List<String> out = p.generateUrlPayloads(List.of(
            "[h]x//..", "[h]x//./..", "[h]x/.//..", "[h]x/.//../"
        ));
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/x//../admin")),
            "expected /x//../admin from [h]x//..");
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/x//./../admin")),
            "expected /x//./../admin from [h]x//./..");
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/x/.//../admin")),
            "expected /x/.//../admin from [h]x/.//..");
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/x/.//..//admin")),
            "expected /x/.//..//admin from [h]x/.//../");
    }

    @Test
    void generator_sacrificialPrefixLandsOnTargetShape() throws Exception {
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/admin");
        List<String> out = processor.generateUrlPayloads(List.of("[h]x/.."));
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/x/../admin")),
                "expected /x/../admin from [h]x/.. ; got " + out);
    }

    @Test
    void generator_headInjectionPositionZeroOnly() throws Exception {
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/api/admin/users");
        List<String> out = processor.generateUrlPayloads(List.of("[h]..;"));
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/..;/api/admin/users")),
                "HEAD should put payload before first segment; got " + out);
        assertFalse(out.stream().anyMatch(u -> u.contains("/api/..;/admin")),
                "HEAD must NOT inject at non-zero positions (would reroute off-target); got " + out);
        assertFalse(out.stream().anyMatch(u -> u.endsWith("/..;") && !u.endsWith("/..;/api/admin/users")),
                "HEAD must NOT append at end; got " + out);
    }

    @Test
    void generator_crossEncodingChainsStayOnTarget() throws Exception {
        // Target /admin: the whole point is that bypass URLs still resolve to /admin
        // after normalization. BETWEEN mid-path on ../..%2f would produce /api/../..%2f/
        // which goes up and off target. Cross-chains must use only HEAD/PREFIX.
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/api/admin/users");
        List<String> out = processor.generateUrlPayloads(List.of());
        // Cross-chain mid-path between-segment forms should NOT exist:
        assertFalse(out.stream().anyMatch(u -> u.matches(".*/api/\\.\\.(/|%2f)\\.\\.(/|%2f)/admin.*")),
                "cross-chain must not insert between segments; got " + out);
    }

    @Test
    void generator_betweenInjectionInsertsNewSegment() throws Exception {
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/api/v1/users");
        List<String> out = processor.generateUrlPayloads(List.of("[b]..;"));
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/..;/api/v1/users")),
                "BETWEEN should produce ..; before first segment; got " + out);
        assertTrue(out.stream().anyMatch(u -> u.contains("/api/..;/v1/users")),
                "BETWEEN should produce ..; between api and v1; got " + out);
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/api/v1/users/..;")),
                "BETWEEN should produce ..; after last segment; got " + out);
    }

    @Test
    void generator_suffixOnlyPayloadDoesNotAppearAsPrefix() throws Exception {
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/api/v1/users");
        List<String> out = processor.generateUrlPayloads(List.of("[s]?evil"));
        assertFalse(out.stream().anyMatch(u -> u.contains("/?evilapi")),
                "[s] payload should not be prefix-injected; got " + out);
        assertTrue(out.stream().anyMatch(u -> u.contains("users?evil")),
                "[s] payload should still be suffix-appended; got " + out);
    }

    @Test
    void embeddedPayloadFileLoads() {
        List<String> payloads = PayloadLoader.loadPayloads("url_payloads.txt");
        assertFalse(payloads.isEmpty(), "url_payloads.txt must load");
        assertTrue(payloads.size() > 300, "expected > 300 payloads in file, got " + payloads.size());
        for (String p : payloads) {
            assertFalse(p.trim().startsWith("#"), "comment leaked into payload list: " + p);
            assertFalse(p.isBlank(), "blank payload leaked into list");
        }
    }

    @Test
    void processorGeneratesUrlsForEveryPayloadWithoutThrowing() throws Exception {
        List<String> payloads = PayloadLoader.loadPayloads("url_payloads.txt");
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/api/v1/users");

        List<String> generated = processor.generateUrlPayloads(payloads);

        assertFalse(generated.isEmpty(), "processor produced zero URLs");
        for (String url : generated) {
            assertTrue(url.startsWith("https://example.com/"),
                    "generated URL escaped origin: " + url);
        }
    }

    @Test
    void rootOnlyUrlProducesSuffixPayloadsOnly() throws Exception {
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/");
        List<String> generated = processor.generateUrlPayloads(List.of("../", "..%2f"));
        assertTrue(generated.isEmpty() || generated.stream().allMatch(u -> u.startsWith("https://example.com/")),
                "root-only URL should not produce foreign origins");
    }

    @Test
    void expandSegmentCase_fullCartesianUnderCap() {
        List<String> variants = UrlPayloadProcessor.expandSegmentCase("api");
        assertEquals(8, variants.size());
        assertTrue(variants.contains("api"));
        assertTrue(variants.contains("API"));
        assertTrue(variants.contains("Api"));
        assertTrue(variants.contains("aPi"));
        assertTrue(variants.contains("apI"));
    }

    @Test
    void expandSegmentCase_aboveCapFallsBackToAllLowerAndAllUpper() {
        List<String> variants = UrlPayloadProcessor.expandSegmentCase("dashboard");
        assertEquals(2, variants.size());
        assertTrue(variants.contains("dashboard"));
        assertTrue(variants.contains("DASHBOARD"));
    }

    @Test
    void expandSegmentCase_digitsAndSymbolsUntouched() {
        assertEquals(List.of("123"), UrlPayloadProcessor.expandSegmentCase("123"));
        List<String> v1 = UrlPayloadProcessor.expandSegmentCase("v1");
        assertEquals(2, v1.size());
        assertTrue(v1.contains("v1"));
        assertTrue(v1.contains("V1"));
    }

    @Test
    void generator_outputIsDeterministicAcrossRuns() throws Exception {
        UrlPayloadProcessor p1 = new UrlPayloadProcessor("https://example.com/api/v1/users");
        UrlPayloadProcessor p2 = new UrlPayloadProcessor("https://example.com/api/v1/users");
        List<String> out1 = p1.generateUrlPayloads(List.of("../", "%2e%2e%2f"));
        List<String> out2 = p2.generateUrlPayloads(List.of("../", "%2e%2e%2f"));
        assertEquals(out1, out2, "two runs must produce identical URLs (was flaky under old random-case)");
    }

    @Test
    void generator_wholePathAllUpperAppears() throws Exception {
        UrlPayloadProcessor p = new UrlPayloadProcessor("https://example.com/api/v1/users");
        List<String> out = p.generateUrlPayloads(List.of());
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/API/V1/USERS")),
                "whole-path all-upper URL should appear; got " + out);
    }

    @Test
    void crossEncodingChains_twoAndThreeElementDistinct() {
        List<String> chains = UrlPayloadProcessor.generateCrossEncodingChains();
        // 5*4 = 20 two-chains (pairs non-equal) + 5*4*3 = 60 three-chains (all distinct)
        assertEquals(80, chains.size(), "expected 20 two-chains + 60 three-chains = 80");
        assertTrue(chains.contains("../..%2f"));
        assertTrue(chains.contains("..;/%2e%2e%2f"));
        // Sample three-chains (all three distinct primitives)
        assertTrue(chains.contains("../..%2f..;/"), "expected ../..%2f..;/ three-chain");
        assertTrue(chains.contains("%2e%2e/..%2f../"), "expected 3-chain starting with %2e%2e/");
    }

    @Test
    void crossEncodingChains_appearInGeneratedUrls() throws Exception {
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/api/v1/users");
        List<String> urls = processor.generateUrlPayloads(List.of());
        assertTrue(urls.stream().anyMatch(u -> u.contains("../..%2f")),
                "cross-encoded chain ../..%2f should appear somewhere in URLs");
        assertTrue(urls.stream().anyMatch(u -> u.contains("%2e%2e%2f..;/")
                        || u.contains("..;/%2e%2e%2f")),
                "at least one ..;/ <-> %2e%2e%2f cross-chain should appear");
    }

    @Test
    void rootUrlWithBetweenTagProducesPayloads() throws Exception {
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/");
        List<String> generated = processor.generateUrlPayloads(List.of("[b]..;", "[b]%2e%2e"));
        assertFalse(generated.isEmpty(), "root URL with [b] payloads should produce URLs");
        assertTrue(generated.stream().anyMatch(u -> u.contains("..;")),
                "expected ..; to appear in some root-targeted URL; got " + generated);
    }

    @Test
    void reportPayloadSurvivalAndManglingRate() throws Exception {
        List<String> payloads = PayloadLoader.loadPayloads("url_payloads.txt");
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/api/v1/users");
        List<String> generated = processor.generateUrlPayloads(payloads);

        int survived = 0;
        int onlyMangled = 0;
        List<String> vanished = new java.util.ArrayList<>();

        for (String p : payloads) {
            // Strip any classification tag (e.g. [s]?) to the raw payload content;
            // that's what actually reaches the wire.
            String content = UrlPayloadProcessor.parseClassifiedPayload(p).payload;
            boolean verbatim = generated.stream().anyMatch(u -> u.contains(content));
            String mangled = content.replace("%", "%25");
            boolean mangledPresent = !content.equals(mangled)
                    && generated.stream().anyMatch(u -> u.contains(mangled));

            if (verbatim) {
                survived++;
            } else if (mangledPresent) {
                onlyMangled++;
            } else {
                vanished.add(p);
            }
        }

        System.out.println("=== UrlPayloadProcessor survival report ===");
        System.out.println("Input payloads:     " + payloads.size());
        System.out.println("Output URLs:        " + generated.size());
        System.out.println("Verbatim survivors: " + survived);
        System.out.println("Only mangled (%->%25): " + onlyMangled);
        System.out.println("Vanished entirely:  " + vanished.size());
        if (!vanished.isEmpty()) {
            int show = Math.min(vanished.size(), 40);
            for (int i = 0; i < show; i++) {
                System.out.println("  VANISHED: " + vanished.get(i));
            }
            if (vanished.size() > show) {
                System.out.println("  ... and " + (vanished.size() - show) + " more");
            }
        }

        assertTrue(survived + onlyMangled >= payloads.size() * 9 / 10,
                "less than 90% of payloads survived processor (verbatim+mangled): "
                        + (survived + onlyMangled) + "/" + payloads.size());
    }
}
