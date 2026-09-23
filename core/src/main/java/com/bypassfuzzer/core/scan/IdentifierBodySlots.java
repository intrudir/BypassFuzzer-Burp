package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpRequestData;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Exact body-value spans for formats outside JSON and URL-encoded forms. */
final class IdentifierBodySlots {
    private static final Pattern CHARSET = Pattern.compile("(?i)charset\\s*=\\s*['\"]?([^;'\"\\s]+)");
    private static final Pattern XML_ENCODING = Pattern.compile("(?i)<\\?xml[^?]*encoding\\s*=\\s*['\"]([^'\"]+)['\"]");
    private static final Pattern ATTRIBUTE = Pattern.compile("([\\w:.-]+)\\s*=\\s*(['\"])(.*?)\\2", Pattern.DOTALL);
    private static final Pattern PART_NAME = Pattern.compile("(?i)\\bname\\s*=\\s*\"([^\"]+)\"");

    private IdentifierBodySlots() { }

    static List<IdentifierLocation> text(HttpRequestData request, String value) {
        String charsetName = charset(request.firstHeader("Content-Type").orElse(""));
        Charset charset = supported(charsetName);
        if (charset == null) return List.of();
        String body = new String(request.body(), charset);
        List<IdentifierLocation> found = new ArrayList<>();
        int ordinal = 0;
        for (int start = body.indexOf(value); start >= 0; start = body.indexOf(value, start + value.length())) {
            int end = start + value.length();
            if ((start > 0 && identifierChar(body.charAt(start - 1)))
                || (end < body.length() && identifierChar(body.charAt(end)))) continue;
            found.add(new IdentifierLocation(IdentifierLocation.Kind.TEXT, ordinal++, "",
                byteOffset(body, start, charset), value.getBytes(charset).length, charsetName));
        }
        return found;
    }

    static List<IdentifierLocation> xml(HttpRequestData request, String value) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            var builder = factory.newDocumentBuilder();
            builder.setErrorHandler(new DefaultHandler() {
                @Override public void error(SAXParseException error) throws SAXException { throw error; }
                @Override public void fatalError(SAXParseException error) throws SAXException { throw error; }
            });
            builder.parse(new ByteArrayInputStream(request.body()));
        } catch (Exception invalidXml) { return List.of(); }
        String head = new String(request.body(), 0, Math.min(request.body().length, 256), StandardCharsets.ISO_8859_1);
        Matcher declared = XML_ENCODING.matcher(head);
        String charsetName = declared.find() ? declared.group(1)
            : charset(request.firstHeader("Content-Type").orElse(""));
        Charset charset = supported(charsetName);
        if (charset == null) return List.of();
        String body = new String(request.body(), charset);
        List<IdentifierLocation> found = new ArrayList<>();
        Map<String, Integer> attributeCounts = new HashMap<>();
        int textCount = 0;
        int cursor = 0;
        while (cursor < body.length()) {
            int tag = body.indexOf('<', cursor);
            if (tag < 0) break;
            if (tag > cursor && body.substring(cursor, tag).equals(value))
                found.add(new IdentifierLocation(IdentifierLocation.Kind.XML_TEXT, textCount++, "",
                    byteOffset(body, cursor, charset), value.getBytes(charset).length, charsetName));
            if (body.startsWith("<!--", tag)) { cursor = skip(body, "-->", tag + 4); continue; }
            if (body.startsWith("<![CDATA[", tag)) { cursor = skip(body, "]]>", tag + 9); continue; }
            if (body.startsWith("<?", tag)) { cursor = skip(body, "?>", tag + 2); continue; }
            int end = tagEnd(body, tag + 1);
            if (end < 0) break;
            if (!body.startsWith("</", tag) && !body.startsWith("<!", tag)) {
                Matcher attribute = ATTRIBUTE.matcher(body.substring(tag + 1, end));
                while (attribute.find()) {
                    if (!attribute.group(3).equals(value)) continue;
                    String name = attribute.group(1);
                    int ordinal = attributeCounts.merge(name, 1, Integer::sum) - 1;
                    int start = tag + 1 + attribute.start(3);
                    found.add(new IdentifierLocation(IdentifierLocation.Kind.XML_ATTRIBUTE,
                        ordinal, name, byteOffset(body, start, charset),
                        value.getBytes(charset).length, charsetName));
                }
            }
            cursor = end + 1;
        }
        return found;
    }

    static List<IdentifierLocation> multipart(HttpRequestData request, String value) {
        String contentType = request.firstHeader("Content-Type").orElse("");
        Matcher match = Pattern.compile("(?i)\\bboundary\\s*=\\s*\"?([^;\"\\s]+)").matcher(contentType);
        if (!match.find()) return List.of();
        String marker = "--" + match.group(1);
        String raw = new String(request.body(), StandardCharsets.ISO_8859_1);
        if (!raw.startsWith(marker)) return List.of();
        List<IdentifierLocation> found = new ArrayList<>();
        Map<String, Integer> counts = new HashMap<>();
        int cursor = 0;
        while (cursor < raw.length() && raw.startsWith(marker, cursor)) {
            cursor += marker.length();
            if (raw.startsWith("--", cursor)) break;
            if (!raw.startsWith("\r\n", cursor)) break;
            int headersEnd = raw.indexOf("\r\n\r\n", cursor + 2);
            if (headersEnd < 0) break;
            String headers = raw.substring(cursor + 2, headersEnd);
            int bodyStart = headersEnd + 4;
            int next = raw.indexOf("\r\n" + marker, bodyStart);
            if (next < 0) break;
            Matcher nameMatch = PART_NAME.matcher(headers);
            boolean file = Pattern.compile("(?i)\\bfilename\\s*=").matcher(headers).find();
            if (nameMatch.find() && !file) {
                String name = nameMatch.group(1);
                String charsetName = charset(headers);
                Charset charset = supported(charsetName);
                if (charset != null) {
                    byte[] partBytes = java.util.Arrays.copyOfRange(request.body(), bodyStart, next);
                    if (new String(partBytes, charset).equals(value)) {
                        int ordinal = counts.merge(name, 1, Integer::sum) - 1;
                        found.add(new IdentifierLocation(IdentifierLocation.Kind.MULTIPART, ordinal,
                            name, bodyStart, partBytes.length, charsetName));
                    }
                }
            }
            cursor = next + 2;
        }
        return found;
    }

    private static int tagEnd(String body, int start) {
        char quote = 0;
        for (int i = start; i < body.length(); i++) {
            char ch = body.charAt(i);
            if (quote != 0) { if (ch == quote) quote = 0; }
            else if (ch == '\'' || ch == '"') quote = ch;
            else if (ch == '>') return i;
        }
        return -1;
    }

    private static int skip(String body, String marker, int start) {
        int found = body.indexOf(marker, start);
        return found < 0 ? body.length() : found + marker.length();
    }

    private static boolean identifierChar(char value) {
        return Character.isLetterOrDigit(value) || value == '_' || value == '-';
    }

    private static int byteOffset(String text, int index, Charset charset) {
        return text.substring(0, index).getBytes(charset).length;
    }

    private static String charset(String value) {
        Matcher match = CHARSET.matcher(value);
        return match.find() ? match.group(1) : "UTF-8";
    }

    private static Charset supported(String value) {
        try { return Charset.forName(value); }
        catch (RuntimeException unsupported) { return null; }
    }
}
