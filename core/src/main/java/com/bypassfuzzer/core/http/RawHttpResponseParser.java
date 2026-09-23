package com.bypassfuzzer.core.http;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Parses a saved raw HTTP response for offline response-guided previews. */
public final class RawHttpResponseParser {
    public HttpResponseData parse(byte[] raw) {
        if (raw == null || raw.length == 0) throw new IllegalArgumentException("Raw response is empty");
        int split = indexOf(raw, new byte[]{'\r', '\n', '\r', '\n'});
        int separator = 4;
        if (split < 0) { split = indexOf(raw, new byte[]{'\n', '\n'}); separator = 2; }
        if (split < 0) throw new IllegalArgumentException("Raw response has no header/body separator");
        String head = new String(raw, 0, split, StandardCharsets.ISO_8859_1).replace("\r\n", "\n");
        String[] lines = head.split("\n");
        String[] status = lines[0].split("\\s+", 3);
        if (status.length < 2 || !status[0].startsWith("HTTP/"))
            throw new IllegalArgumentException("Invalid response status line");
        int code;
        try { code = Integer.parseInt(status[1]); }
        catch (NumberFormatException invalid) { throw new IllegalArgumentException("Invalid response status code", invalid); }
        List<HttpHeader> headers = new ArrayList<>();
        for (int index = 1; index < lines.length; index++) {
            int colon = lines[index].indexOf(':');
            if (colon <= 0) throw new IllegalArgumentException("Invalid response header");
            headers.add(new HttpHeader(lines[index].substring(0, colon).trim(),
                lines[index].substring(colon + 1).trim()));
        }
        HttpProtocol protocol = status[0].startsWith("HTTP/2") ? HttpProtocol.HTTP_2 : HttpProtocol.HTTP_1;
        return new HttpResponseData(protocol, code, headers,
            Arrays.copyOfRange(raw, split + separator, raw.length), 0);
    }

    private int indexOf(byte[] bytes, byte[] needle) {
        outer: for (int index = 0; index <= bytes.length - needle.length; index++) {
            for (int offset = 0; offset < needle.length; offset++)
                if (bytes[index + offset] != needle[offset]) continue outer;
            return index;
        }
        return -1;
    }
}
