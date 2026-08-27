package com.bypassfuzzer.core.http;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class RawHttpRequestParser {
    public HttpRequestData parse(byte[] raw, TargetOrigin origin) {
        if (raw == null || raw.length == 0) throw new IllegalArgumentException("Raw request is empty");
        int split = indexOf(raw, new byte[]{'\r', '\n', '\r', '\n'});
        int delimiter = 4;
        if (split < 0) {
            split = indexOf(raw, new byte[]{'\n', '\n'});
            delimiter = 2;
        }
        int headEnd = split >= 0 ? split : raw.length;
        byte[] headBytes = Arrays.copyOfRange(raw, 0, headEnd);
        byte[] body = split >= 0 ? Arrays.copyOfRange(raw, split + delimiter, raw.length) : new byte[0];
        String head = new String(headBytes, StandardCharsets.ISO_8859_1).replace("\r\n", "\n");
        String[] lines = head.split("\n", -1);
        if (lines.length == 0) throw new IllegalArgumentException("Raw request has no request line");
        String[] requestLine = lines[0].trim().split("[ \\t]+", 3);
        if (requestLine.length < 2) throw new IllegalArgumentException("Invalid HTTP request line: " + lines[0]);
        HttpProtocol protocol = requestLine.length < 3 ? HttpProtocol.HTTP_0_9
            : requestLine[2].equalsIgnoreCase("HTTP/1.0") ? HttpProtocol.HTTP_1_0
            : requestLine[2].startsWith("HTTP/2") ? HttpProtocol.HTTP_2 : HttpProtocol.HTTP_1;
        List<HttpHeader> headers = new ArrayList<>();
        for (int index = 1; index < lines.length; index++) {
            String line = lines[index];
            if (line.isEmpty()) continue;
            if (line.startsWith(" ") || line.startsWith("\t")) {
                throw new IllegalArgumentException("Obsolete folded headers are not supported");
            }
            int colon = line.indexOf(':');
            if (colon <= 0) throw new IllegalArgumentException("Invalid HTTP header: " + line);
            headers.add(new HttpHeader(line.substring(0, colon).trim(), line.substring(colon + 1).trim()));
        }
        return new HttpRequestData(origin, requestLine[0], requestLine[1], protocol, headers, body);
    }

    private int indexOf(byte[] input, byte[] needle) {
        outer: for (int index = 0; index <= input.length - needle.length; index++) {
            for (int offset = 0; offset < needle.length; offset++) {
                if (input[index + offset] != needle[offset]) continue outer;
            }
            return index;
        }
        return -1;
    }
}
