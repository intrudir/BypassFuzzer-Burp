package com.bypassfuzzer.core.http;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

class RequestPathUtilsTest {
    @Test
    void rawQueryMarkersDoNotHideTheRequestPath() {
        assertEquals("/redirect/next", RequestPathUtils.extractPath(
            "https://example.test/redirect/next?next={INJECT}"));
        assertEquals("/objects/100", RequestPathUtils.extractPath(
            "http://127.0.0.1:8080/objects/100?filter=raw value"));
        assertEquals("/encoded%2Fpath", RequestPathUtils.extractPath(
            "https://example.test/encoded%2Fpath?next={INJECT}"));
    }
}
