package com.bypassfuzzer.core.http;




import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/** Builds stable-per-run User-Agent variants without shared mutable random state. */
public final class UserAgentVariants {

    private static final String[] CHROME_PLATFORMS = {
        "Windows NT 10.0; Win64; x64",
        "X11; Linux x86_64",
        "Macintosh; Intel Mac OS X 10_15_7"
    };

    private UserAgentVariants() {
    }

    public static String valueFor(UserAgentMode mode, long seed, String method, String url,
                                  List<HttpHeader> headers, String body) {
        byte[] digest = digest(seed, method, url, headers, body);
        return mode == UserAgentMode.BROWSER_LIKE ? browserLike(digest) : synthetic(digest);
    }

    private static String synthetic(byte[] digest) {
        String firstToken = "vexa-" + hex(digest, 0, 5);
        String secondToken = "orbit-" + hex(digest, 5, 4);
        int firstMajor = 1 + unsigned(digest[9]) % 97;
        int firstMinor = unsigned(digest[10]) % 100;
        int secondMajor = 1 + unsigned(digest[11]) % 31;
        int secondMinor = unsigned(digest[12]) % 100;
        return firstToken + "/" + firstMajor + "." + firstMinor
            + " " + secondToken + "/" + secondMajor + "." + secondMinor;
    }

    private static String browserLike(byte[] digest) {
        int family = unsigned(digest[0]) % 3;
        String platform = CHROME_PLATFORMS[unsigned(digest[1]) % CHROME_PLATFORMS.length];
        if (family == 1) {
            int version = 105 + unsigned(digest[2]) % 46;
            return "Mozilla/5.0 (" + platform + "; rv:" + version + ".0) "
                + "Gecko/20100101 Firefox/" + version + ".0";
        }
        if (family == 2) {
            int major = 14 + unsigned(digest[2]) % 6;
            int minor = unsigned(digest[3]) % 7;
            return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                + "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" + major + "." + minor
                + " Safari/605.1.15";
        }
        int major = 105 + unsigned(digest[2]) % 46;
        int build = 1000 + ((unsigned(digest[3]) << 8 | unsigned(digest[4])) % 8000);
        int patch = unsigned(digest[5]) % 200;
        return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) "
            + "Chrome/" + major + ".0." + build + "." + patch + " Safari/537.36";
    }

    private static byte[] digest(long seed, String method, String url, List<HttpHeader> headers, String body) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(Long.toUnsignedString(seed).getBytes(StandardCharsets.UTF_8));
            digest.update((byte) '\n');
            {
                update(digest, method);
                update(digest, url);
                try {
                    for (HttpHeader header : headers) {
                        if (!header.name().equalsIgnoreCase("User-Agent")) {
                            update(digest, header.name());
                            update(digest, header.value());
                        }
                    }
                } catch (Exception ignored) {
                    // Method, URL, and body still produce a stable request fingerprint.
                }
                update(digest, body);
            }
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private static void update(MessageDigest digest, String value) {
        digest.update(safe(value).getBytes(StandardCharsets.UTF_8));
        digest.update((byte) '\n');
    }

    private static int unsigned(byte value) {
        return Byte.toUnsignedInt(value);
    }

    private static String hex(byte[] bytes, int offset, int length) {
        StringBuilder result = new StringBuilder(length * 2);
        for (int index = offset; index < offset + length; index++) {
            result.append(Character.forDigit((bytes[index] >>> 4) & 0xf, 16));
            result.append(Character.forDigit(bytes[index] & 0xf, 16));
        }
        return result.toString();
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
