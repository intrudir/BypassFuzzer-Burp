package com.bypassfuzzer.cli.transport;

import com.bypassfuzzer.core.http.*;
import java.time.Duration;
import java.util.List;

/** Fresh JVM so a test trust store cannot change other tests' default TLS state. */
public final class NettyTlsProbe {
    public static void main(String[] args) throws Exception {
        var origin = TargetOrigin.parse(args[0]);
        var request = new HttpRequestData(origin, "GET", "/tls-check", HttpProtocol.parse(args[1]),
            List.of(new HttpHeader("Host", origin.authority())), new byte[0]);
        try (var transport = new NettyRequestTransport(Boolean.parseBoolean(args[2]), null)) {
            System.out.println("STATUS=" + transport.send(request, Duration.ofSeconds(5)).statusCode());
        }
    }
}
