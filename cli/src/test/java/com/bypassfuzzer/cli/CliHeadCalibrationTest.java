package com.bypassfuzzer.cli;

import com.sun.net.httpserver.HttpServer;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;
import java.net.InetSocketAddress;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;

class CliHeadCalibrationTest {
    @TempDir Path directory;
    @Test void absentWireContentLengthStaysUnavailableAfterAggregation() throws Exception {
        var server=new java.net.ServerSocket(0,16,java.net.InetAddress.getLoopbackAddress());
        var worker=new Thread(() -> {
            while(!server.isClosed()) try(var socket=server.accept()) {
                var reader=new java.io.BufferedReader(new java.io.InputStreamReader(socket.getInputStream(),java.nio.charset.StandardCharsets.ISO_8859_1));
                String line=reader.readLine(); boolean original=line.contains(" /api/v1/admin ");
                while(!(line=reader.readLine()).isEmpty()) { }
                socket.getOutputStream().write(("HTTP/1.1 "+(original?"403 Denied":"200 OK")+"\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n").getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
            } catch(java.io.IOException error) { if(!server.isClosed()) throw new RuntimeException(error); }
        },"owned-head-fixture");worker.setDaemon(true);worker.start();
        try {
            var request=directory.resolve("head.raw"); Files.writeString(request,"HEAD /api/v1/admin HTTP/1.1\r\nHost: owned.test\r\n\r\n");
            var output=directory.resolve("evidence");
            int code=new CommandLine(new BypassFuzzerCli()).execute("bypass","--request",request.toString(),"--target-origin","http://127.0.0.1:"+server.getLocalPort(),
                "--playbooks","bypass.path.api_prefix","--protocol","http1","--retry-attempts","0","--output",output.toString());
            assertEquals(0,code);
            var rows=Files.readAllLines(output.resolve("results.jsonl")).stream().map(line->JsonParser.parseString(line).getAsJsonObject()).toList();
            assertEquals(7,rows.size());
            for(var row:rows) if(!row.get("baseline").getAsBoolean()) {
                assertEquals("UNAVAILABLE",row.getAsJsonObject("calibration").get("assessment").getAsString());
                assertEquals("LIKELY_BYPASS",row.get("signal").getAsString());
            }
        } finally { server.close(); worker.join(1000); }
    }
    @Test void invalidPrefixUsesPreflightExitCodeBeforeInputOrTraffic() {
        assertEquals(2,new CommandLine(new BypassFuzzerCli()).execute("bypass","--api-prefix","//invalid"));
        assertEquals(2,new CommandLine(new BypassFuzzerCli()).execute("sweep","--api-prefix","//invalid"));
    }

}
