package com.bypassfuzzer.cli;

import com.bypassfuzzer.cli.run.RunControl;
import com.bypassfuzzer.core.scan.*;
import com.bypassfuzzer.core.http.*;
import com.google.gson.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import java.util.function.Predicate;
import static org.junit.jupiter.api.Assertions.*;

class RunControlTest {
    @TempDir Path temporary;
    private RunConfiguration initial(){return new RunConfiguration(Set.of(),2,2,100,Set.of("a"),List.of(new ConfiguredHeader("Authorization","secret-fixture")),Set.of(),UserAgentMode.DISABLED,0);}
    private JsonObject status(Path file,Predicate<JsonObject> accepted) throws Exception {
        Path status=file.resolveSibling(file.getFileName()+".status.json");long deadline=System.nanoTime()+5_000_000_000L;
        while(System.nanoTime()<deadline){if(Files.exists(status)){var value=JsonParser.parseString(Files.readString(status)).getAsJsonObject();if(accepted.test(value))return value;}Thread.sleep(20);}
        throw new AssertionError("Run-control status never reached the expected state");
    }
    @Test void validatesAtomicEditsAndReturnsCredentialFreeStatus() throws Exception {
        var file=temporary.resolve("control");Files.writeString(file,"pause");var live=new LiveRun(initial(),Map.of("a","A","b","B"));
        try(var control=new RunControl(file,null,null,live)) {
            status(file,j -> j.get("state").getAsString().equals("paused"));
            Files.writeString(file,"{\"action\":\"apply-resume\",\"commandId\":null,\"expectedRevision\":0,\"configuration\":{\"concurrency\":3}}");
            status(file,j -> !j.get("error").getAsString().isEmpty());assertEquals(0,live.snapshot().revision());assertEquals(LiveRun.State.PAUSED,live.snapshot().state());
            Files.writeString(file,"{\"action\":\"apply-resume\",\"expectedRevision\":0,\"configuration\":{\"playbooks\":[\"missing\"]}}");
            var rejected=status(file,j -> !j.get("error").getAsString().isEmpty());assertEquals("paused",rejected.get("state").getAsString());assertEquals(0,rejected.get("revision").getAsLong());
            Files.writeString(file,"{\"action\":\"apply-resume\",\"expectedRevision\":0,\"configuration\":{\"playbooks\":[\"b\"],\"headers\":[\"User-Agent: edited-secret-fixture\"],\"concurrency\":3,\"perHostConcurrency\":1,\"requestsPerSecond\":20,\"excludeHosts\":[\"api.test\"]}}");
            var accepted=status(file,j -> j.get("revision").getAsLong()==1 && j.get("error").getAsString().isEmpty());assertEquals("running",accepted.get("state").getAsString());
            assertTrue(live.snapshot().configuration().excludes("api.test"));assertEquals(Set.of("b"),live.snapshot().configuration().playbooks());assertFalse(accepted.toString().contains("secret-fixture"));
            Files.writeString(file,"pause");status(file,j -> j.get("state").getAsString().equals("paused"));
            Files.writeString(file,"{\"action\":\"apply-resume\",\"expectedRevision\":0,\"configuration\":{\"concurrency\":1}}");
            rejected=status(file,j -> !j.get("error").getAsString().isEmpty());assertEquals("paused",rejected.get("state").getAsString());assertEquals(1,live.snapshot().revision());
        }
    }
    @Test void invalidControlLocationFailsBeforeAWatcherCanStart() {
        var live=new LiveRun(initial(),Map.of("a","A"));
        assertThrows(IllegalArgumentException.class,() -> new RunControl(temporary.resolve("missing/control"),null,null,live));
        assertEquals(0,live.snapshot().requestsSent());
    }
    @Test void rejectsUnknownFieldsFractionsInjectionAndConflictingHeadersBeforeApply() {
        for(String json:List.of("{\"concurrency\":1.5}","{\"extra\":true}","{\"headers\":[\"X-One: okay\\r\\nX-Two: bad\"]}","{\"headers\":[\"X-Test: x\"],\"removeHeaders\":[\"X-Test\"]}"))
            assertThrows(RuntimeException.class,() -> RunControl.patch(initial(),JsonParser.parseString(json).getAsJsonObject()),json);
    }
}
