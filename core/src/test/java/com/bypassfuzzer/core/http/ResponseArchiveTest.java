package com.bypassfuzzer.core.http;

import org.junit.jupiter.api.Test;
import java.util.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import static org.junit.jupiter.api.Assertions.*;

class ResponseArchiveTest {
    @Test void retainsLargeControlsPrivatelyAndCleansOnlyItsOwnFiles() throws Exception {
        byte[] bytes=new byte[32768];Arrays.fill(bytes,(byte)7);
        var response=new HttpResponseData(HttpProtocol.HTTP_1,404,List.of(new HttpHeader("Content-Type","text/plain")),bytes,3);
        var archive=new ResponseArchive();var retained=archive.retain(response);
        assertEquals(32768,retained.bodyLength());assertArrayEquals(bytes,retained.body());
        var field=ResponseArchive.class.getDeclaredField("directory");field.setAccessible(true);Path directory=(Path)field.get(archive);
        assertEquals("rwx------",PosixFilePermissions.toString(Files.getPosixFilePermissions(directory)));
        try(var files=Files.list(directory)){for(Path file:files.toList())assertEquals("rw-------",PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));}
        archive.close();assertFalse(Files.exists(directory));assertArrayEquals(bytes,response.body());archive.close();
    }
}
