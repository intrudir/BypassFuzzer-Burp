package com.bypassfuzzer.core.http;

import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.io.*;
import java.util.*;

/** Run-owned storage for retained controls. Neither request credentials nor bodies enter logs. */
public final class ResponseArchive implements AutoCloseable {
    private Path directory;
    public synchronized HttpResponseData retain(HttpResponseData response) {
        if(response==null || response.bodyLength()<=16384 || response.archived())return response;
        try {
            if(directory==null) {
                directory=Files.createTempDirectory("bypassfuzzer-controls-");
                try{Files.setPosixFilePermissions(directory,PosixFilePermissions.fromString("rwx------"));}catch(UnsupportedOperationException ignored){ }
            }
            Path file=Files.createTempFile(directory,"response-",".body");
            try{Files.setPosixFilePermissions(file,PosixFilePermissions.fromString("rw-------"));}catch(UnsupportedOperationException ignored){ }
            Files.write(file,response.body());return response.backedBy(file);
        }catch(IOException error){throw new UncheckedIOException(error);}
    }
    @Override public synchronized void close() throws IOException {
        if(directory==null)return;
        try(var paths=Files.list(directory)){for(Path path:paths.toList())Files.delete(path);}
        Files.delete(directory);directory=null;
    }
}
