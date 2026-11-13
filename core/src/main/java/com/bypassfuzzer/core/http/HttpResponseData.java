package com.bypassfuzzer.core.http;

import java.util.List;
import java.nio.file.*;
import java.io.*;

/** Immutable response; retained run controls can keep large bodies in a private temporary archive. */
public final class HttpResponseData {
    private final HttpProtocol protocol;
    private final int statusCode;
    private final List<HttpHeader> headers;
    private final byte[] bytes;
    private final Path bodyFile;
    private final int bodyLength;
    private final long durationMillis;
    public HttpResponseData(HttpProtocol protocol,int statusCode,List<HttpHeader> headers,byte[] body,long durationMillis) {
        this(protocol,statusCode,headers,body==null ? new byte[0] : body.clone(),null,body==null ? 0 : body.length,durationMillis);
    }
    private HttpResponseData(HttpProtocol protocol,int statusCode,List<HttpHeader> headers,byte[] bytes,Path bodyFile,int bodyLength,long durationMillis) {
        this.protocol=protocol==null ? HttpProtocol.HTTP_1 : protocol;this.statusCode=statusCode;
        this.headers=List.copyOf(headers==null ? List.of() : headers);this.bytes=bytes;this.bodyFile=bodyFile;this.bodyLength=bodyLength;this.durationMillis=Math.max(0,durationMillis);
    }
    HttpResponseData backedBy(Path file){return new HttpResponseData(protocol,statusCode,headers,null,file,bodyLength,durationMillis);}
    boolean archived(){return bodyFile!=null;}
    public HttpProtocol protocol(){return protocol;}
    public int statusCode(){return statusCode;}
    public List<HttpHeader> headers(){return headers;}
    public long durationMillis(){return durationMillis;}
    public byte[] body(){
        if(bodyFile==null)return bytes.clone();
        try{return Files.readAllBytes(bodyFile);}catch(IOException error){throw new UncheckedIOException("Retained response body is unavailable",error);}
    }
    public int bodyLength(){return bodyLength;}
    public java.util.Optional<String> firstHeader(String name){return headers.stream().filter(h -> h.name().equalsIgnoreCase(name)).map(HttpHeader::value).findFirst();}
}
