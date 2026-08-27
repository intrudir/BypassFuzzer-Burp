package com.bypassfuzzer.cli.transport;

import com.bypassfuzzer.core.http.HttpHeader;
import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.http.HttpResponseData;
import com.bypassfuzzer.core.http.RequestTransport;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http2.DefaultHttp2DataFrame;
import io.netty.handler.codec.http2.DefaultHttp2Headers;
import io.netty.handler.codec.http2.DefaultHttp2HeadersFrame;
import io.netty.handler.codec.http2.Http2DataFrame;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;
import io.netty.handler.codec.http2.Http2HeadersFrame;
import io.netty.handler.codec.http2.Http2MultiplexHandler;
import io.netty.handler.codec.http2.Http2StreamChannelBootstrap;
import io.netty.handler.proxy.HttpProxyHandler;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.ApplicationProtocolNegotiationHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.util.ReferenceCountUtil;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/** One-request-per-connection transport that preserves raw HTTP/1 targets and supports native HTTP/2. */
public final class NettyRequestTransport implements RequestTransport {
    private static final int MAX_RESPONSE_BYTES = 64 * 1024 * 1024;
    private static final Set<String> H2_FORBIDDEN = Set.of("connection", "keep-alive", "proxy-connection",
        "transfer-encoding", "upgrade", "http2-settings");
    private final EventLoopGroup group;
    private final boolean insecure;
    private final URI proxy;
    private final int connectTimeoutMillis;

    public NettyRequestTransport(boolean insecure, String proxy) {
        this(insecure, proxy, Duration.ofSeconds(10));
    }

    public NettyRequestTransport(boolean insecure, String proxy, Duration connectTimeout) {
        this.group = new NioEventLoopGroup(Math.max(1, Math.min(8, Runtime.getRuntime().availableProcessors())));
        this.insecure = insecure;
        this.proxy = proxy == null || proxy.isBlank() ? null : validateProxy(proxy);
        this.connectTimeoutMillis = Math.toIntExact(Math.max(1L, connectTimeout.toMillis()));
    }

    @Override
    public HttpResponseData send(HttpRequestData request, Duration timeout) throws Exception {
        request = request.withSyncedContentLength();
        HttpProtocol requested = request.protocol();
        if (requested == HttpProtocol.BOTH) throw new IllegalArgumentException("BOTH must be expanded before transport");
        if (requested == HttpProtocol.HTTP_0_9) return sendHttp09(request, timeout);
        boolean wantH2 = requested == HttpProtocol.HTTP_2;
        boolean auto = requested == HttpProtocol.AUTO;
        if (!request.origin().secure() && auto) return sendHttp1(request.withProtocol(HttpProtocol.HTTP_1), timeout);
        return sendNegotiated(request, timeout, wantH2, auto);
    }

    private HttpResponseData sendHttp1(HttpRequestData request, Duration timeout) throws Exception {
        return sendNegotiated(request, timeout, false, false);
    }

    private HttpResponseData sendNegotiated(HttpRequestData request, Duration timeout, boolean wantH2, boolean auto) throws Exception {
        long started = System.nanoTime();
        CompletableFuture<HttpResponseData> response = new CompletableFuture<>();
        CompletableFuture<HttpProtocol> ready = new CompletableFuture<>();
        SslContext ssl = request.origin().secure() ? sslContext(wantH2 || auto, auto) : null;
        Bootstrap bootstrap = bootstrap(new ChannelInitializer<SocketChannel>() {
            @Override
            protected void initChannel(SocketChannel channel) throws Exception {
                addProxy(channel.pipeline());
                if (ssl != null) {
                    channel.pipeline().addLast(ssl.newHandler(channel.alloc(), request.origin().host(), request.origin().port()));
                    channel.pipeline().addLast(new ApplicationProtocolNegotiationHandler("") {
                        @Override
                        protected void configurePipeline(ChannelHandlerContext context, String protocol) {
                            if (ApplicationProtocolNames.HTTP_2.equals(protocol)) {
                                configureH2(context.pipeline());
                                ready.complete(HttpProtocol.HTTP_2);
                            } else if (ApplicationProtocolNames.HTTP_1_1.equals(protocol) || (protocol.isEmpty() && !wantH2)) {
                                configureH1(context.pipeline(), response, started);
                                ready.complete(HttpProtocol.HTTP_1);
                            } else {
                                ready.completeExceptionally(new IllegalStateException("Server did not negotiate requested HTTP protocol"));
                            }
                        }

                        @Override
                        public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
                            ready.completeExceptionally(cause);
                            response.completeExceptionally(cause);
                            context.close();
                        }
                    });
                } else if (wantH2) {
                    configureH2(channel.pipeline());
                    ready.complete(HttpProtocol.HTTP_2);
                } else {
                    configureH1(channel.pipeline(), response, started);
                    ready.complete(HttpProtocol.HTTP_1);
                }
            }
        });
        Channel channel = bootstrap.connect(request.origin().host(), request.origin().port()).sync().channel();
        try {
            HttpProtocol actual = ready.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (wantH2 && actual != HttpProtocol.HTTP_2) throw new IllegalStateException("HTTP/2 was requested but not negotiated");
            if (actual == HttpProtocol.HTTP_2) writeH2(channel, request, response, started);
            else writeH1(channel, request);
            return response.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } finally {
            channel.close().syncUninterruptibly();
        }
    }

    private void configureH1(ChannelPipeline pipeline, CompletableFuture<HttpResponseData> response, long started) {
        pipeline.addLast(new HttpClientCodec());
        pipeline.addLast(new HttpObjectAggregator(MAX_RESPONSE_BYTES));
        pipeline.addLast(new SimpleChannelInboundHandler<FullHttpResponse>() {
            @Override
            protected void channelRead0(ChannelHandlerContext context, FullHttpResponse message) {
                List<HttpHeader> headers = new ArrayList<>();
                message.headers().forEach(entry -> headers.add(new HttpHeader(entry.getKey(), entry.getValue())));
                byte[] body = new byte[message.content().readableBytes()];
                message.content().getBytes(message.content().readerIndex(), body);
                HttpProtocol protocol = message.protocolVersion().equals(HttpVersion.HTTP_1_0) ? HttpProtocol.HTTP_1_0 : HttpProtocol.HTTP_1;
                response.complete(new HttpResponseData(protocol, message.status().code(), headers, body, elapsed(started)));
            }

            @Override
            public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
                response.completeExceptionally(cause);
                context.close();
            }
        });
    }

    private void writeH1(Channel channel, HttpRequestData request) {
        HttpVersion version = request.protocol() == HttpProtocol.HTTP_1_0 ? HttpVersion.HTTP_1_0 : HttpVersion.HTTP_1_1;
        ByteBuf body = Unpooled.wrappedBuffer(request.body());
        FullHttpRequest message = new DefaultFullHttpRequest(version, HttpMethod.valueOf(request.method()), request.rawTarget(), body, false);
        for (HttpHeader header : request.headers()) message.headers().add(header.name(), header.value());
        if (!message.headers().contains(HttpHeaderNames.HOST)) message.headers().add(HttpHeaderNames.HOST, request.origin().authority());
        if (body.isReadable() && !message.headers().contains(HttpHeaderNames.CONTENT_LENGTH)) {
            message.headers().add(HttpHeaderNames.CONTENT_LENGTH, body.readableBytes());
        }
        channel.writeAndFlush(message);
    }

    private void configureH2(ChannelPipeline pipeline) {
        pipeline.addLast(Http2FrameCodecBuilder.forClient().build());
        pipeline.addLast(new Http2MultiplexHandler(new ChannelInitializer<Channel>() {
            @Override protected void initChannel(Channel channel) { channel.pipeline().addLast(new SimpleChannelInboundHandler<Object>() {
                @Override protected void channelRead0(ChannelHandlerContext context, Object message) { }
            }); }
        }));
    }

    private void writeH2(Channel parent, HttpRequestData request, CompletableFuture<HttpResponseData> response, long started) throws Exception {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        List<HttpHeader> responseHeaders = new ArrayList<>();
        int[] status = {0};
        Http2StreamChannelBootstrap streamBootstrap = new Http2StreamChannelBootstrap(parent);
        streamBootstrap.handler(new ChannelInitializer<Channel>() {
            @Override
            protected void initChannel(Channel channel) {
                channel.pipeline().addLast(new SimpleChannelInboundHandler<Object>() {
                    @Override
                    protected void channelRead0(ChannelHandlerContext context, Object message) {
                        if (message instanceof Http2HeadersFrame frame) {
                            frame.headers().forEach(entry -> {
                                if (entry.getKey().toString().equals(":status")) status[0] = Integer.parseInt(entry.getValue().toString());
                                else responseHeaders.add(new HttpHeader(entry.getKey().toString(), entry.getValue().toString()));
                            });
                            if (frame.isEndStream()) complete();
                        } else if (message instanceof Http2DataFrame frame) {
                            byte[] bytes = new byte[frame.content().readableBytes()];
                            frame.content().getBytes(frame.content().readerIndex(), bytes);
                            body.writeBytes(bytes);
                            if (body.size() > MAX_RESPONSE_BYTES) throw new IllegalStateException("Response exceeded " + MAX_RESPONSE_BYTES + " bytes");
                            if (frame.isEndStream()) complete();
                        }
                    }

                    private void complete() {
                        response.complete(new HttpResponseData(HttpProtocol.HTTP_2, status[0], responseHeaders,
                            body.toByteArray(), elapsed(started)));
                    }

                    @Override
                    public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
                        response.completeExceptionally(cause);
                        context.close();
                    }
                });
            }
        });
        Channel stream = streamBootstrap.open().sync().getNow();
        DefaultHttp2Headers headers = new DefaultHttp2Headers();
        headers.method(request.method()).path(request.rawTarget()).scheme(request.origin().scheme())
            .authority(request.firstHeader("Host").orElse(request.origin().authority()));
        for (HttpHeader header : request.headers()) {
            String name = header.name().toLowerCase(Locale.ROOT);
            if (name.equals("host") || name.startsWith(":") || H2_FORBIDDEN.contains(name)) continue;
            if (name.equals("te") && !header.value().equalsIgnoreCase("trailers")) continue;
            headers.add(name, header.value());
        }
        byte[] requestBody = request.body();
        stream.write(new DefaultHttp2HeadersFrame(headers, requestBody.length == 0));
        if (requestBody.length > 0) stream.write(new DefaultHttp2DataFrame(Unpooled.wrappedBuffer(requestBody), true));
        stream.flush();
    }

    private HttpResponseData sendHttp09(HttpRequestData request, Duration timeout) throws Exception {
        long started = System.nanoTime();
        CompletableFuture<HttpResponseData> response = new CompletableFuture<>();
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        SslContext ssl = request.origin().secure() ? sslContext(false, false) : null;
        Bootstrap bootstrap = bootstrap(new ChannelInitializer<SocketChannel>() {
            @Override protected void initChannel(SocketChannel channel) throws Exception {
                addProxy(channel.pipeline());
                if (ssl != null) channel.pipeline().addLast(ssl.newHandler(channel.alloc(), request.origin().host(), request.origin().port()));
                channel.pipeline().addLast(new io.netty.channel.ChannelInboundHandlerAdapter() {
                    @Override public void channelRead(ChannelHandlerContext context, Object message) {
                        ByteBuf bytes = (ByteBuf) message;
                        byte[] chunk = new byte[bytes.readableBytes()];
                        bytes.readBytes(chunk);
                        body.writeBytes(chunk);
                        ReferenceCountUtil.release(message);
                    }
                    @Override public void channelInactive(ChannelHandlerContext context) { response.complete(new HttpResponseData(HttpProtocol.HTTP_0_9, 200, List.of(), body.toByteArray(), elapsed(started))); }
                    @Override public void exceptionCaught(ChannelHandlerContext context, Throwable cause) { response.completeExceptionally(cause); context.close(); }
                });
            }
        });
        Channel channel = bootstrap.connect(request.origin().host(), request.origin().port()).sync().channel();
        try {
            channel.writeAndFlush(Unpooled.copiedBuffer(request.method() + " " + request.rawTarget() + "\r\n", java.nio.charset.StandardCharsets.ISO_8859_1)).sync();
            return response.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } finally { channel.close().syncUninterruptibly(); }
    }

    private Bootstrap bootstrap(ChannelInitializer<SocketChannel> initializer) {
        return new Bootstrap().group(group).channel(NioSocketChannel.class)
            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectTimeoutMillis).handler(initializer);
    }

    private SslContext sslContext(boolean h2, boolean allowHttp1) throws Exception {
        SslContextBuilder builder = SslContextBuilder.forClient();
        if (insecure) builder.trustManager(InsecureTrustManagerFactory.INSTANCE);
        if (h2) builder.applicationProtocolConfig(new ApplicationProtocolConfig(
            ApplicationProtocolConfig.Protocol.ALPN, ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
            ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
            allowHttp1 ? List.of(ApplicationProtocolNames.HTTP_2, ApplicationProtocolNames.HTTP_1_1)
                : List.of(ApplicationProtocolNames.HTTP_2)));
        return builder.build();
    }

    private void addProxy(ChannelPipeline pipeline) {
        if (proxy == null) return;
        int port = proxy.getPort() > 0 ? proxy.getPort() : 8080;
        InetSocketAddress address = new InetSocketAddress(proxy.getHost(), port);
        if (proxy.getUserInfo() == null) pipeline.addLast(new HttpProxyHandler(address));
        else {
            String[] credentials = proxy.getUserInfo().split(":", 2);
            pipeline.addLast(new HttpProxyHandler(address, credentials[0], credentials.length > 1 ? credentials[1] : ""));
        }
    }

    private URI validateProxy(String value) {
        URI uri = URI.create(value);
        if (!"http".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) {
            throw new IllegalArgumentException("Proxy must be an http:// URL");
        }
        return uri;
    }

    private static long elapsed(long started) { return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started); }

    @Override
    public void close() {
        group.shutdownGracefully(0, 5, TimeUnit.SECONDS).syncUninterruptibly();
    }
}
