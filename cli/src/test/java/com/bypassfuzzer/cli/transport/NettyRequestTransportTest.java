package com.bypassfuzzer.cli.transport;

import com.bypassfuzzer.core.http.HttpHeader;
import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.http.TargetOrigin;
import com.sun.net.httpserver.HttpServer;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http2.DefaultHttp2DataFrame;
import io.netty.handler.codec.http2.DefaultHttp2Headers;
import io.netty.handler.codec.http2.DefaultHttp2HeadersFrame;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;
import io.netty.handler.codec.http2.Http2HeadersFrame;
import io.netty.handler.codec.http2.Http2MultiplexHandler;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;

class NettyRequestTransportTest {
    @Test
    void sendsRawHttp1TargetAndReceivesResponse() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicReference<String> target = new AtomicReference<>();
        server.createContext("/", exchange -> {
            target.set(exchange.getRequestURI().toASCIIString());
            byte[] body = "http1-ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try (NettyRequestTransport transport = new NettyRequestTransport(false, null)) {
            TargetOrigin origin = new TargetOrigin("http", "127.0.0.1", server.getAddress().getPort());
            HttpRequestData request = new HttpRequestData(origin, "GET", "/a/%2e/b?x=1", HttpProtocol.HTTP_1,
                List.of(new HttpHeader("Host", origin.authority()), new HttpHeader("X-Duplicate", "one"),
                    new HttpHeader("X-Duplicate", "two")), new byte[0]);
            var response = transport.send(request, Duration.ofSeconds(5));

            assertEquals(200, response.statusCode());
            assertEquals("/a/%2e/b?x=1", target.get());
            assertEquals("http1-ok", new String(response.body(), StandardCharsets.UTF_8));
        } finally { server.stop(0); }
    }

    @Test
    void sendsNativeCleartextHttp2WithAuthorityAndRawPath() throws Exception {
        EventLoopGroup boss = new NioEventLoopGroup(1);
        EventLoopGroup workers = new NioEventLoopGroup(1);
        AtomicReference<String> authority = new AtomicReference<>();
        AtomicReference<String> path = new AtomicReference<>();
        Channel server = new ServerBootstrap().group(boss, workers).channel(NioServerSocketChannel.class)
            .childHandler(new ChannelInitializer<SocketChannel>() {
                @Override protected void initChannel(SocketChannel channel) {
                    channel.pipeline().addLast(Http2FrameCodecBuilder.forServer().build());
                    channel.pipeline().addLast(new Http2MultiplexHandler(new ChannelInitializer<Channel>() {
                        @Override protected void initChannel(Channel stream) {
                            stream.pipeline().addLast(new SimpleChannelInboundHandler<Object>() {
                                @Override protected void channelRead0(ChannelHandlerContext context, Object message) {
                                    if (message instanceof Http2HeadersFrame frame) {
                                        authority.set(frame.headers().authority().toString());
                                        path.set(frame.headers().path().toString());
                                        DefaultHttp2Headers headers = new DefaultHttp2Headers();
                                        headers.status("200").add("content-type", "text/plain");
                                        context.write(new DefaultHttp2HeadersFrame(headers, false));
                                        context.writeAndFlush(new DefaultHttp2DataFrame(
                                            Unpooled.copiedBuffer("h2-ok", StandardCharsets.UTF_8), true));
                                    }
                                }
                            });
                        }
                    }));
                }
            }).bind("127.0.0.1", 0).sync().channel();
        try (NettyRequestTransport transport = new NettyRequestTransport(false, null)) {
            int port = ((InetSocketAddress) server.localAddress()).getPort();
            TargetOrigin origin = new TargetOrigin("http", "127.0.0.1", port);
            HttpRequestData request = new HttpRequestData(origin, "GET", "/h2/%2e/test", HttpProtocol.HTTP_2,
                List.of(new HttpHeader("Host", "fuzzed-authority.example")), new byte[0]);
            var response = transport.send(request, Duration.ofSeconds(5));

            assertEquals(HttpProtocol.HTTP_2, response.protocol());
            assertEquals(200, response.statusCode());
            assertEquals("fuzzed-authority.example", authority.get());
            assertEquals("/h2/%2e/test", path.get());
        } finally {
            server.close().syncUninterruptibly();
            boss.shutdownGracefully().syncUninterruptibly();
            workers.shutdownGracefully().syncUninterruptibly();
        }
    }
}
