package com.bypassfuzzer.cli.run;

import com.bypassfuzzer.core.http.*;
import com.bypassfuzzer.core.throttle.GlobalTrafficGovernor;
import java.nio.file.*;
import java.util.concurrent.*;

/** CLI counterpart of Dashboard admission and pause/resume/stop, without platform-specific signals. */
public final class RunControl implements AutoCloseable {
    private record Binding(Runnable pause, Runnable resume, Runnable stop) { }
    private final java.util.List<Binding> bindings = new CopyOnWriteArrayList<>();
    private final GlobalTrafficGovernor<HttpRequestData> governor = new GlobalTrafficGovernor<>(r -> r.origin().toString());
    private final ScheduledExecutorService watcher;
    private volatile String state = "resume";

    public RunControl(Path file, Integer maxInFlight, Double maxRate) {
        if (maxInFlight != null && maxInFlight < 1 || maxRate != null && maxRate <= 0)
            throw new IllegalArgumentException("Traffic limits must be positive");
        governor.configure(maxInFlight != null || maxRate != null,
            maxInFlight == null ? 10 : maxInFlight, maxRate == null ? 10 : maxRate);
        if (file == null) watcher = null;
        else {
            watcher = Executors.newSingleThreadScheduledExecutor(r -> {
                var thread = new Thread(r, "bypassfuzzer-run-control"); thread.setDaemon(true); return thread;
            });
            poll(file);
            watcher.scheduleWithFixedDelay(() -> poll(file), 100, 100, TimeUnit.MILLISECONDS);
        }
    }

    public AutoCloseable bind(Runnable pause, Runnable resume, Runnable stop) {
        var binding = new Binding(pause, resume, stop);
        bindings.add(binding);
        apply(binding, state);
        return () -> bindings.remove(binding);
    }

    public boolean continuing() { return !state.equals("stop") && !Thread.currentThread().isInterrupted(); }
    public boolean stopped() { return state.equals("stop"); }

    public RequestTransport transport(RequestTransport network) {
        return (request, timeout) -> {
            try {
                return governor.execute(request, () -> {
                    try { return network.send(request, timeout); }
                    catch (Exception error) { throw new CompletionException(error); }
                }, this::continuing);
            } catch (CompletionException error) {
                if (error.getCause() instanceof Exception cause) throw cause;
                throw error;
            }
        };
    }

    private void poll(Path file) {
        if (stopped() || !Files.isRegularFile(file)) return;
        try {
            String command = Files.readString(file).trim().toLowerCase(java.util.Locale.ROOT);
            if (!java.util.Set.of("pause", "resume", "stop").contains(command) || command.equals(state)) return;
            state = command;
            if (command.equals("pause")) governor.pause(); else governor.resume();
            for (var binding : bindings) apply(binding, command);
        } catch (java.io.IOException error) { System.err.println("Unable to read run control: " + error.getMessage()); }
    }
    private void apply(Binding binding, String command) {
        switch (command) {
            case "pause" -> binding.pause().run();
            case "resume" -> binding.resume().run();
            case "stop" -> binding.stop().run();
        }
    }
    @Override public void close() { if (watcher != null) watcher.shutdownNow(); }
}
