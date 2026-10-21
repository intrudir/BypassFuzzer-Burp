package com.bypassfuzzer.core.scan;

import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;

/** Burp's deferred retries: control canaries, sampled mutation quarantine and retained work. */
public final class DeferredRetryRunner<T> {
    private record Group(String authority, String family) { }

    public void run(Queue<T> queue, int attempts, int concurrency, BooleanSupplier continuing,
        Function<T, String> authority, Function<T, String> family, Predicate<T> healthyControl,
        BiPredicate<T, Integer> retry, IntConsumer quarantined, Consumer<String> log) {
        Set<Group> quarantine = new HashSet<>();
        Set<String> throttledHosts = new HashSet<>();
        for (int attempt = 1; attempt <= attempts && continuing.getAsBoolean() && !queue.isEmpty(); attempt++) {
            var pending = new ArrayList<T>();
            T item;
            while ((item = queue.poll()) != null) pending.add(item);
            if (pending.isEmpty()) return;
            log.accept("Deferred retry pass " + attempt + ": " + pending.size() + " payload(s).");
            var groups = new LinkedHashMap<Group, List<T>>();
            for (T task : pending) groups.computeIfAbsent(new Group(authority.apply(task), family.apply(task)),
                ignored -> new ArrayList<>()).add(task);
            ExecutorService pool = Executors.newFixedThreadPool(Math.max(1, Math.min(concurrency, pending.size())));
            Set<T> unstarted = ConcurrentHashMap.newKeySet();
            int retryAttempt = attempt;
            try {
                for (var entry : groups.entrySet()) {
                    var group = entry.getKey();
                    var tasks = entry.getValue();
                    if (quarantine.contains(group) || throttledHosts.contains(group.authority())) {
                        queue.addAll(tasks);
                        continue;
                    }
                    T sample = tasks.get(0);
                    if (!continuing.getAsBoolean() || !healthyControl.test(sample)) {
                        queue.addAll(tasks);
                        throttledHosts.add(group.authority());
                        log.accept("Automatic retries paused for " + group.authority() + ": control canary failed; requests retained.");
                        continue;
                    }
                    if (retry.test(sample, attempt)) {
                        if (tasks.size() > 1) queue.addAll(tasks.subList(1, tasks.size()));
                        quarantine.add(group);
                        quarantined.accept(tasks.size());
                        log.accept("Quarantined " + tasks.size() + " " + group.family() + " payload(s) for " + group.authority());
                        continue;
                    }
                    for (int index = 1; index < tasks.size(); index++) {
                        T task = tasks.get(index);
                        unstarted.add(task);
                        pool.submit(() -> {
                            unstarted.remove(task);
                            try { return retry.test(task, retryAttempt); }
                            catch (RuntimeException error) { queue.add(task); throw error; }
                        });
                    }
                }
            } finally {
                pool.shutdown();
                try {
                    while (continuing.getAsBoolean() && !pool.awaitTermination(200, TimeUnit.MILLISECONDS)) { }
                } catch (InterruptedException error) { Thread.currentThread().interrupt(); }
                finally {
                    if (!pool.isTerminated()) pool.shutdownNow();
                    queue.addAll(unstarted);
                }
            }
        }
    }
}
