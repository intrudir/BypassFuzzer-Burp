package com.bypassfuzzer.core.scan;

import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;

/** Deferred retries retain every unattempted item when a run is edited or stopped. */
public final class DeferredRetryRunner<T> {
    private record Group(String authority,String family) { }
    public void run(Queue<T> queue,int attempts,int concurrency,BooleanSupplier continuing,
        Function<T,String> authority,Function<T,String> family,Predicate<T> healthyControl,
        BiPredicate<T,Integer> retry,IntConsumer quarantined,Consumer<String> log) {
        Set<Group> quarantine=new HashSet<>();Set<String> throttledHosts=new HashSet<>();
        for(int attempt=1;attempt<=attempts && continuing.getAsBoolean() && !queue.isEmpty();attempt++) {
            var pending=new ArrayList<T>();T item;while((item=queue.poll())!=null)pending.add(item);
            if(pending.isEmpty())return;
            log.accept("Deferred retry pass "+attempt+": "+pending.size()+" payload(s).");
            var groups=new LinkedHashMap<Group,List<T>>();
            for(T task:pending)groups.computeIfAbsent(new Group(authority.apply(task),family.apply(task)),ignored -> new ArrayList<>()).add(task);
            ExecutorService pool=Executors.newFixedThreadPool(Math.max(1,Math.min(concurrency,pending.size())));
            Set<T> outstanding=ConcurrentHashMap.newKeySet();outstanding.addAll(pending);
            var futures=new ArrayList<Future<?>>();int retryAttempt=attempt;
            try {
                for(var entry:groups.entrySet()) {
                    var group=entry.getKey();var tasks=entry.getValue();
                    if(quarantine.contains(group) || throttledHosts.contains(group.authority()))continue;
                    T sample=tasks.get(0);
                    if(!continuing.getAsBoolean() || !healthyControl.test(sample)) {
                        throttledHosts.add(group.authority());log.accept("Automatic retries paused for "+group.authority()+": control canary failed; requests retained.");continue;
                    }
                    boolean failed=retry.test(sample,attempt);outstanding.remove(sample);
                    if(failed) {
                        quarantine.add(group);quarantined.accept(tasks.size());
                        log.accept("Quarantined "+tasks.size()+" "+group.family()+" payload(s) for "+group.authority());continue;
                    }
                    for(int index=1;index<tasks.size();index++) {
                        T task=tasks.get(index);futures.add(pool.submit(() -> {boolean result=retry.test(task,retryAttempt);outstanding.remove(task);return result;}));
                    }
                }
                for(var future:futures)try {future.get();}
                catch(ExecutionException error) {if(error.getCause() instanceof RuntimeException runtime)throw runtime;throw new CompletionException(error.getCause());}
                catch(InterruptedException error) {Thread.currentThread().interrupt();throw new CancellationException("Retry pass stopped");}
            } finally {
                pool.shutdown();
                try {while(continuing.getAsBoolean() && !pool.awaitTermination(100,TimeUnit.MILLISECONDS)) { }}
                catch(InterruptedException error){Thread.currentThread().interrupt();}
                finally {
                    if(!pool.isTerminated())pool.shutdownNow();
                    for(T task:outstanding)if(!queue.contains(task))queue.add(task);
                }
            }
        }
    }
}
