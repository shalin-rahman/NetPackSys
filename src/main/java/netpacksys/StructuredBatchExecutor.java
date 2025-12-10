package netpacksys;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.Phaser;
import java.util.concurrent.TimeUnit;

public final class StructuredBatchExecutor {
    private final ExecutorService executor;
    private final List<Future<?>> tasks = Collections.synchronizedList(new ArrayList<>());
    private final Phaser phaser = new Phaser(1);

    public StructuredBatchExecutor(ExecutorService executor) {
        this.executor = executor;
    }

    public <T> Future<T> submitBatchTask(Callable<T> task) {
        phaser.register();
        Future<T> future = executor.submit(() -> {
            try {
                return task.call();
            } finally {
                phaser.arriveAndDeregister();
            }
        });
        tasks.add(future);
        return future;
    }

    public void shutdownAndAwait() {
        phaser.arriveAndAwaitAdvance();
        executor.shutdown();
        try {
            if (!executor.awaitTermination(60, TimeUnit.SECONDS)) {
                System.err.println(" Batch executor did not terminate in time. Forcing shutdown.");
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            executor.shutdownNow();
        }
    }
}

