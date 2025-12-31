package core;

import core.capture.CaptureService;
import core.capture.PcapCaptureService;
import core.capture.SimulatedCaptureService;
import core.formatter.TabRowPacketFormatter;
import core.output.ConsoleOutputAccumulator;
import core.output.FileOutputWriter;
import core.parser.ApplicationParserRegistry;
import core.parser.FrameParser;
import core.parser.LayerParser;
import core.parser.LinkParser;
import core.parser.NetworkParser;
import core.parser.TransportParser;

import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

public final class PacketAnalyzerApp {
    private final Config cfg;
    private final CaptureService capture;
    private final PacketProcessor processor;
    private final StructuredBatchExecutor executor;
    private final ConsoleOutputAccumulator consoleAccumulator;
    private final FileOutputWriter fileWriter;

    public PacketAnalyzerApp(Config cfg) throws org.pcap4j.core.PcapNativeException {
        this.cfg = cfg;

        CaptureService cs;
        if ("sim".equalsIgnoreCase(cfg.iface())) {
            cs = new SimulatedCaptureService();
        } else {
            cs = new PcapCaptureService(cfg.iface());
            System.out.println(" Live capture initialized on: " + cfg.usedNetwork());
        }

        this.capture = cs;
        this.consoleAccumulator = new ConsoleOutputAccumulator();
        this.fileWriter = new FileOutputWriter(cfg.outFile());

        List<LayerParser> parsers = List.of(
                new FrameParser(cfg.usedNetwork()),
                new LinkParser(),
                new NetworkParser(),
                new TransportParser()
        );

        this.processor = new PacketProcessor(parsers, new TabRowPacketFormatter(), consoleAccumulator, fileWriter, cfg.protocols());
        this.executor = new StructuredBatchExecutor(Executors.newVirtualThreadPerTaskExecutor());
    }

    public long run() throws Exception {
        System.out.printf(" Capturing for %ds, protocols=%s%n", cfg.durationSec(), cfg.protocols());
        final AtomicLong count = new AtomicLong(0);
        long start = System.currentTimeMillis();
        final long deadline = start + cfg.durationSec() * 1000L;

        final ExecutorService captureExecutor = Executors.newSingleThreadExecutor();

        final StructuredBatchExecutor finalExecutor = this.executor;
        final PacketProcessor finalProcessor = this.processor;

        try (CaptureService cap = capture; FileOutputWriter fw = fileWriter) {
            Future<Void> captureFuture = captureExecutor.submit(() -> {
                try {
                    capture.startCapture(packet -> {
                        if (System.currentTimeMillis() > deadline) {
                            return false;
                        }

                        final long n = count.incrementAndGet();
                        finalExecutor.submitBatchTask(() -> {
                            finalProcessor.process(packet, n);
                            return Boolean.TRUE;
                        });
                        return true;
                    }, cfg.durationSec());
                    return null;
                } catch (Exception e) {
                    System.err.println("\n Capture failed: " + e.getMessage());
                    return null;
                }
            });

            while (!captureFuture.isDone()) {
                long remainingSec = (deadline - System.currentTimeMillis() + 999) / 1000;
                if (remainingSec < 0) remainingSec = 0;

                System.out.printf("\r Time Remaining: %d seconds. Packets processed: %d", remainingSec, count.get());

                if (remainingSec == 0) break;

                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            System.out.println();

            try {
                captureFuture.get(cfg.durationSec() + 2, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                System.err.println(" Capture thread timed out during termination, forcing shutdown.");
                captureFuture.cancel(true);
            }

        } finally {
            captureExecutor.shutdownNow();
            executor.shutdownAndAwait();

            long totalPackets = count.get();
            long filteredPackets = processor.getFilteredPacketCount();
            consoleAccumulator.printFinalReport(filteredPackets, totalPackets);
        }
        return count.get();
    }
}


