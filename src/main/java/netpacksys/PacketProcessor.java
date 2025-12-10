package netpacksys;

import netpacksys.formatter.PacketFormatter;
import netpacksys.output.OutputWriter;
import netpacksys.parser.ApplicationParserRegistry;
import netpacksys.parser.LayerParser;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

public final class PacketProcessor {
    private final List<LayerParser> parsers;
    private final PacketFormatter formatter;
    private final OutputWriter consoleWriter;
    private final OutputWriter fileWriter;
    private final Set<String> protocols;
    private final ApplicationParserRegistry appRegistry = new ApplicationParserRegistry();
    private final AtomicLong filteredPacketCount = new AtomicLong(0);

    public PacketProcessor(List<LayerParser> parsers, PacketFormatter formatter, OutputWriter consoleWriter, OutputWriter fileWriter, Set<String> protocols) {
        this.parsers = parsers;
        this.formatter = formatter;
        this.consoleWriter = consoleWriter;
        this.fileWriter = fileWriter;
        this.protocols = protocols;
    }

    public long getFilteredPacketCount() {
        return filteredPacketCount.get();
    }

    public void process(PcapPacketStub packet, long frameNo) {
        PacketContext ctx = new PacketContext(frameNo, packet);

        for (LayerParser parser : parsers) {
            parser.parse(ctx);
        }

        TransportInfo t = ctx.transport();
        if (t != null) {
            appRegistry.parse(ctx, t);
        }

        addDelaySummary(ctx);

        boolean filter = protocols.contains("ALL");
        if (!filter) {
            Map<String, String> appLayer = ctx.layers().get("APP");
            if (appLayer != null) {
                String appProto = appLayer.get("AppProto");
                filter = protocols.contains(appProto);
            }
        }
        if (!filter) return;

        filteredPacketCount.incrementAndGet();

        List<String> rows = formatter.format(ctx);
        consoleWriter.writeRows(rows);
        fileWriter.writeRows(rows);
    }

    private void addDelaySummary(PacketContext ctx) {
        Map<String, String> summary = new LinkedHashMap<>();

        double totalDelay = ctx.getTotalNodalDelay();
        double processingDelay = ctx.getTotalProcessingDelay();
        double transmissionDelay = ctx.getTotalTransmissionDelay();
        double propagationDelay = ctx.getTotalPropagationDelay();
        double queuingDelay = ctx.getTotalQueuingDelay();

        summary.put("TotalNodalDelay", String.format("%.6f ms", totalDelay));
        summary.put("TotalProcessingDelay", String.format("%.6f ms", processingDelay));
        summary.put("TotalTransmissionDelay", String.format("%.6f ms", transmissionDelay));
        summary.put("TotalPropagationDelay", String.format("%.6f ms", propagationDelay));
        summary.put("TotalQueuingDelay", String.format("%.6f ms", queuingDelay));

        if (totalDelay > 0) {
            summary.put("ProcessingPercent", String.format("%.1f%%", (processingDelay / totalDelay) * 100));
            summary.put("TransmissionPercent", String.format("%.1f%%", (transmissionDelay / totalDelay) * 100));
            summary.put("PropagationPercent", String.format("%.1f%%", (propagationDelay / totalDelay) * 100));
            summary.put("QueuingPercent", String.format("%.1f%%", (queuingDelay / totalDelay) * 100));
        }

        String bottleneck = "Processing";
        double maxDelay = processingDelay;
        if (transmissionDelay > maxDelay) {
            maxDelay = transmissionDelay;
            bottleneck = "Transmission";
        }
        if (propagationDelay > maxDelay) {
            maxDelay = propagationDelay;
            bottleneck = "Propagation";
        }
        if (queuingDelay > maxDelay) {
            bottleneck = "Queuing";
        }
        summary.put("Bottleneck", bottleneck);

        ctx.layers().put("DELAY_SUMMARY", summary);
    }
}

