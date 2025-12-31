package core.parser;

import core.DelayInfo;
import core.PacketContext;
import core.PcapPacketStub;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;

public final class FrameParser implements LayerParser {
    private final String usedNetwork;
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSS'Z'").withZone(ZoneOffset.UTC);

    public FrameParser(String usedNetwork) {
        this.usedNetwork = usedNetwork;
    }

    @Override
    public void parse(PacketContext ctx) {
        PcapPacketStub stub = ctx.stub();
        long startTime = System.nanoTime();

        Map<String, String> m = new LinkedHashMap<>();
        m.put("FrameNo", String.valueOf(stub.frameNo()));
        m.put("UsedNetwork", usedNetwork);
        m.put("Len", String.valueOf(stub.length()));
        m.put("CapLen", String.valueOf(stub.capLength()));
        m.put("WireBits", String.valueOf(stub.length() * 8));
        m.put("Timestamp", ISO_FORMATTER.format(stub.timestamp()));

        double processingDelay = (System.nanoTime() - startTime) / 1_000_000.0;
        double transmissionDelay = 0;
        double propagationDelay = 0;
        double queuingDelay = 0;

        DelayInfo delayInfo = new DelayInfo(
                processingDelay,
                transmissionDelay,
                propagationDelay,
                queuingDelay,
                String.format("Processing: %.6f ms (header parsing)", processingDelay)
        );

        ctx.addDelayInfo("FRAME", delayInfo);
        m.put("ProcessingDelay", String.format("%.6f ms", processingDelay));
        m.put("TransmissionDelay", String.format("%.6f ms", transmissionDelay));
        m.put("PropagationDelay", String.format("%.6f ms", propagationDelay));
        m.put("QueuingDelay", String.format("%.6f ms", queuingDelay));
        m.put("TotalDelay", String.format("%.6f ms", delayInfo.totalDelay()));

        ctx.addLayer("FRAME", m, ctx.payload());
    }
}


