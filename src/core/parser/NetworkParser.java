package core.parser;

import core.DelayInfo;
import core.PacketContext;

import java.util.Arrays;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public final class NetworkParser implements LayerParser {
    private static String ip(byte[] b, int off) {
        if (b.length < off + 4) return "-";
        return String.format("%d.%d.%d.%d", b[off] & 0xFF, b[off + 1] & 0xFF, b[off + 2] & 0xFF, b[off + 3] & 0xFF);
    }

    private static String getProtocolName(int proto) {
        return switch (proto) {
            case 1 -> "ICMP";
            case 6 -> "TCP";
            case 17 -> "UDP";
            default -> "Unknown(" + proto + ")";
        };
    }

    @Override
    public void parse(PacketContext ctx) {
        long startTime = System.nanoTime();
        byte[] raw = ctx.payload();
        if (raw.length < 20 || (raw[0] & 0xF0) != 0x40) return;

        int ihl = (raw[0] & 0x0F) * 4;
        if (raw.length < ihl) return;

        int totLen = ((raw[2] & 0xFF) << 8) | (raw[3] & 0xFF);
        int proto = raw[9] & 0xFF;
        int ttl = raw[8] & 0xFF;
        int fragOffset = ((raw[6] & 0x1F) << 8) | (raw[7] & 0xFF);
        int flags = (raw[6] & 0xE0) >> 5;
        String flagsBin = String.format("%3s", Integer.toBinaryString(flags)).replace(' ', '0');

        Map<String, String> m = new LinkedHashMap<>();
        m.put("SrcIP", ip(raw, 12));
        m.put("DstIP", ip(raw, 16));
        m.put("TTL", String.valueOf(ttl));
        m.put("Proto", String.valueOf(proto));
        m.put("ProtoName", getProtocolName(proto));
        m.put("TotLen", String.valueOf(totLen));
        m.put("IHL", String.valueOf(ihl));
        m.put("Flags", String.format("0x%02x (%s bits)", flags, flagsBin));
        m.put("FragOffset", String.valueOf(fragOffset));

        double processingDelay = (System.nanoTime() - startTime) / 1_000_000.0;
        double routerProcessingDelay = 0.05;
        double networkBandwidth = 100_000_000.0;
        double packetSizeBits = totLen * 8.0;
        double transmissionDelay = (packetSizeBits / networkBandwidth) * 1000;

        double avgHopDistance = 500_000.0;
        double propagationSpeed = 200_000_000.0;
        double propagationDelay = (avgHopDistance / propagationSpeed) * 1000;

        double queuingDelay = 0.1 + (Math.random() * 2.0);

        DelayInfo delayInfo = new DelayInfo(
                processingDelay + routerProcessingDelay,
                transmissionDelay,
                propagationDelay,
                queuingDelay,
                String.format("Proc: %.3f ms (routing), Trans: %.6f ms (L/R), Prop: %.6f ms (hop), Queue: %.3f ms (congestion)",
                        routerProcessingDelay, transmissionDelay, propagationDelay, queuingDelay)
        );

        ctx.addDelayInfo("NETWORK", delayInfo);

        m.put("ProcessingDelay", String.format("%.6f ms", processingDelay + routerProcessingDelay));
        m.put("TransmissionDelay", String.format("%.6f ms", transmissionDelay));
        m.put("PropagationDelay", String.format("%.6f ms", propagationDelay));
        m.put("QueuingDelay", String.format("%.3f ms", queuingDelay));
        m.put("TotalDelay", String.format("%.6f ms", delayInfo.totalDelay()));
        m.put("HopDistance", String.format("%.0f km", avgHopDistance / 1000));

        ctx.addLayer("NETWORK", m, Arrays.copyOfRange(raw, ihl, raw.length));
    }
}


