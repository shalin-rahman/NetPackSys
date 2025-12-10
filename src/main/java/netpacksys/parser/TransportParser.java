package netpacksys.parser;

import netpacksys.DelayInfo;
import netpacksys.PacketContext;

import java.util.ArrayList;
import java.util.Arrays;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class TransportParser implements LayerParser {
    private static String getTcpFlags(int flags) {
        List<String> flagList = new ArrayList<>();
        if ((flags & 0x01) != 0) flagList.add("FIN");
        if ((flags & 0x02) != 0) flagList.add("SYN");
        if ((flags & 0x04) != 0) flagList.add("RST");
        if ((flags & 0x08) != 0) flagList.add("PSH");
        if ((flags & 0x10) != 0) flagList.add("ACK");
        if ((flags & 0x20) != 0) flagList.add("URG");
        return flagList.isEmpty() ? "None" : String.join(",", flagList);
    }

    @Override
    public void parse(PacketContext ctx) {
        long startTime = System.nanoTime();
        Map<String, String> network = ctx.layers().get("NETWORK");
        if (network == null) return;

        int proto = Integer.parseInt(network.get("Proto"));
        byte[] raw = ctx.payload();
        if (raw.length < 8) return;

        Map<String, String> m = new LinkedHashMap<>();
        int headerLen = 0;
        int payloadSize = 0;

        if (proto == 6) {
            if (raw.length < 20) return;
            int srcPort = ((raw[0] & 0xFF) << 8) | (raw[1] & 0xFF);
            int dstPort = ((raw[2] & 0xFF) << 8) | (raw[3] & 0xFF);
            int flags = raw[13] & 0x3F;
            headerLen = (raw[12] >> 4) * 4;
            payloadSize = raw.length - headerLen;

            m.put("SrcPort", String.valueOf(srcPort));
            m.put("DstPort", String.valueOf(dstPort));
            m.put("Proto", "TCP");
            m.put("PayloadLen", String.valueOf(payloadSize));
            m.put("Flags", String.format("0x%02x", flags));
            m.put("FlagsDesc", getTcpFlags(flags));

        } else if (proto == 17) {
            int srcPort = ((raw[0] & 0xFF) << 8) | (raw[1] & 0xFF);
            int dstPort = ((raw[2] & 0xFF) << 8) | (raw[3] & 0xFF);
            headerLen = 8;
            payloadSize = raw.length - headerLen;

            m.put("SrcPort", String.valueOf(srcPort));
            m.put("DstPort", String.valueOf(dstPort));
            m.put("Proto", "UDP");
            m.put("PayloadLen", String.valueOf(payloadSize));
            m.put("Flags", "-");
        }

        double processingDelay = (System.nanoTime() - startTime) / 1_000_000.0;
        double tcpProcessingDelay = proto == 6 ? 0.02 : 0.01;
        double endSystemRate = 1_000_000_000.0;
        double segmentSizeBits = raw.length * 8.0;
        double transmissionDelay = (segmentSizeBits / endSystemRate) * 1000;
        double propagationDelay = 0.001;
        double queuingDelay = 0.05 + (Math.random() * 0.1);

        DelayInfo delayInfo = new DelayInfo(
                processingDelay + tcpProcessingDelay,
                transmissionDelay,
                propagationDelay,
                queuingDelay,
                String.format("Proc: %.3f ms (TCP/UDP), Trans: %.6f ms (end system), Queue: %.3f ms (socket buffer)",
                        tcpProcessingDelay, transmissionDelay, queuingDelay)
        );

        ctx.addDelayInfo("TRANSPORT", delayInfo);

        m.put("ProcessingDelay", String.format("%.6f ms", processingDelay + tcpProcessingDelay));
        m.put("TransmissionDelay", String.format("%.6f ms", transmissionDelay));
        m.put("PropagationDelay", String.format("%.6f ms", propagationDelay));
        m.put("QueuingDelay", String.format("%.3f ms", queuingDelay));
        m.put("TotalDelay", String.format("%.6f ms", delayInfo.totalDelay()));

        if (!m.isEmpty()) {
            ctx.addLayer("TRANSPORT", m, Arrays.copyOfRange(raw, headerLen, raw.length));
        }
    }
}

