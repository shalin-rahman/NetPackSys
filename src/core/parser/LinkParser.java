package core.parser;

import core.DelayInfo;
import core.PacketContext;

import java.util.Arrays;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public final class LinkParser implements LayerParser {
    private static String mac(byte[] b, int off) {
        if (b.length < off + 6) return "-";
        String[] parts = new String[6];
        for (int i = 0; i < 6; i++) {
            parts[i] = String.format("%02x", b[off + i]);
        }
        return String.join(":", parts);
    }

    @Override
    public void parse(PacketContext ctx) {
        long startTime = System.nanoTime();
        byte[] raw = ctx.payload();
        if (raw.length < 14) return;

        int etherType = ((raw[12] & 0xFF) << 8) | (raw[13] & 0xFF);

        Map<String, String> m = new LinkedHashMap<>();
        m.put("DstMAC", mac(raw, 0));
        m.put("SrcMAC", mac(raw, 6));
        m.put("EtherType", String.format("0x%04x", etherType));
        m.put("EtherTypeDesc", getEtherTypeDescription(etherType));

        double processingDelay = (System.nanoTime() - startTime) / 1_000_000.0;

        double linkRate = 1_000_000_000.0;
        double frameSizeBits = raw.length * 8.0;
        double transmissionDelay = (frameSizeBits / linkRate) * 1000;

        double distance = 100.0;
        double propagationSpeed = 200_000_000.0;
        double propagationDelay = (distance / propagationSpeed) * 1000;

        double queuingDelay = 0.001;

        DelayInfo delayInfo = new DelayInfo(
                processingDelay,
                transmissionDelay,
                propagationDelay,
                queuingDelay,
                String.format("Trans: %.6f ms (L/R=%.0f bits / %.0f bps), Prop: %.6f ms (d/s=%.1f m / %.0f m/s)",
                        transmissionDelay, frameSizeBits, linkRate, propagationDelay, distance, propagationSpeed)
        );

        ctx.addDelayInfo("LINK", delayInfo);

        m.put("ProcessingDelay", String.format("%.6f ms", processingDelay));
        m.put("TransmissionDelay", String.format("%.6f ms", transmissionDelay));
        m.put("PropagationDelay", String.format("%.6f ms", propagationDelay));
        m.put("QueuingDelay", String.format("%.6f ms", queuingDelay));
        m.put("TotalDelay", String.format("%.6f ms", delayInfo.totalDelay()));
        m.put("LinkRate", String.format("%.0f Mbps", linkRate / 1_000_000));
        m.put("Distance", String.format("%.1f m", distance));

        if (etherType == 0x8100 || etherType == 0x88a8) {
            if (raw.length < 18) return;
            etherType = ((raw[16] & 0xFF) << 8) | (raw[17] & 0xFF);

            Map<String, String> vlan = new LinkedHashMap<>();
            vlan.put("VLANID", String.valueOf(((raw[14] & 0x0F) << 8) | (raw[15] & 0xFF)));
            vlan.put("EtherType", String.format("0x%04x", etherType));

            ctx.addLayer("VLAN", vlan, Arrays.copyOfRange(raw, 18, raw.length));
            raw = Arrays.copyOfRange(raw, 18, raw.length);
        }

        if (etherType == 0x0800) {
            ctx.addLayer("LINK", m, Arrays.copyOfRange(raw, 14, raw.length));
        } else {
            ctx.addLayer("LINK", m, new byte[0]);
        }
    }

    private String getEtherTypeDescription(int etherType) {
        return switch (etherType) {
            case 0x0800 -> "IPv4";
            case 0x0806 -> "ARP";
            case 0x86DD -> "IPv6";
            case 0x8100 -> "VLAN-tagged";
            default -> "Unknown";
        };
    }
}


