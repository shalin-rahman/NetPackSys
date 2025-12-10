package netpacksys;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public final class DnsParser implements ApplicationParser {
    @Override
    public boolean canParse(PacketContext ctx, TransportInfo t) {
        return "UDP".equals(t.proto()) && (t.dstPort() == 53 || t.srcPort() == 53);
    }

    @Override
    public Map<String, String> parse(PacketContext ctx, TransportInfo t) {
        long startTime = System.nanoTime();
        Map<String, String> m = new LinkedHashMap<>();
        m.put("AppProto", "DNS");
        byte[] raw = ctx.payload();
        if (raw.length < 12) {
            m.put("Error", "Packet too short");
            return m;
        }

        try {
            int id = ((raw[0] & 0xFF) << 8) | (raw[1] & 0xFF);
            int flags = ((raw[2] & 0xFF) << 8) | (raw[3] & 0xFF);
            int qdCount = ((raw[4] & 0xFF) << 8) | (raw[5] & 0xFF);
            int anCount = ((raw[6] & 0xFF) << 8) | (raw[7] & 0xFF);
            int nsCount = ((raw[8] & 0xFF) << 8) | (raw[9] & 0xFF);
            int arCount = ((raw[10] & 0xFF) << 8) | (raw[11] & 0xFF);

            m.put("ID", String.format("0x%04x", id));
            m.put("Flags", String.format("0x%04x", flags));
            m.put("Questions", String.valueOf(qdCount));
            m.put("Answers", String.valueOf(anCount));
            m.put("Authority", String.valueOf(nsCount));
            m.put("Additional", String.valueOf(arCount));

            boolean isResponse = (flags & 0x8000) != 0;
            m.put("Type", isResponse ? "Response" : "Query");

            if (qdCount > 0 && !isResponse) {
                StringBuilder qname = new StringBuilder();
                int offset = 12;
                while (offset < raw.length && offset < 512) {
                    int len = raw[offset] & 0xFF;
                    if (len == 0) break;
                    if (len > 63) break;

                    if (!qname.isEmpty()) qname.append('.');
                    qname.append(new String(raw, offset + 1, len, StandardCharsets.US_ASCII));
                    offset += len + 1;

                    if (offset + 1 < raw.length && raw[offset] == 0) {
                        int qtype = ((raw[offset + 1] & 0xFF) << 8) | (raw[offset + 2] & 0xFF);
                        m.put("QueryType", getDnsType(qtype));
                        break;
                    }
                }
                if (!qname.isEmpty()) {
                    m.put("Query", qname.toString());
                }
            }

        } catch (Exception e) {
            m.put("Error", "Malformed DNS");
        }

        double processingDelay = (System.nanoTime() - startTime) / 1_000_000.0;
        double dnsProcessingDelay = 0.05;
        double queuingDelay = 0.1 + (Math.random() * 0.2);

        DelayInfo delayInfo = new DelayInfo(
                processingDelay + dnsProcessingDelay,
                0,
                0,
                queuingDelay,
                String.format("Proc: %.3f ms (DNS resolution), Queue: %.3f ms", dnsProcessingDelay, queuingDelay)
        );

        ctx.addDelayInfo("APP", delayInfo);

        m.put("ProcessingDelay", String.format("%.6f ms", processingDelay + dnsProcessingDelay));
        m.put("TransmissionDelay", "0.000000 ms");
        m.put("PropagationDelay", "0.000000 ms");
        m.put("QueuingDelay", String.format("%.3f ms", queuingDelay));
        m.put("TotalDelay", String.format("%.6f ms", delayInfo.totalDelay()));

        return m;
    }

    private String getDnsType(int qtype) {
        return switch (qtype) {
            case 1 -> "A";
            case 28 -> "AAAA";
            case 5 -> "CNAME";
            case 15 -> "MX";
            case 2 -> "NS";
            case 12 -> "PTR";
            case 6 -> "SOA";
            case 16 -> "TXT";
            default -> "UNKNOWN(" + qtype + ")";
        };
    }
}

