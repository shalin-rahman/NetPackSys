package core.parser;

import core.DelayInfo;
import core.PacketContext;
import core.TransportInfo;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public final class HttpParser implements ApplicationParser {
    @Override
    public boolean canParse(PacketContext ctx, TransportInfo t) {
        return "TCP".equals(t.proto()) && (t.dstPort() == 80 || t.dstPort() == 8080 || t.srcPort() == 80 || t.srcPort() == 8080);
    }

    @Override
    public Map<String, String> parse(PacketContext ctx, TransportInfo t) {
        long startTime = System.nanoTime();
        Map<String, String> m = new LinkedHashMap<>();
        m.put("AppProto", "HTTP");

        try {
            String payload = new String(ctx.payload(), StandardCharsets.US_ASCII);
            if (!payload.trim().isEmpty()) {
                String firstLine = payload.lines().findFirst().orElse("").trim();
                if (!firstLine.isEmpty()) {
                    m.put("FirstLine", firstLine);

                    if (firstLine.startsWith("HTTP/")) {
                        m.put("Type", "Response");
                        String[] parts = firstLine.split(" ");
                        if (parts.length >= 2) {
                            m.put("StatusCode", parts[1]);
                        }
                    } else {
                        m.put("Type", "Request");
                        String[] parts = firstLine.split(" ");
                        if (parts.length >= 2) {
                            m.put("Method", parts[0]);
                            m.put("Path", parts[1]);
                        }
                    }
                }
            }
        } catch (Exception ignored) {
            m.put("Error", "Malformed HTTP");
        }

        double processingDelay = (System.nanoTime() - startTime) / 1_000_000.0;
        double appProcessingDelay = 0.1 + (Math.random() * 0.5);
        double queuingDelay = 0.2 + (Math.random() * 1.0);

        DelayInfo delayInfo = new DelayInfo(
                processingDelay + appProcessingDelay,
                0,
                0,
                queuingDelay,
                String.format("Proc: %.3f ms (app logic), Queue: %.3f ms (CPU/IO wait)",
                        appProcessingDelay, queuingDelay)
        );

        ctx.addDelayInfo("APP", delayInfo);

        m.put("ProcessingDelay", String.format("%.6f ms", processingDelay + appProcessingDelay));
        m.put("TransmissionDelay", "0.000000 ms");
        m.put("PropagationDelay", "0.000000 ms");
        m.put("QueuingDelay", String.format("%.3f ms", queuingDelay));
        m.put("TotalDelay", String.format("%.6f ms", delayInfo.totalDelay()));

        return m;
    }
}


