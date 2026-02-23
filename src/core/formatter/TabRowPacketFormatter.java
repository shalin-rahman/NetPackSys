package core.formatter;

import core.PacketContext;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public final class TabRowPacketFormatter implements PacketFormatter {
    @Override
    public List<String> format(PacketContext ctx) {
        List<String> rows = new ArrayList<>();

        // Create a temporary map to hold all layers
        Map<String, Map<String, String>> layerMap = ctx.layers();

        // 1. FRAME should always be first
        Map<String, String> frameLayer = layerMap.get("FRAME");
        if (frameLayer != null) {
            rows.add(formatLayer("FRAME", frameLayer));
        }

        // 2. All other layers except FRAME and DELAY_SUMMARY
        for (Map.Entry<String, Map<String, String>> e : layerMap.entrySet()) {
            String layerName = e.getKey();
            if ("FRAME".equals(layerName) || "DELAY_SUMMARY".equals(layerName)) continue;
            rows.add(formatLayer(layerName, e.getValue()));
        }

        // 3. DELAY_SUMMARY should be near the end
        Map<String, String> delaySummary = layerMap.get("DELAY_SUMMARY");
        if (delaySummary != null) {
            rows.add(formatLayer("DELAY_SUMMARY", delaySummary));
            rows.add(""); // Space after delay info
        }

        // 4. DATA_DUMP for bit visualization
        Map<String, String> dataDump = layerMap.get("DATA_DUMP");
        if (dataDump != null) {
            rows.add(formatLayer("DATA_DUMP", dataDump));
            rows.add(""); // Space after data dump
        }

        rows.add("----");
        rows.add(""); // Extra newline after the whole frame block
        return rows;
    }

    private String formatLayer(String name, Map<String, String> fields) {
        String data = name + "\t" +
                fields.entrySet().stream()
                        .map(x -> x.getKey() + "=" + x.getValue())
                        .collect(Collectors.joining("\t"));
        return data + "\n"; // Explicit newline after layer
    }
}


