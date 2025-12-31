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

        Map<String, String> delaySummary = ctx.layers().get("DELAY_SUMMARY");
        if (delaySummary != null) {
            String summaryRow = "DELAY_SUMMARY\t" +
                    delaySummary.entrySet().stream()
                            .map(x -> x.getKey() + "=" + x.getValue())
                            .collect(Collectors.joining("\t"));
            rows.add(summaryRow);
            rows.add("----");
        }

        for (Map.Entry<String, Map<String, String>> e : ctx.layers().entrySet()) {
            if ("DELAY_SUMMARY".equals(e.getKey())) continue;

            String row = e.getKey() + "\t" +
                    e.getValue().entrySet().stream()
                            .map(x -> x.getKey() + "=" + x.getValue())
                            .collect(Collectors.joining("\t"));
            rows.add(row);
        }
        rows.add("----");
        return rows;
    }
}


