package netpacksys;

import java.util.List;
import java.util.Map;

public final class ApplicationParserRegistry {
    private final List<ApplicationParser> parsers = List.of(
            new HttpParser(),
            new TlsParser(),
            new DnsParser()
    );

    public void parse(PacketContext ctx, TransportInfo t) {
        for (ApplicationParser parser : parsers) {
            if (parser.canParse(ctx, t)) {
                Map<String, String> appData = parser.parse(ctx, t);
                if (appData != null && !appData.isEmpty()) {
                    ctx.addLayer("APP", appData, new byte[0]);
                    return;
                }
            }
        }

        Map<String, String> genericApp = new java.util.LinkedHashMap<>();
        genericApp.put("AppProto", "UNKNOWN");
        genericApp.put("Info", "No specific application protocol detected");
        ctx.addLayer("APP", genericApp, new byte[0]);
    }
}

