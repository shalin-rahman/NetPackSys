package core.parser;

import core.PacketContext;
import core.PcapPacketStub;
import core.TransportInfo;
import core.util.SyntheticPacketFactory;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DnsParserTest {

    @Test
    void parsesDnsQuery() {
        byte[] payload = SyntheticPacketFactory.buildSyntheticDnsQuery("google.com");
        var stub = new PcapPacketStub(1, payload, Instant.now(), payload.length, payload.length);
        var ctx = new PacketContext(1, stub);
        var t = new TransportInfo(12345, 53, "UDP", payload.length, "-");

        Map<String, String> appLayer = new DnsParser().parse(ctx, t);

        assertNotNull(appLayer, "DNS data should be returned");
        assertEquals("DNS", appLayer.get("AppProto"));
        assertEquals("google.com", appLayer.get("Query"));
    }
}
