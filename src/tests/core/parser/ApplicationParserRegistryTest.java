package core.parser;

import core.PacketContext;
import core.PcapPacketStub;
import core.TransportInfo;
import core.util.SyntheticPacketFactory;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class ApplicationParserRegistryTest {

    @Test
    void httpParserIsSelected() {
        // Create a payload-only stub for unit testing the registry logic
        byte[] payload = ("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
        var stub = new PcapPacketStub(1, payload, Instant.now(), payload.length, payload.length);
        
        var ctx = new PacketContext(1, stub);
        var t = new TransportInfo(51322, 80, "TCP", payload.length, "0x00");

        new ApplicationParserRegistry().parse(ctx, t);

        var app = ctx.layers().get("APP");
        assertNotNull(app, "APP layer should exist");
        assertEquals("HTTP", app.get("AppProto"));
        assertTrue(app.getOrDefault("FirstLine", "").startsWith("GET"), "Should capture HTTP request line");
    }

    @Test
    void tlsParserExtractsSniWhenPresent() {
        // Create a payload-only stub for TLS
        byte[] payload = SyntheticPacketFactory.buildSyntheticTlsClientHello(SyntheticPacketFactory.SIM_HOST);
        var stub = new PcapPacketStub(2, payload, Instant.now(), payload.length, payload.length);
        
        var ctx = new PacketContext(2, stub);
        var t = new TransportInfo(51322, 443, "TCP", payload.length, "0x00");

        new ApplicationParserRegistry().parse(ctx, t);

        var app = ctx.layers().get("APP");
        assertNotNull(app, "APP layer should exist");
        assertEquals("TLS", app.get("AppProto"));
        assertEquals(SyntheticPacketFactory.SIM_HOST, app.get("SNI"), "SNI should be extracted from ClientHello");
    }
}

