package netpacksys.parser;

import netpacksys.PacketContext;
import netpacksys.TransportInfo;
import netpacksys.parser.ApplicationParserRegistry;
import netpacksys.util.SyntheticPacketFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ApplicationParserRegistryTest {

    @Test
    void httpParserIsSelected() {
        var stub = SyntheticPacketFactory.httpRequestStub(1);
        var ctx = new PacketContext(1, stub);
        var t = new TransportInfo(51322, 80, "TCP", 0, "0x00");

        new ApplicationParserRegistry().parse(ctx, t);

        var app = ctx.layers().get("APP");
        assertNotNull(app, "APP layer should exist");
        assertEquals("HTTP", app.get("AppProto"));
        assertTrue(app.getOrDefault("FirstLine", "").startsWith("GET"), "Should capture HTTP request line");
    }

    @Test
    void tlsParserExtractsSniWhenPresent() {
        var stub = SyntheticPacketFactory.tlsClientHelloStub(2);
        var ctx = new PacketContext(2, stub);
        var t = new TransportInfo(51322, 443, "TCP", 0, "0x00");

        new ApplicationParserRegistry().parse(ctx, t);

        var app = ctx.layers().get("APP");
        assertNotNull(app, "APP layer should exist");
        assertEquals("TLS", app.get("AppProto"));
        assertEquals(SyntheticPacketFactory.SIM_HOST, app.get("SNI"), "SNI should be extracted from ClientHello");
    }
}

