package netpacksys.parser;

import netpacksys.PacketContext;
import netpacksys.util.SyntheticPacketFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class NetworkParserTest {

    @Test
    void extractsIpv4Addresses() {
        var stub = SyntheticPacketFactory.httpRequestStub(10);
        var ctx = new PacketContext(10, stub);

        new FrameParser("SIM").parse(ctx);
        new LinkParser().parse(ctx);
        new NetworkParser().parse(ctx);

        var netLayer = ctx.layers().get("NETWORK");
        assertNotNull(netLayer, "NETWORK layer should be present");
        assertEquals("192.168.0.2", netLayer.get("SrcIP"));
        assertEquals("142.250.193.110", netLayer.get("DstIP"));
        assertEquals("6", netLayer.get("Proto"), "Protocol should be TCP (6)");
    }
}

