package core.parser;

import core.PacketContext;
import core.util.SyntheticPacketFactory;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class LinkParserTest {

    @Test
    void extractsEthernetMacAddresses() {
        var stub = SyntheticPacketFactory.httpRequestStub(1);
        var ctx = new PacketContext(1, stub);

        new LinkParser().parse(ctx);

        Map<String, String> linkLayer = ctx.layers().get("LINK");
        assertNotNull(linkLayer, "LINK layer should be present");
        
        // SyntheticPacketFactory uses 00:11:22:33:44:55 for source in makeEthernetIpv4TcpPacket
        assertEquals("00:11:22:33:44:55", linkLayer.get("SrcMAC"));
        assertEquals("00:00:00:00:00:00", linkLayer.get("DstMAC"));
        assertEquals("0x0800", linkLayer.get("EtherType"));
    }
}
