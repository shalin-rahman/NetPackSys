package netpacksys.processor;

import netpacksys.PacketProcessor;
import netpacksys.formatter.TabRowPacketFormatter;
import netpacksys.parser.FrameParser;
import netpacksys.parser.LinkParser;
import netpacksys.parser.NetworkParser;
import netpacksys.parser.TransportParser;
import netpacksys.support.TestOutputWriter;
import netpacksys.util.SyntheticPacketFactory;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class PacketProcessorTest {

    @Test
    void delaySummaryIsAddedForProcessedPackets() {
        var processor = new PacketProcessor(
                List.of(new FrameParser("SIM"), new LinkParser(), new NetworkParser(), new TransportParser()),
                new TabRowPacketFormatter(),
                new TestOutputWriter(),
                new TestOutputWriter(),
                Set.of("ALL")
        );

        var stub = SyntheticPacketFactory.httpRequestStub(1);
        processor.process(stub, 1);

        assertEquals(1, processor.getFilteredPacketCount());
    }

    @Test
    void nonMatchingProtocolIsFilteredOut() {
        var processor = new PacketProcessor(
                List.of(new FrameParser("SIM"), new LinkParser(), new NetworkParser(), new TransportParser()),
                new TabRowPacketFormatter(),
                new TestOutputWriter(),
                new TestOutputWriter(),
                Set.of("DNS")
        );

        var stub = SyntheticPacketFactory.httpRequestStub(1);
        processor.process(stub, 1);

        assertEquals(0, processor.getFilteredPacketCount(), "HTTP should be filtered when only DNS requested");
    }
}

