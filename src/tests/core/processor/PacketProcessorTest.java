package core.processor;

import core.PacketProcessor;
import core.formatter.TabRowPacketFormatter;
import core.parser.FrameParser;
import core.parser.LinkParser;
import core.parser.NetworkParser;
import core.parser.TransportParser;
import core.support.TestOutputWriter;
import core.util.SyntheticPacketFactory;
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


