package netpacksys;

import netpacksys.formatter.TabRowPacketFormatter;
import netpacksys.output.OutputWriter;
import netpacksys.parser.FrameParser;
import netpacksys.parser.LinkParser;
import netpacksys.parser.NetworkParser;
import netpacksys.parser.TransportParser;
import netpacksys.util.SyntheticPacketFactory;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class PacketAnalyzerAppTest {

    @Test
    void simulationProducesPackets() throws Exception {
        Path tempLog = Files.createTempFile("packet-log", ".txt");
        Config cfg = new Config("sim", "SIMULATED", 1, Set.of("ALL"), tempLog.toString());
        PacketAnalyzerApp app = new PacketAnalyzerApp(cfg);
        long count = app.run();
        assertTrue(count > 0, "Simulation should produce packets");
        assertTrue(Files.size(tempLog) > 0, "Log file should contain output");
    }

    @Test
    void processorFiltersRequestedProtocol() {
        CaptureListWriter consoleWriter = new CaptureListWriter();
        CaptureListWriter fileWriter = new CaptureListWriter();
        PacketProcessor processor = new PacketProcessor(
                List.of(new FrameParser("SIM"), new LinkParser(), new NetworkParser(), new TransportParser()),
                new TabRowPacketFormatter(),
                consoleWriter,
                fileWriter,
                Set.of("HTTP")
        );

        PcapPacketStub stub = SyntheticPacketFactory.httpRequestStub(1);
        processor.process(stub, 1);

        assertEquals(1, processor.getFilteredPacketCount(), "HTTP packet should be counted");
        assertFalse(consoleWriter.rows.isEmpty(), "Console writer should receive rows");
        assertFalse(fileWriter.rows.isEmpty(), "File writer should receive rows");
    }

    @Test
    void delayInfoTotalsAccumulate() {
        DelayInfo info = new DelayInfo(1.0, 2.0, 3.0, 4.0, "test");
        assertEquals(10.0, info.totalDelay(), 0.0001);
    }

    private static final class CaptureListWriter implements OutputWriter {
        private final List<String> rows = new ArrayList<>();

        @Override
        public void writeRows(List<String> newRows) {
            rows.addAll(newRows);
        }

        @Override
        public void close() throws IOException {
            // no-op
        }
    }
}

