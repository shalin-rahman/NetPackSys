package processor;

import model.PacketRecord;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TableLogProcessorTest {

    @Test
    void parsesPacketBlockCorrectly() {
        List<String> logs = List.of(
            "FRAME\tFrameNo=5\tTimestamp=2025-01-01T12:00:00Z\tLen=64\n",
            "NETWORK\tSrcIP=1.1.1.1\tDstIP=2.2.2.2\tProtoName=TCP\n",
            "TRANSPORT\tSrcPort=80\tDstPort=1234\tProtoName=TCP\n",
            "DELAY_SUMMARY\tTotalNodalDelay=0.5 ms\n",
            "----\n"
        );

        TableLogProcessor processor = new TableLogProcessor();
        List<PacketRecord> records = processor.process(logs);

        assertEquals(1, records.size(), "Should have 1 packet record");
        PacketRecord r = records.get(0);
        assertEquals(5, r.frameNo());
        assertEquals("1.1.1.1", r.srcIp());
        assertEquals("2.2.2.2", r.dstIp());
        assertEquals("0.5 ms", r.totalDelay());
    }

    @Test
    void handlesMissingDelayWithCustomWording() {
        List<String> logs = List.of(
            "FRAME\tFrameNo=10\tTimestamp=2025-01-01T12:00:00Z\tLen=64\n",
            "NETWORK\tSrcIP=1.1.1.1\tDstIP=2.2.2.2\tProtoName=UDP\n",
            "----\n"
        );

        TableLogProcessor processor = new TableLogProcessor();
        List<PacketRecord> records = processor.process(logs);

        assertEquals(1, records.size());
        assertEquals("10 Packet Delay", records.get(0).totalDelay(), "Should show custom 'X Packet Delay' text");
    }
}
