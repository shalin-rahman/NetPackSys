package core.formatter;

import core.PacketContext;
import core.PcapPacketStub;
import core.util.SyntheticPacketFactory;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TabRowPacketFormatterTest {

    @Test
    void formatsPacketWithMultipleLayers() {
        var stub = new PcapPacketStub(1, new byte[0], Instant.now(), 0, 0);
        var ctx = new PacketContext(1, stub);

        Map<String, String> layer1 = new LinkedHashMap<>();
        layer1.put("Field1", "Val1");
        ctx.addLayer("LAYER1", layer1, null);

        Map<String, String> delay = new LinkedHashMap<>();
        delay.put("TotalNodalDelay", "0.5 ms");
        ctx.layers().put("DELAY_SUMMARY", delay);

        var formatter = new TabRowPacketFormatter();
        List<String> rows = formatter.format(ctx);

        assertFalse(rows.isEmpty());
        assertTrue(rows.stream().anyMatch(r -> r.startsWith("LAYER1")), "Should contain LAYER1 row");
        assertTrue(rows.stream().anyMatch(r -> r.startsWith("DELAY_SUMMARY")), "Should contain DELAY_SUMMARY row");
        assertTrue(rows.contains("----"), "Should contain block separator");
    }
}
