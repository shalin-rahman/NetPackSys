package processor;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DetailLogProcessorTest {
    
    private final DetailLogProcessor processor = new DetailLogProcessor();
    
    @Test
    void process_mixedLines_excludesDelaySummaryAndSeparators() {
        List<String> input = Arrays.asList(
            "Packet 1 details",
            "DELAY_SUMMARY: Total delay",
            "----",
            "Packet 2 details",
            "More info"
        );
        
        List<String> result = processor.process(input);
        
        assertEquals(3, result.size());
        assertEquals("Packet 1 details", result.get(0));
        assertEquals("Packet 2 details", result.get(1));
        assertEquals("More info", result.get(2));
    }
    
    @Test
    void process_onlyExcludedLines_returnsEmptyList() {
        List<String> input = Arrays.asList(
            "DELAY_SUMMARY: Line 1",
            "----",
            "DELAY_SUMMARY: Line 2"
        );
        
        List<String> result = processor.process(input);
        
        assertTrue(result.isEmpty());
    }
    
    @Test
    void process_emptyInput_returnsEmptyList() {
        List<String> result = processor.process(Collections.emptyList());
        
        assertTrue(result.isEmpty());
    }
}
