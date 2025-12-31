package processor;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SummaryLogProcessorTest {
    
    private final SummaryLogProcessor processor = new SummaryLogProcessor();
    
    @Test
    void process_linesWithDelaySummary_returnsOnlyDelaySummaryLines() {
        List<String> input = Arrays.asList(
            "DELAY_SUMMARY: Total delay 100ms",
            "Some other line",
            "DELAY_SUMMARY: Network delay 50ms",
            "Another line"
        );
        
        List<String> result = processor.process(input);
        
        assertEquals(2, result.size());
        assertEquals("DELAY_SUMMARY: Total delay 100ms", result.get(0));
        assertEquals("DELAY_SUMMARY: Network delay 50ms", result.get(1));
    }
    
    @Test
    void process_noDelaySummaryLines_returnsEmptyList() {
        List<String> input = Arrays.asList("Line 1", "Line 2", "Line 3");
        
        List<String> result = processor.process(input);
        
        assertTrue(result.isEmpty());
    }
    
    @Test
    void process_emptyInput_returnsEmptyList() {
        List<String> result = processor.process(Collections.emptyList());
        
        assertTrue(result.isEmpty());
    }
    
    @Test
    void process_allDelaySummaryLines_returnsAllLines() {
        List<String> input = Arrays.asList(
            "DELAY_SUMMARY: Line 1",
            "DELAY_SUMMARY: Line 2",
            "DELAY_SUMMARY: Line 3"
        );
        
        List<String> result = processor.process(input);
        
        assertEquals(3, result.size());
        assertEquals(input, result);
    }
}
