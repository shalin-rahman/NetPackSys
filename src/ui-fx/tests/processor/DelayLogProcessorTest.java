package processor;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DelayLogProcessorTest {
    
    private final DelayLogProcessor processor = new DelayLogProcessor();
    
    @Test
    void process_linesWithDelay_returnsDelayLines() {
        List<String> input = Arrays.asList(
            "Network delay: 50ms",
            "Normal packet info",
            "Processing delay detected",
            "Another line",
            "Bottleneck delay at layer 3"
        );
        
        List<String> result = processor.process(input);
        
        assertEquals(3, result.size());
        assertTrue(result.contains("Network delay: 50ms"));
        assertTrue(result.contains("Processing delay detected"));
        assertTrue(result.contains("Bottleneck delay at layer 3"));
    }
    
    @Test
    void process_caseInsensitive_matchesDelayInAnyCase() {
        List<String> input = Arrays.asList(
            "DELAY in processing",
            "delay in network",
            "DeLaY in transport"
        );
        
        List<String> result = processor.process(input);
        
        assertEquals(3, result.size());
    }
    
    @Test
    void process_noDelayLines_returnsEmptyList() {
        List<String> input = Arrays.asList("Line 1", "Line 2", "Line 3");
        
        List<String> result = processor.process(input);
        
        assertTrue(result.isEmpty());
    }
    
    @Test
    void process_emptyInput_returnsEmptyList() {
        List<String> result = processor.process(Collections.emptyList());
        
        assertTrue(result.isEmpty());
    }
}
