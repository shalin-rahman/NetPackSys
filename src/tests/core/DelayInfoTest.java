package core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class DelayInfoTest {
    
    @Test
    public void testDelayInfoCreation() {
        DelayInfo info = new DelayInfo(1.5, 0.5, 2.0, 1.0, "calculated");
        
        assertEquals(1.5, info.processingDelay());
        assertEquals(0.5, info.transmissionDelay());
        assertEquals(2.0, info.propagationDelay());
        assertEquals(1.0, info.queuingDelay());
        assertEquals("calculated", info.calculation());
    }
    
    @Test
    public void testTotalDelay() {
        DelayInfo info = new DelayInfo(1.5, 0.5, 2.0, 1.0, "test");
        assertEquals(5.0, info.totalDelay(), 0.001);
    }
    
    @Test
    public void testTotalDelayZero() {
        DelayInfo info = new DelayInfo(0.0, 0.0, 0.0, 0.0, "zero");
        assertEquals(0.0, info.totalDelay());
    }
    
    @Test
    public void testTotalDelayPartial() {
        DelayInfo info = new DelayInfo(1.0, 0.0, 0.0, 0.0, "processing");
        assertEquals(1.0, info.totalDelay());
    }
    
    @Test
    public void testTotalDelayAll() {
        DelayInfo info = new DelayInfo(2.5, 1.2, 3.1, 0.8, "all");
        assertEquals(7.6, info.totalDelay(), 0.001);
    }
}
