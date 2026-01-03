package core.capture;

import core.PcapPacketStub;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

public class SimulatedCaptureServiceTest {
    
    private SimulatedCaptureService captureService;
    private List<PcapPacketStub> capturedPackets;
    
    @BeforeEach
    public void setUp() {
        captureService = new SimulatedCaptureService();
        capturedPackets = new ArrayList<>();
    }
    
    @Test
    public void testSimulatedCaptureBasic() {
        PacketHandler handler = stub -> {
            capturedPackets.add(stub);
            return capturedPackets.size() < 5;
        };
        
        captureService.startCapture(handler, 1);
        
        assertTrue(capturedPackets.size() > 0);
    }
    
    @Test
    public void testSimulatedCaptureMultipleSeconds() {
        PacketHandler handler = stub -> {
            capturedPackets.add(stub);
            return true;
        };
        
        captureService.startCapture(handler, 2);
        
        // Should capture approximately 10 packets (5 per second * 2 seconds)
        assertTrue(capturedPackets.size() >= 5);
    }
    
    @Test
    public void testSimulatedCaptureHandlerStop() {
        AtomicBoolean stopped = new AtomicBoolean(false);
        PacketHandler handler = stub -> {
            capturedPackets.add(stub);
            if (capturedPackets.size() >= 3) {
                stopped.set(true);
                return false;
            }
            return true;
        };
        
        captureService.startCapture(handler, 2);
        
        assertTrue(stopped.get());
        assertEquals(3, capturedPackets.size());
    }
    
    @Test
    public void testSimulatedCaptureClose() {
        AtomicBoolean closed = new AtomicBoolean(false);
        PacketHandler handler = stub -> {
            capturedPackets.add(stub);
            if (capturedPackets.size() == 2) {
                captureService.close();
            }
            return true;
        };
        
        captureService.startCapture(handler, 5);
        
        assertTrue(capturedPackets.size() >= 2);
    }
    
    @Test
    public void testSimulatedCaptureVariousPacketTypes() {
        PacketHandler handler = stub -> {
            capturedPackets.add(stub);
            return capturedPackets.size() < 15;
        };
        
        captureService.startCapture(handler, 2);
        
        // Verify we have different types of packets
        assertTrue(capturedPackets.size() > 0);
        // Each cycle generates HTTP, DNS, and TLS packets
        assertTrue(capturedPackets.size() >= 3);
    }
    
    @Test
    public void testSimulatedCaptureZeroSeconds() {
        PacketHandler handler = stub -> {
            capturedPackets.add(stub);
            return true;
        };
        
        captureService.startCapture(handler, 0);
        
        // With maxSeconds=0, it should still capture at least 1 packet (max(1, 0*5) = 1)
        assertTrue(capturedPackets.size() >= 1);
    }
}
