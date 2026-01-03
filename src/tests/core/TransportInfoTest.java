package core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class TransportInfoTest {
    
    private TransportInfo transportInfo;
    
    @BeforeEach
    public void setUp() {
        transportInfo = new TransportInfo(12345, 80, "TCP", 512, "SYN,ACK");
    }
    
    @Test
    public void testTransportInfoCreation() {
        assertEquals(12345, transportInfo.srcPort());
        assertEquals(80, transportInfo.dstPort());
        assertEquals("TCP", transportInfo.proto());
        assertEquals(512, transportInfo.payloadLen());
        assertEquals("SYN,ACK", transportInfo.flags());
    }
    
    @Test
    public void testTransportInfoUDP() {
        TransportInfo udp = new TransportInfo(50000, 53, "UDP", 256, "-");
        
        assertEquals(50000, udp.srcPort());
        assertEquals(53, udp.dstPort());
        assertEquals("UDP", udp.proto());
        assertEquals(256, udp.payloadLen());
        assertEquals("-", udp.flags());
    }
    
    @Test
    public void testTransportInfoHighPorts() {
        TransportInfo high = new TransportInfo(65535, 65535, "TCP", 1024, "ACK");
        
        assertEquals(65535, high.srcPort());
        assertEquals(65535, high.dstPort());
    }
    
    @Test
    public void testTransportInfoLowPorts() {
        TransportInfo low = new TransportInfo(1, 1, "TCP", 64, "SYN");
        
        assertEquals(1, low.srcPort());
        assertEquals(1, low.dstPort());
    }
}
