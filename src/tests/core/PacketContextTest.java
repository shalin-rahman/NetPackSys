package core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class PacketContextTest {
    
    private PacketContext context;
    private PcapPacketStub stub;
    
    @BeforeEach
    public void setUp() {
        stub = new PcapPacketStub(1, new byte[]{1, 2, 3, 4}, Instant.now(), 4, 4);
        context = new PacketContext(1, stub);
    }
    
    @Test
    public void testPacketContextCreation() {
        assertEquals(1, context.frameNo());
        assertNotNull(context.stub());
        assertNotNull(context.layers());
        assertNull(context.transport());
        assertNull(context.app());
    }
    
    @Test
    public void testPayload() {
        byte[] payload = context.payload();
        assertNotNull(payload);
        assertEquals(4, payload.length);
    }
    
    @Test
    public void testAddLayer() {
        Map<String, String> linkData = new HashMap<>();
        linkData.put("SrcMAC", "00:11:22:33:44:55");
        linkData.put("DstMAC", "AA:BB:CC:DD:EE:FF");
        
        byte[] newPayload = new byte[]{5, 6, 7};
        context.addLayer("LINK", linkData, newPayload);
        
        assertTrue(context.layers().containsKey("LINK"));
        assertEquals(linkData, context.layers().get("LINK"));
        assertEquals(3, context.payload().length);
    }
    
    @Test
    public void testAddTransportLayer() {
        Map<String, String> transportData = new HashMap<>();
        transportData.put("SrcPort", "12345");
        transportData.put("DstPort", "80");
        transportData.put("Proto", "TCP");
        transportData.put("PayloadLen", "256");
        transportData.put("Flags", "SYN,ACK");
        
        context.addLayer("TRANSPORT", transportData, new byte[]{});
        
        TransportInfo transport = context.transport();
        assertNotNull(transport);
        assertEquals(12345, transport.srcPort());
        assertEquals(80, transport.dstPort());
        assertEquals("TCP", transport.proto());
    }
    
    @Test
    public void testSetApp() {
        Map<String, String> appData = new HashMap<>();
        appData.put("Method", "GET");
        appData.put("Path", "/index.html");
        
        context.setApp(appData);
        
        assertEquals(appData, context.app());
        assertEquals("GET", context.app().get("Method"));
    }
    
    @Test
    public void testAddDelayInfo() {
        DelayInfo delay = new DelayInfo(1.0, 0.5, 2.0, 0.5, "link");
        context.addDelayInfo("LINK", delay);
        
        assertTrue(context.delayInfo().containsKey("LINK"));
        assertEquals(delay, context.delayInfo().get("LINK"));
    }
    
    @Test
    public void testGetTotalNodalDelay() {
        context.addDelayInfo("LINK", new DelayInfo(1.0, 0.0, 0.0, 0.0, "link"));
        context.addDelayInfo("NETWORK", new DelayInfo(2.0, 0.0, 0.0, 0.0, "network"));
        context.addDelayInfo("TRANSPORT", new DelayInfo(1.5, 0.0, 0.0, 0.0, "transport"));
        
        assertEquals(4.5, context.getTotalNodalDelay(), 0.001);
    }
    
    @Test
    public void testGetTotalProcessingDelay() {
        context.addDelayInfo("LINK", new DelayInfo(1.0, 0.0, 0.0, 0.0, "link"));
        context.addDelayInfo("NETWORK", new DelayInfo(2.0, 0.0, 0.0, 0.0, "network"));
        
        assertEquals(3.0, context.getTotalProcessingDelay(), 0.001);
    }
    
    @Test
    public void testGetTotalTransmissionDelay() {
        context.addDelayInfo("LINK", new DelayInfo(0.0, 1.5, 0.0, 0.0, "link"));
        context.addDelayInfo("NETWORK", new DelayInfo(0.0, 0.5, 0.0, 0.0, "network"));
        
        assertEquals(2.0, context.getTotalTransmissionDelay(), 0.001);
    }
    
    @Test
    public void testGetTotalPropagationDelay() {
        context.addDelayInfo("NETWORK", new DelayInfo(0.0, 0.0, 2.5, 0.0, "network"));
        
        assertEquals(2.5, context.getTotalPropagationDelay(), 0.001);
    }
    
    @Test
    public void testGetTotalQueuingDelay() {
        context.addDelayInfo("LINK", new DelayInfo(0.0, 0.0, 0.0, 0.5, "link"));
        context.addDelayInfo("NETWORK", new DelayInfo(0.0, 0.0, 0.0, 1.0, "network"));
        context.addDelayInfo("TRANSPORT", new DelayInfo(0.0, 0.0, 0.0, 0.2, "transport"));
        
        assertEquals(1.7, context.getTotalQueuingDelay(), 0.001);
    }
    
    @Test
    public void testMultipleLayers() {
        Map<String, String> linkData = new HashMap<>();
        linkData.put("SrcMAC", "00:11:22:33:44:55");
        
        Map<String, String> networkData = new HashMap<>();
        networkData.put("SrcIP", "192.168.1.1");
        
        Map<String, String> transportData = new HashMap<>();
        transportData.put("SrcPort", "80");
        transportData.put("DstPort", "12345");
        transportData.put("Proto", "TCP");
        transportData.put("PayloadLen", "256");
        transportData.put("Flags", "ACK");
        
        context.addLayer("LINK", linkData, new byte[]{});
        context.addLayer("NETWORK", networkData, new byte[]{});
        context.addLayer("TRANSPORT", transportData, new byte[]{});
        
        assertEquals(3, context.layers().size());
        assertNotNull(context.transport());
    }
}
