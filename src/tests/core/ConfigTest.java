package core;

import org.junit.jupiter.api.Test;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class ConfigTest {
    
    @Test
    public void testConfigCreation() {
        Set<String> protocols = Set.of("HTTP", "DNS");
        Config config = new Config("eth0", "SIMULATED", 10, protocols, "output.txt");
        
        assertEquals("eth0", config.iface());
        assertEquals("SIMULATED", config.usedNetwork());
        assertEquals(10, config.durationSec());
        assertEquals("output.txt", config.outFile());
        assertTrue(config.protocols().contains("HTTP"));
    }
    
    @Test
    public void testParseProtocolsEmpty() {
        Set<String> result = Config.parseProtocols("");
        assertEquals(1, result.size());
        assertTrue(result.contains("ALL"));
    }
    
    @Test
    public void testParseProtocolsNull() {
        Set<String> result = Config.parseProtocols(null);
        assertEquals(1, result.size());
        assertTrue(result.contains("ALL"));
    }
    
    @Test
    public void testParseProtocolsALL() {
        Set<String> result = Config.parseProtocols("ALL");
        assertEquals(1, result.size());
        assertTrue(result.contains("ALL"));
    }
    
    @Test
    public void testParseProtocolsCSV() {
        Set<String> result = Config.parseProtocols("HTTP,DNS,TLS");
        assertEquals(3, result.size());
        assertTrue(result.contains("HTTP"));
        assertTrue(result.contains("DNS"));
        assertTrue(result.contains("TLS"));
    }
    
    @Test
    public void testParseProtocolsWhitespace() {
        Set<String> result = Config.parseProtocols("  HTTP  , DNS , HTTPS  ");
        assertEquals(3, result.size());
        assertTrue(result.contains("HTTP"));
        assertTrue(result.contains("DNS"));
        assertTrue(result.contains("HTTPS"));
    }
    
    @Test
    public void testConfigTLSNormalization() {
        Set<String> protocols = Set.of("HTTP", "TLS", "DNS");
        Config config = new Config("eth0", "SIMULATED", 10, protocols, "output.txt");
        
        assertTrue(config.protocols().contains("HTTPS"));
        assertFalse(config.protocols().contains("TLS"));
    }
}
