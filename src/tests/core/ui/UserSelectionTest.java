package core.ui;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.junit.jupiter.api.Assertions.*;

public class UserSelectionTest {
    
    private UserSelection userSelection;
    
    @BeforeEach
    public void setUp() {
        userSelection = new UserSelection("eth0", 10, "HTTP,DNS");
    }
    
    @Test
    public void testUserSelectionCreation() {
        assertEquals("eth0", userSelection.interfaceSelection());
        assertEquals(10, userSelection.durationSec());
        assertEquals("HTTP,DNS", userSelection.protocolsCsv());
    }
    
    @Test
    public void testUserSelectionSimulated() {
        UserSelection sim = new UserSelection("sim", 5, "ALL");
        
        assertEquals("sim", sim.interfaceSelection());
        assertEquals(5, sim.durationSec());
        assertEquals("ALL", sim.protocolsCsv());
    }
    
    @Test
    public void testUserSelectionMultipleProtocols() {
        UserSelection multi = new UserSelection("wlan0", 20, "HTTP,HTTPS,DNS,TLS");
        
        assertEquals("wlan0", multi.interfaceSelection());
        assertEquals(20, multi.durationSec());
        assertTrue(multi.protocolsCsv().contains("HTTP"));
        assertTrue(multi.protocolsCsv().contains("DNS"));
    }
    
    @Test
    public void testUserSelectionZeroDuration() {
        UserSelection zero = new UserSelection("eth0", 0, "ALL");
        
        assertEquals(0, zero.durationSec());
    }
    
    @Test
    public void testUserSelectionLongDuration() {
        UserSelection long_duration = new UserSelection("eth1", 3600, "ALL");
        
        assertEquals(3600, long_duration.durationSec());
    }
}
