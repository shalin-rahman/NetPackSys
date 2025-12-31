package service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class FileLogFileServiceTest {
    
    private final FileLogFileService service = new FileLogFileService();
    
    @Test
    void readLogFile_validFile_returnsLines(@TempDir Path tempDir) throws IOException {
        Path testFile = tempDir.resolve("test.log");
        List<String> expectedLines = Arrays.asList("Line 1", "Line 2", "Line 3");
        Files.write(testFile, expectedLines);
        
        List<String> actualLines = service.readLogFile(testFile);
        
        assertEquals(expectedLines, actualLines);
    }
    
    @Test
    void readLogFile_emptyFile_returnsEmptyList(@TempDir Path tempDir) throws IOException {
        Path testFile = tempDir.resolve("empty.log");
        Files.createFile(testFile);
        
        List<String> lines = service.readLogFile(testFile);
        
        assertTrue(lines.isEmpty());
    }
    
    @Test
    void readLogFile_fileNotFound_throwsIOException() {
        Path nonExistentFile = Path.of("nonexistent.log");
        
        IOException exception = assertThrows(IOException.class, () -> {
            service.readLogFile(nonExistentFile);
        });
        
        assertTrue(exception.getMessage().contains("File not found"));
    }
    
    @Test
    void readLogFile_largeFile_readsAllLines(@TempDir Path tempDir) throws IOException {
        Path testFile = tempDir.resolve("large.log");
        StringBuilder content = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            content.append("Line ").append(i).append("\n");
        }
        Files.writeString(testFile, content.toString());
        
        List<String> lines = service.readLogFile(testFile);
        
        assertEquals(1000, lines.size());
        assertEquals("Line 0", lines.get(0));
        assertEquals("Line 999", lines.get(999));
    }
}
