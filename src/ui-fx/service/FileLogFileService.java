package service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class FileLogFileService implements LogFileService {
    
    @Override
    public List<String> readLogFile(Path filePath) throws IOException {
        if (!Files.exists(filePath)) {
            throw new IOException("File not found: " + filePath);
        }
        return Files.readAllLines(filePath);
    }
}
