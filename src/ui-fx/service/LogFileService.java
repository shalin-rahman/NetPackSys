package service;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

public interface LogFileService {
    List<String> readLogFile(Path filePath) throws IOException;
}
