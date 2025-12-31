package presenter;

import processor.LogProcessor;
import service.LogFileService;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

public class LogPresenter {
    
    private final LogFileService fileService;
    private final LogProcessor summaryProcessor;
    private final LogProcessor detailProcessor;
    private final LogProcessor delayProcessor;
    
    public LogPresenter(LogFileService fileService, 
                       LogProcessor summaryProcessor,
                       LogProcessor detailProcessor,
                       LogProcessor delayProcessor) {
        this.fileService = fileService;
        this.summaryProcessor = summaryProcessor;
        this.detailProcessor = detailProcessor;
        this.delayProcessor = delayProcessor;
    }
    
    public LogData loadLog(String filePath) {
        try {
            List<String> allLines = fileService.readLogFile(Path.of(filePath));
            
            List<String> summaryLines = summaryProcessor.process(allLines);
            List<String> detailLines = detailProcessor.process(allLines);
            List<String> delayLines = delayProcessor.process(allLines);
            
            return new LogData(summaryLines, detailLines, delayLines);
            
        } catch (IOException e) {
            return LogData.error("Error reading file: " + e.getMessage());
        } catch (Exception e) {
            return LogData.error("Unexpected error: " + e.getMessage());
        }
    }
    
    public static class LogData {
        public final List<String> summaryLines;
        public final List<String> detailLines;
        public final List<String> delayLines;
        public final String errorMessage;
        
        public LogData(List<String> summary, List<String> detail, List<String> delay) {
            this.summaryLines = summary;
            this.detailLines = detail;
            this.delayLines = delay;
            this.errorMessage = null;
        }
        
        private LogData(String error) {
            this.summaryLines = Collections.emptyList();
            this.detailLines = Collections.emptyList();
            this.delayLines = Collections.emptyList();
            this.errorMessage = error;
        }
        
        public static LogData error(String msg) {
            return new LogData(msg);
        }
        
        public boolean hasError() {
            return errorMessage != null;
        }
    }
}
