package presenter;

import processor.LogProcessor;
import service.LogFileService;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

public class LogPresenter {
    
    private final LogFileService fileService;
    private final LogProcessor<String> summaryProcessor;
    private final LogProcessor<String> detailProcessor;
    private final LogProcessor<String> delayProcessor;
    private final LogProcessor<model.PacketRecord> tableProcessor;
    
    public LogPresenter(LogFileService fileService, 
                       LogProcessor<String> summaryProcessor,
                       LogProcessor<String> detailProcessor,
                       LogProcessor<String> delayProcessor) {
        this.fileService = fileService;
        this.summaryProcessor = summaryProcessor;
        this.detailProcessor = detailProcessor;
        this.delayProcessor = delayProcessor;
        this.tableProcessor = new processor.TableLogProcessor();
    }
    
    public LogData loadLog(String filePath) {
        try {
            List<String> allLines = fileService.readLogFile(Path.of(filePath));
            
            List<String> summaryLines = summaryProcessor.process(allLines);
            List<String> detailLines = detailProcessor.process(allLines);
            List<String> delayLines = delayProcessor.process(allLines);
            List<model.PacketRecord> records = tableProcessor.process(allLines);
            
            return new LogData(summaryLines, detailLines, delayLines, records);
            
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
        public final List<model.PacketRecord> records;
        public final String errorMessage;
        
        public LogData(List<String> summary, List<String> detail, List<String> delay, List<model.PacketRecord> records) {
            this.summaryLines = summary;
            this.detailLines = detail;
            this.delayLines = delay;
            this.records = records;
            this.errorMessage = null;
        }
        
        private LogData(String error) {
            this.summaryLines = Collections.emptyList();
            this.detailLines = Collections.emptyList();
            this.delayLines = Collections.emptyList();
            this.records = Collections.emptyList();
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
