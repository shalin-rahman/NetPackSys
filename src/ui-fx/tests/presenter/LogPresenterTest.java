package presenter;

import processor.LogProcessor;
import service.LogFileService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class LogPresenterTest {
    
    @Mock
    private LogFileService mockFileService;
    
    @Mock
    private LogProcessor mockSummaryProcessor;
    
    @Mock
    private LogProcessor mockDetailProcessor;
    
    @Mock
    private LogProcessor mockDelayProcessor;
    
    private LogPresenter presenter;
    
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        presenter = new LogPresenter(
            mockFileService,
            mockSummaryProcessor,
            mockDetailProcessor,
            mockDelayProcessor
        );
    }
    
    @Test
    void loadLog_validFile_returnsFilteredData() throws IOException {
        List<String> allLines = Arrays.asList("Line 1", "Line 2", "Line 3");
        List<String> summaryLines = Collections.singletonList("Summary");
        List<String> detailLines = Collections.singletonList("Detail");
        List<String> delayLines = Collections.singletonList("Delay");
        
        when(mockFileService.readLogFile(any(Path.class))).thenReturn(allLines);
        when(mockSummaryProcessor.process(allLines)).thenReturn(summaryLines);
        when(mockDetailProcessor.process(allLines)).thenReturn(detailLines);
        when(mockDelayProcessor.process(allLines)).thenReturn(delayLines);
        
        LogPresenter.LogData result = presenter.loadLog("test.log");
        
        assertFalse(result.hasError());
        assertEquals(summaryLines, result.summaryLines);
        assertEquals(detailLines, result.detailLines);
        assertEquals(delayLines, result.delayLines);
        
        verify(mockFileService).readLogFile(any(Path.class));
        verify(mockSummaryProcessor).process(allLines);
        verify(mockDetailProcessor).process(allLines);
        verify(mockDelayProcessor).process(allLines);
    }
    
    @Test
    void loadLog_fileNotFound_returnsError() throws IOException {
        when(mockFileService.readLogFile(any(Path.class)))
            .thenThrow(new IOException("File not found"));
        
        LogPresenter.LogData result = presenter.loadLog("nonexistent.log");
        
        assertTrue(result.hasError());
        assertNotNull(result.errorMessage);
        assertTrue(result.errorMessage.contains("File not found"));
    }
    
    @Test
    void loadLog_ioException_returnsError() throws IOException {
        when(mockFileService.readLogFile(any(Path.class)))
            .thenThrow(new IOException("Read error"));
        
        LogPresenter.LogData result = presenter.loadLog("error.log");
        
        assertTrue(result.hasError());
        assertNotNull(result.errorMessage);
    }
}
