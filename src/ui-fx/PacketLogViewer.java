package netpacksys.ui.fx;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class PacketLogViewer extends Application {
    
    private TextArea summaryText;
    private TextArea detailText;
    private TextArea delayText;
    private TextField logPathInput;
    
    @Override
    public void start(Stage primaryStage) {
        // Initialize text areas
        summaryText = new TextArea();
        summaryText.setEditable(false);
        summaryText.setWrapText(true);
        summaryText.setPrefRowCount(8);
        
        detailText = new TextArea();
        detailText.setEditable(false);
        detailText.setWrapText(true);
        detailText.setPrefRowCount(8);
        
        delayText = new TextArea();
        delayText.setEditable(false);
        delayText.setWrapText(true);
        delayText.setPrefRowCount(8);
        
        // Top bar with log path input
        logPathInput = new TextField("packet_analysis_log.txt");
        logPathInput.setPrefWidth(400);
        Button loadBtn = new Button("Load Log");
        loadBtn.setOnAction(e -> loadLogFile());
        
        HBox topBar = new HBox(10);
        topBar.setPadding(new Insets(10));
        topBar.getChildren().addAll(new Label("Log File:"), logPathInput, loadBtn);
        
        // Main content area
        VBox contentArea = new VBox(10);
        contentArea.setPadding(new Insets(10));
        
        VBox summarySection = new VBox(5);
        summarySection.getChildren().addAll(
            new Label("Summary (DELAY_SUMMARY lines):"),
            summaryText
        );
        
        VBox detailSection = new VBox(5);
        detailSection.getChildren().addAll(
            new Label("Packet Details:"),
            detailText
        );
        
        VBox delaySection = new VBox(5);
        delaySection.getChildren().addAll(
            new Label("Delay Information:"),
            delayText
        );
        
        contentArea.getChildren().addAll(summarySection, detailSection, delaySection);
        
        ScrollPane scrollPane = new ScrollPane(contentArea);
        scrollPane.setFitToWidth(true);
        
        BorderPane layout = new BorderPane();
        layout.setTop(topBar);
        layout.setCenter(scrollPane);
        
        Scene scene = new Scene(layout, 900, 700);
        primaryStage.setTitle("NetPackSys - Packet Log Viewer");
        primaryStage.setScene(scene);
        primaryStage.show();
        
        // Load default log on startup
        loadLogFile();
    }
    
    private void loadLogFile() {
        String logFilePath = logPathInput.getText().trim();
        Path path = Path.of(logFilePath);
        
        if (!Files.exists(path)) {
            summaryText.setText("Error: Log file not found at " + logFilePath);
            detailText.clear();
            delayText.clear();
            return;
        }
        
        try {
            List<String> allLines = Files.readAllLines(path);
            
            // Extract summary lines
            StringBuilder summary = new StringBuilder();
            for (String line : allLines) {
                if (line.startsWith("DELAY_SUMMARY")) {
                    summary.append(line).append("\n");
                }
            }
            summaryText.setText(summary.toString());
            
            // Extract packet details (everything except summary and separators)
            StringBuilder details = new StringBuilder();
            for (String line : allLines) {
                if (!line.startsWith("DELAY_SUMMARY") && !line.equals("----")) {
                    details.append(line).append("\n");
                }
            }
            detailText.setText(details.toString());
            
            // Extract delay-related lines
            StringBuilder delays = new StringBuilder();
            for (String line : allLines) {
                if (line.contains("Delay") || line.contains("delay") || line.contains("Bottleneck")) {
                    delays.append(line).append("\n");
                }
            }
            delayText.setText(delays.toString());
            
        } catch (IOException ex) {
            summaryText.setText("Error reading file: " + ex.getMessage());
            detailText.clear();
            delayText.clear();
        }
    }
    
    public static void main(String[] args) {
        launch(args);
    }
}
