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
import java.util.stream.Collectors;

/**
 * Simple JavaFX viewer for console-generated log output.
 * This module is independent from the core CLI module; point it at the log file produced by PacketAnalyzer.
 */
public class PacketFxApp extends Application {

    private TextArea summaryArea;
    private TextArea detailArea;
    private TextArea delayArea;
    private TextField logPathField;

    @Override
    public void start(Stage stage) {
        summaryArea = buildReadOnlyArea("Summary");
        detailArea = buildReadOnlyArea("Details");
        delayArea = buildReadOnlyArea("Delay Info");
        logPathField = new TextField("packet_analysis_log.txt");

        Button loadButton = new Button("Load Log");
        loadButton.setOnAction(e -> refreshFromLog());

        HBox top = new HBox(10, new Label("Log path:"), logPathField, loadButton);
        top.setPadding(new Insets(10));

        VBox center = new VBox(10,
                wrapWithLabel("Summary (lines starting with DELAY_SUMMARY)", summaryArea),
                wrapWithLabel("Packet Details", detailArea),
                wrapWithLabel("Delay Details (per layer)", delayArea)
        );
        center.setPadding(new Insets(10));

        BorderPane root = new BorderPane();
        root.setTop(top);
        root.setCenter(new ScrollPane(center));

        stage.setTitle("NetPackSys Log Viewer");
        stage.setScene(new Scene(root, 900, 700));
        stage.show();

        refreshFromLog();
    }

    private TextArea buildReadOnlyArea(String prompt) {
        TextArea area = new TextArea();
        area.setEditable(false);
        area.setPromptText(prompt);
        area.setWrapText(true);
        area.setPrefRowCount(8);
        return area;
    }

    private VBox wrapWithLabel(String label, Control control) {
        VBox box = new VBox(4, new Label(label), control);
        return box;
    }

    private void refreshFromLog() {
        Path logPath = Path.of(logPathField.getText().trim());
        if (!Files.exists(logPath)) {
            summaryArea.setText("Log file not found: " + logPath);
            detailArea.clear();
            delayArea.clear();
            return;
        }
        try {
            List<String> lines = Files.readAllLines(logPath);
            summaryArea.setText(lines.stream()
                    .filter(l -> l.startsWith("DELAY_SUMMARY"))
                    .collect(Collectors.joining("\n")));

            detailArea.setText(lines.stream()
                    .filter(l -> !l.startsWith("DELAY_SUMMARY") && !l.equals("----"))
                    .collect(Collectors.joining("\n")));

            delayArea.setText(lines.stream()
                    .filter(l -> l.contains("Delay") || l.contains("delay") || l.contains("Bottleneck"))
                    .collect(Collectors.joining("\n")));
        } catch (IOException e) {
            summaryArea.setText("Failed to load log: " + e.getMessage());
            detailArea.clear();
            delayArea.clear();
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}

