import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import presenter.LogPresenter;
import processor.DelayLogProcessor;
import processor.DetailLogProcessor;
import processor.SummaryLogProcessor;
import service.FileLogFileService;

public class PacketLogViewer extends Application {
    
    private TextArea summaryText;
    private TextArea detailText;
    private TextArea delayText;
    private TextField logPathInput;
    private LogPresenter presenter;
    
    @Override
    public void start(Stage primaryStage) {
        // Initialize presenter with dependencies
        presenter = new LogPresenter(
            new FileLogFileService(),
            new SummaryLogProcessor(),
            new DetailLogProcessor(),
            new DelayLogProcessor()
        );
        
        // Build UI
        summaryText = createTextArea();
        detailText = createTextArea();
        delayText = createTextArea();
        
        logPathInput = new TextField("packet_analysis_log.txt");
        logPathInput.setPrefWidth(400);
        
        Button loadBtn = new Button("Load Log");
        loadBtn.setOnAction(e -> handleLoadLog());
        
        HBox topBar = new HBox(10);
        topBar.setPadding(new Insets(10));
        topBar.getChildren().addAll(new Label("Log File:"), logPathInput, loadBtn);
        
        VBox contentArea = new VBox(10);
        contentArea.setPadding(new Insets(10));
        
        VBox summarySection = createSection("Summary (DELAY_SUMMARY lines):", summaryText);
        VBox detailSection = createSection("Packet Details:", detailText);
        VBox delaySection = createSection("Delay Information:", delayText);
        
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
        
        handleLoadLog();
    }
    
    private TextArea createTextArea() {
        TextArea area = new TextArea();
        area.setEditable(false);
        area.setWrapText(true);
        area.setPrefRowCount(8);
        return area;
    }
    
    private VBox createSection(String title, TextArea content) {
        VBox section = new VBox(5);
        section.getChildren().addAll(new Label(title), content);
        return section;
    }
    
    private void handleLoadLog() {
        String filePath = logPathInput.getText().trim();
        LogPresenter.LogData data = presenter.loadLog(filePath);
        
        if (data.hasError()) {
            summaryText.setText("Error: " + data.errorMessage);
            detailText.clear();
            delayText.clear();
        } else {
            summaryText.setText(String.join("\n", data.summaryLines));
            detailText.setText(String.join("\n", data.detailLines));
            delayText.setText(String.join("\n", data.delayLines));
        }
    }
    
    public static void main(String[] args) {
        launch(args);
    }
}
