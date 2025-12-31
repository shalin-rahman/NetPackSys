import core.Config;
import core.PacketAnalyzerApp;
import javafx.application.Application;
import javafx.beans.property.SimpleStringProperty;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import model.PacketRecord;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import presenter.LogPresenter;
import processor.DelayLogProcessor;
import processor.DetailLogProcessor;
import processor.SummaryLogProcessor;
import service.FileLogFileService;

import java.awt.Desktop;
import java.io.File;
import java.util.List;
import java.util.Set;
import java.util.Collections;

public class PacketLogViewer extends Application {
    
    private TableView<PacketRecord> packetRecordTableView;
    private TextArea packetDetailsTextArea;
    private LogPresenter logPresenter;
    private Stage primaryStage;
    
    @Override
    public void start(Stage primaryStage) {
        this.primaryStage = primaryStage;
        
        logPresenter = new LogPresenter(
            new FileLogFileService(),
            new SummaryLogProcessor(),
            new DetailLogProcessor(),
            new DelayLogProcessor()
        );
        
        packetRecordTableView = createPacketTableView();
        packetDetailsTextArea = new TextArea();
        packetDetailsTextArea.setEditable(false);
        packetDetailsTextArea.setWrapText(true);
        packetDetailsTextArea.setPrefRowCount(15);
        
        Button newCaptureButton = new Button("New Capture");
        newCaptureButton.setStyle("-fx-background-color: #4CAF50; -fx-text-fill: white;");
        newCaptureButton.setOnAction(event -> displayCaptureConfigurationDialog());
        
        HBox topControlBar = new HBox(10);
        topControlBar.setPadding(new Insets(10));
        topControlBar.getChildren().addAll(newCaptureButton);
        
        SplitPane mainSplitPane = new SplitPane();
        mainSplitPane.setOrientation(javafx.geometry.Orientation.VERTICAL);
        
        VBox packetListSection = new VBox(5, new Label("Packet List (Select to view details):"), packetRecordTableView);
        packetListSection.setPadding(new Insets(10));
        
        VBox packetDetailsSection = new VBox(5, new Label("Packet Details:"), packetDetailsTextArea);
        packetDetailsSection.setPadding(new Insets(10));
        
        mainSplitPane.getItems().addAll(packetListSection, packetDetailsSection);
        mainSplitPane.setDividerPositions(0.6);
        
        BorderPane mainLayout = new BorderPane();
        mainLayout.setTop(topControlBar);
        mainLayout.setCenter(mainSplitPane);
        
        Scene mainScene = new Scene(mainLayout, 1000, 800);
        primaryStage.setTitle("NetPackSys - Packet Log Viewer");
        primaryStage.setScene(mainScene);
        primaryStage.show();
        
        loadLogFile("packet_analysis_log.txt");
    }
    
    private TableView<PacketRecord> createPacketTableView() {
        TableView<PacketRecord> table = new TableView<>();
        
        TableColumn<PacketRecord, String> frameNumberColumn = new TableColumn<>("No.");
        frameNumberColumn.setCellValueFactory(data -> new SimpleStringProperty(String.valueOf(data.getValue().frameNo())));
        frameNumberColumn.setPrefWidth(50);
        
        TableColumn<PacketRecord, String> timestampColumn = new TableColumn<>("Time");
        timestampColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().timestamp()));
        timestampColumn.setPrefWidth(200);
        
        TableColumn<PacketRecord, String> sourceIpColumn = new TableColumn<>("Source");
        sourceIpColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().srcIp()));
        sourceIpColumn.setPrefWidth(120);
        
        TableColumn<PacketRecord, String> destinationIpColumn = new TableColumn<>("Destination");
        destinationIpColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().dstIp()));
        destinationIpColumn.setPrefWidth(120);
        
        TableColumn<PacketRecord, String> protocolColumn = new TableColumn<>("Protocol");
        protocolColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().protocol()));
        protocolColumn.setPrefWidth(80);
        
        TableColumn<PacketRecord, String> lengthColumn = new TableColumn<>("Length");
        lengthColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().length()));
        lengthColumn.setPrefWidth(60);
        
        TableColumn<PacketRecord, String> informationColumn = new TableColumn<>("Info");
        informationColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().info()));
        informationColumn.setPrefWidth(250);
        
        TableColumn<PacketRecord, String> nodalDelayColumn = new TableColumn<>("Nodal Delay");
        nodalDelayColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().totalDelay()));
        nodalDelayColumn.setPrefWidth(100);
        
        table.getColumns().addAll(List.of(frameNumberColumn, timestampColumn, sourceIpColumn, destinationIpColumn, protocolColumn, lengthColumn, informationColumn, nodalDelayColumn));
        
        table.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) -> {
            if (newValue != null) {
                packetDetailsTextArea.setText(newValue.rawContent());
            } else {
                packetDetailsTextArea.clear();
            }
        });
        
        return table;
    }
 
    private void loadLogFile(String logFilePath) {
        LogPresenter.LogData logData = logPresenter.loadLog(logFilePath);
        
        if (logData.hasError()) {
            packetDetailsTextArea.setText("Error loading log: " + logData.errorMessage);
            packetRecordTableView.getItems().clear();
        } else {
            packetRecordTableView.getItems().setAll(logData.records);
            if (!logData.records.isEmpty()) {
                packetRecordTableView.getSelectionModel().selectFirst();
            }
        }
    }

    private void displayCaptureConfigurationDialog() {
        try {
            List<PcapNetworkInterface> availableDevices = Pcaps.findAllDevs();
            
            Dialog<Config> captureDialog = new Dialog<>();
            captureDialog.setTitle("New Packet Capture");
            captureDialog.setHeaderText("Packet Capture Configuration");

            ButtonType startButtonType = new ButtonType("Start", ButtonBar.ButtonData.OK_DONE);
            captureDialog.getDialogPane().getButtonTypes().addAll(startButtonType, ButtonType.CANCEL);

            GridPane dialogGridPane = new GridPane();
            dialogGridPane.setHgap(10);
            dialogGridPane.setVgap(10);
            dialogGridPane.setPadding(new Insets(20, 150, 10, 10));

            // Interface
            ComboBox<Object> networkInterfaceComboBox = new ComboBox<>();
            networkInterfaceComboBox.getItems().add("Simulation Mode");
            if (availableDevices != null) {
                networkInterfaceComboBox.getItems().addAll(availableDevices);
            }
            networkInterfaceComboBox.getSelectionModel().selectFirst();
            
            networkInterfaceComboBox.setCellFactory(param -> new ListCell<>() {
                @Override
                protected void updateItem(Object item, boolean empty) {
                    super.updateItem(item, empty);
                    if (empty || item == null) {
                        setText(null);
                    } else if (item instanceof PcapNetworkInterface networkInterface) {
                        String description = networkInterface.getDescription() != null ? networkInterface.getDescription() : networkInterface.getName();
                        setText(description + " [" + networkInterface.getName() + "]");
                    } else {
                        setText(item.toString());
                    }
                }
            });
            networkInterfaceComboBox.setButtonCell(networkInterfaceComboBox.getCellFactory().call(null));
            networkInterfaceComboBox.setPrefWidth(400);

            // Inputs
            TextField durationTextField = new TextField("10");
            TextField protocolTextField = new TextField("ALL");
            protocolTextField.setPromptText("TCP, UDP, HTTP... or ALL");
            TextField outputFileTextField = new TextField("packet_analysis_log.txt");

            dialogGridPane.add(new Label("Interface:"), 0, 0);
            dialogGridPane.add(networkInterfaceComboBox, 1, 0);
            dialogGridPane.add(new Label("Duration (sec):"), 0, 1);
            dialogGridPane.add(durationTextField, 1, 1);
            dialogGridPane.add(new Label("Protocols:"), 0, 2);
            dialogGridPane.add(protocolTextField, 1, 2);
            dialogGridPane.add(new Label("Output File:"), 0, 3);
            dialogGridPane.add(outputFileTextField, 1, 3);
            
            Label adminHint = new Label("⚠️ Administrator privileges required for live capture");
            adminHint.setStyle("-fx-text-fill: #b00020; -fx-font-size: 11px;");
            dialogGridPane.add(adminHint, 1, 4);

            captureDialog.getDialogPane().setContent(dialogGridPane);

            captureDialog.setResultConverter(dialogButton -> {
                if (dialogButton != startButtonType) {
                    return null;
                }

                Object selectedItem = networkInterfaceComboBox.getValue();
                String interfaceName;
                String networkDescription;
                
                if (selectedItem instanceof PcapNetworkInterface networkInterface) {
                    interfaceName = networkInterface.getName();
                    networkDescription = networkInterface.getDescription() != null ? networkInterface.getDescription() : networkInterface.getName();
                } else {
                    interfaceName = "sim";
                    networkDescription = "SIMULATED";
                }

                int captureDurationSeconds = 10;
                try {
                    String durationInputText = durationTextField.getText().trim();
                    if (!durationInputText.isEmpty()) captureDurationSeconds = Integer.parseInt(durationInputText);
                } catch (NumberFormatException ignored) {}
                
                String protocolInputText = protocolTextField.getText().trim();
                Set<String> protocolSet = Config.parseProtocols(protocolInputText);
                
                String outputFileText = outputFileTextField.getText().trim();
                if (outputFileText.isEmpty()) outputFileText = "packet_analysis_log.txt";

                return new Config(interfaceName, networkDescription, captureDurationSeconds, protocolSet, outputFileText);
            });

            captureDialog.showAndWait().ifPresent(this::executePacketCapture);

        } catch (PcapNativeException e) {
            showAlert(Alert.AlertType.ERROR, "Initialization Error", "Failed to list interfaces: " + e.getMessage());
        }
    }

    private void executePacketCapture(Config configuration) {
        Alert progressAlert = new Alert(Alert.AlertType.INFORMATION);
        progressAlert.setTitle("Capturing...");
        progressAlert.setHeaderText("Packet Capture in Progress");
        progressAlert.setContentText("Capturing on " + configuration.iface() + " for " + configuration.durationSec() + " seconds...");
        progressAlert.initModality(Modality.WINDOW_MODAL);
        progressAlert.initOwner(primaryStage);
        
        progressAlert.getDialogPane().lookupButton(ButtonType.OK).setDisable(true); 
        progressAlert.show();

        Task<Long> captureTask = new Task<>() {
            @Override
            protected Long call() throws Exception {
                return new PacketAnalyzerApp(configuration).run();
            }
        };

        captureTask.setOnSucceeded(workerStateEvent -> {
            progressAlert.setResult(ButtonType.OK);
            progressAlert.close();
            
            long capturedPacketCount = (long) workerStateEvent.getSource().getValue();
            
            // Auto reload table
            loadLogFile(configuration.outFile());

            // Show completion alert with option to View Log
            Alert completeAlert = new Alert(Alert.AlertType.INFORMATION);
            completeAlert.setTitle("Capture Complete");
            completeAlert.setHeaderText("Capture Finished Successfully");
            completeAlert.setContentText("Captured " + capturedPacketCount + " packets.\nTable updated.");
            
            ButtonType viewLogButtonType = new ButtonType("View Log File", ButtonBar.ButtonData.OTHER);
            completeAlert.getButtonTypes().add(viewLogButtonType);
            
            completeAlert.showAndWait().ifPresent(buttonType -> {
                if (buttonType == viewLogButtonType) {
                    openLogFileInEditor(configuration.outFile());
                }
            });
        });

        captureTask.setOnFailed(workerStateEvent -> {
            progressAlert.setResult(ButtonType.OK);
            progressAlert.close();
            Throwable exception = workerStateEvent.getSource().getException();
            showAlert(Alert.AlertType.ERROR, "Capture Failed", exception.getMessage());
        });

        new Thread(captureTask).start();
    }

    private void openLogFileInEditor(String filePath) {
        try {
            File logFile = new File(filePath);
            if (logFile.exists()) {
                // Try to use Desktop API
                if (Desktop.isDesktopSupported()) {
                    Desktop.getDesktop().open(logFile);
                } else {
                    // Fallback for systems where Desktop is not supported (unlikely on Windows)
                    new ProcessBuilder("notepad.exe", filePath).start();
                }
            } else {
                showAlert(Alert.AlertType.ERROR, "File Not Found", "The log file does not exist: " + filePath);
            }
        } catch (Exception e) {
            showAlert(Alert.AlertType.ERROR, "Open Error", "Failed to open log file: " + e.getMessage());
        }
    }

    private void showAlert(Alert.AlertType alertType, String title, String contentText) {
        Alert alert = new Alert(alertType);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(contentText);
        alert.showAndWait();
    }
    
    public static void main(String[] args) {
        launch(args);
    }
}
