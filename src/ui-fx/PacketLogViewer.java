import core.Config;
import core.PacketAnalyzerApp;
import javafx.application.Application;
import javafx.beans.property.SimpleStringProperty;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import model.PacketRecord;
import org.pcap4j.core.*;
import presenter.LogPresenter;
import processor.DelayLogProcessor;
import processor.DetailLogProcessor;
import processor.SummaryLogProcessor;
import service.FileLogFileService;

import java.awt.Desktop;
import java.io.File;
import java.io.FileInputStream;
import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class PacketLogViewer extends Application {
    
    private TableView<PacketRecord> packetRecordTableView;
    private TextArea packetDetailsTextArea;
    private LogPresenter logPresenter;
    private Stage primaryStage;
    private final Map<String, Long> interfaceTrafficMap = new ConcurrentHashMap<>();
    
    @Override
    public void start(Stage primaryStage) {
        this.primaryStage = primaryStage;
        
        try {
            File iconFile = new File("../../nps_icon.png");
            if (!iconFile.exists()) {
                iconFile = new File("nps_icon.png");
            }
            if (iconFile.exists()) {
                primaryStage.getIcons().add(new Image(new FileInputStream(iconFile)));
            }
        } catch (Exception e) {
            System.err.println("Could not load application icon: " + e.getMessage());
        }

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
        newCaptureButton.setStyle("-fx-background-color: #4CAF50; -fx-text-fill: white; -fx-font-weight: bold;");
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
        primaryStage.setTitle("NetPackSys - Network Packet Capture and Delay Analysis System");
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

    private boolean isInterfaceActive(PcapNetworkInterface networkInterface) {
        try {
            if (networkInterface.isUp()) {
                return true;
            }
        } catch (Exception ignored) {}

        List<PcapAddress> addresses = networkInterface.getAddresses();
        if (addresses != null && !addresses.isEmpty()) {
            for (PcapAddress address : addresses) {
                InetAddress inetAddr = address.getAddress();
                if (inetAddr != null && !inetAddr.isLoopbackAddress()) {
                    return true;
                }
            }
        }
        return false;
    }

    private void auditTrafficForActiveInterfaces(List<PcapNetworkInterface> interfaces) {
        interfaceTrafficMap.clear();
        if (interfaces.isEmpty()) return;

        CountDownLatch latch = new CountDownLatch(interfaces.size());
        for (PcapNetworkInterface dev : interfaces) {
            new Thread(() -> {
                try (PcapHandle handle = dev.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)) {
                    AtomicLong count = new AtomicLong(0);
                    long startTime = System.currentTimeMillis();
                    // Listen for 300ms
                    while (System.currentTimeMillis() - startTime < 300) {
                        if (handle.getNextPacket() != null) {
                            count.incrementAndGet();
                        }
                    }
                    interfaceTrafficMap.put(dev.getName(), count.get());
                } catch (Exception ignored) {
                } finally {
                    latch.countDown();
                }
            }).start();
        }
        try {
            latch.await(1000, TimeUnit.MILLISECONDS);
        } catch (InterruptedException ignored) {}
    }

    private void displayCaptureConfigurationDialog() {
        // Show a temporary "Scanning" dialog or just run the task
        Alert scanningAlert = new Alert(Alert.AlertType.INFORMATION);
        scanningAlert.setTitle("Smart Sync");
        scanningAlert.setHeaderText("Detecting Active Traffic...");
        scanningAlert.setContentText("Scanning interfaces for live data to help you pick the right one...");
        scanningAlert.getDialogPane().lookupButton(ButtonType.OK).setDisable(true);
        scanningAlert.show();

        Task<List<PcapNetworkInterface>> scanTask = new Task<>() {
            @Override
            protected List<PcapNetworkInterface> call() throws Exception {
                List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
                if (allDevs == null) return Collections.emptyList();
                
                List<PcapNetworkInterface> activeOnes = new ArrayList<>();
                for (PcapNetworkInterface d : allDevs) {
                    if (isInterfaceActive(d)) activeOnes.add(d);
                }
                
                auditTrafficForActiveInterfaces(activeOnes);
                return allDevs;
            }
        };

        scanTask.setOnSucceeded(e -> {
            scanningAlert.close();
            openConfigDialog(scanTask.getValue());
        });

        scanTask.setOnFailed(e -> {
            scanningAlert.close();
            System.err.println("Scan failed: " + scanTask.getException().getMessage());
            openConfigDialog(Collections.emptyList());
        });

        new Thread(scanTask).start();
    }

    private void openConfigDialog(List<PcapNetworkInterface> availableDevices) {
        boolean npcapAvailable = (availableDevices != null && !availableDevices.isEmpty());

        Dialog<Config> captureDialog = new Dialog<>();
        captureDialog.setTitle("New Packet Capture");
        captureDialog.setHeaderText("Smart Interface Selection\nWe scanned for traffic to help you avoid '0 packets captured'.");

        ButtonType startButtonType = new ButtonType("Start", ButtonBar.ButtonData.OK_DONE);
        captureDialog.getDialogPane().getButtonTypes().addAll(startButtonType, ButtonType.CANCEL);

        GridPane dialogGridPane = new GridPane();
        dialogGridPane.setHgap(10);
        dialogGridPane.setVgap(10);
        dialogGridPane.setPadding(new Insets(20, 150, 10, 10));

        ComboBox<Object> networkInterfaceComboBox = new ComboBox<>();
        networkInterfaceComboBox.getItems().add("Simulation Mode");

        List<PcapNetworkInterface> prioritized = new ArrayList<>();
        List<PcapNetworkInterface> others = new ArrayList<>();

        if (availableDevices != null) {
            for (PcapNetworkInterface device : availableDevices) {
                Long traffic = interfaceTrafficMap.getOrDefault(device.getName(), 0L);
                if (traffic > 0) {
                    prioritized.add(device);
                } else if (isInterfaceActive(device)) {
                    prioritized.add(device); // Keep active ones high even if no current traffic
                } else {
                    others.add(device);
                }
            }
        }

        // Sort prioritized by traffic count descending
        prioritized.sort((a, b) -> {
            Long tA = interfaceTrafficMap.getOrDefault(a.getName(), 0L);
            Long tB = interfaceTrafficMap.getOrDefault(b.getName(), 0L);
            return tB.compareTo(tA);
        });

        networkInterfaceComboBox.getItems().addAll(prioritized);
        networkInterfaceComboBox.getItems().addAll(others);

        if (!prioritized.isEmpty()) {
            networkInterfaceComboBox.getSelectionModel().select(prioritized.get(0));
        } else {
            networkInterfaceComboBox.getSelectionModel().selectFirst();
        }
        
        networkInterfaceComboBox.setCellFactory(param -> new ListCell<>() {
            @Override
            protected void updateItem(Object item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                    setStyle("");
                } else if (item instanceof PcapNetworkInterface networkInterface) {
                    String description = networkInterface.getDescription() != null ? networkInterface.getDescription() : networkInterface.getName();
                    Long traffic = interfaceTrafficMap.getOrDefault(networkInterface.getName(), 0L);
                    boolean active = isInterfaceActive(networkInterface);

                    if (traffic > 0) {
                        setText("🔥 LIVE TRAFFIC: " + description + " (" + traffic + " pkts detected)");
                        setStyle("-fx-text-fill: #e65100; -fx-font-weight: bold;");
                    } else if (active) {
                        setText("\u2705 Active: " + description);
                        setStyle("-fx-text-fill: #2e7d32;");
                    } else {
                        setText("\u26aa Inactive: " + description);
                        setStyle("-fx-text-fill: #9e9e9e;");
                    }
                } else {
                    setText("\uD83D\uDDA5\uFE0F " + item.toString());
                    setStyle("-fx-text-fill: #1565c0; -fx-font-weight: bold;");
                }
            }
        });
        networkInterfaceComboBox.setButtonCell(networkInterfaceComboBox.getCellFactory().call(null));
        networkInterfaceComboBox.setPrefWidth(550);

        TextField durationTextField = new TextField("10");
        TextField protocolTextField = new TextField("ALL");
        TextField outputFileTextField = new TextField("packet_analysis_log.txt");

        dialogGridPane.add(new Label("Interface:"), 0, 0);
        dialogGridPane.add(networkInterfaceComboBox, 1, 0);
        dialogGridPane.add(new Label("Duration (sec):"), 0, 1);
        dialogGridPane.add(durationTextField, 1, 1);
        dialogGridPane.add(new Label("Protocols:"), 0, 2);
        dialogGridPane.add(protocolTextField, 1, 2);
        dialogGridPane.add(new Label("Output File:"), 0, 3);
        dialogGridPane.add(outputFileTextField, 1, 3);
        
        String hintText = prioritized.isEmpty() ? "\u26a0\ufe0f No active traffic detected. Simulation mode recommended." : "✅ High-traffic interfaces marked with 🔥";
        Label statusLabel = new Label(hintText);
        statusLabel.setStyle("-fx-text-fill: #388e3c; -fx-font-size: 11px;");
        dialogGridPane.add(statusLabel, 1, 4);

        captureDialog.getDialogPane().setContent(dialogGridPane);

        captureDialog.setResultConverter(dialogButton -> {
            if (dialogButton != startButtonType) return null;
            Object selectedItem = networkInterfaceComboBox.getValue();
            String interfaceName = (selectedItem instanceof PcapNetworkInterface ni) ? ni.getName() : "sim";
            String networkDescription = (selectedItem instanceof PcapNetworkInterface ni) ? 
                (ni.getDescription() != null ? ni.getDescription() : ni.getName()) : "SIMULATED";

            int duration = 10;
            try { duration = Integer.parseInt(durationTextField.getText()); } catch (Exception ignored) {}
            Set<String> protos = Config.parseProtocols(protocolTextField.getText());
            String out = outputFileTextField.getText();
            return new Config(interfaceName, networkDescription, duration, protos, out);
        });

        captureDialog.showAndWait().ifPresent(this::executePacketCapture);
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
            loadLogFile(configuration.outFile());

            Alert completeAlert = new Alert(Alert.AlertType.INFORMATION);
            completeAlert.setTitle("Capture Complete");
            completeAlert.setHeaderText("Capture Finished");
            completeAlert.setContentText("Captured " + capturedPacketCount + " packets.");
            if (capturedPacketCount == 0 && !"sim".equals(configuration.iface())) {
                completeAlert.setAlertType(Alert.AlertType.WARNING);
                completeAlert.setContentText("0 packets captured. Try browsing some websites while capturing or select a different interface marked with 🔥.");
            }
            
            ButtonType viewLogButtonType = new ButtonType("View Log File", ButtonBar.ButtonData.OTHER);
            completeAlert.getButtonTypes().add(viewLogButtonType);
            completeAlert.showAndWait().ifPresent(bt -> {
                if (bt == viewLogButtonType) openLogFileInEditor(configuration.outFile());
            });
        });

        captureTask.setOnFailed(e -> {
            progressAlert.setResult(ButtonType.OK);
            progressAlert.close();
            showAlert(Alert.AlertType.ERROR, "Capture Failed", e.getSource().getException().getMessage());
        });

        new Thread(captureTask).start();
    }

    private void openLogFileInEditor(String filePath) {
        try {
            File logFile = new File(filePath);
            if (logFile.exists() && Desktop.isDesktopSupported()) {
                Desktop.getDesktop().open(logFile);
            } else {
                new ProcessBuilder("notepad.exe", filePath).start();
            }
        } catch (Exception e) {
            showAlert(Alert.AlertType.ERROR, "Open Error", e.getMessage());
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
