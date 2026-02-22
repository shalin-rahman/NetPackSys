import core.Config;
import core.PacketAnalyzerApp;
import javafx.application.Application;
import javafx.beans.property.SimpleStringProperty;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.layout.*;
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
import java.io.FileInputStream;
import java.util.List;
import java.util.Set;

public class PacketLogViewer extends Application {

    private static final String DEFAULT_LOG_FILE = "packet_analysis_log.txt";

    private TableView<PacketRecord> packetRecordTableView;
    private TextArea packetDetailsTextArea;
    private Label statusBarLabel;
    private LogPresenter logPresenter;
    private Stage primaryStage;

    @Override
    public void start(Stage primaryStage) {
        this.primaryStage = primaryStage;

        try {
            File iconFile = new File("../../nps_icon.png");
            if (!iconFile.exists()) iconFile = new File("nps_icon.png");
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
        packetRecordTableView.getStyleClass().add("packet-table");

        packetDetailsTextArea = new TextArea();
        packetDetailsTextArea.setEditable(false);
        packetDetailsTextArea.setWrapText(true);
        packetDetailsTextArea.setPrefRowCount(12);
        packetDetailsTextArea.getStyleClass().add("details-area");

        statusBarLabel = new Label("Ready");
        HBox statusBar = new HBox(statusBarLabel);
        statusBar.getStyleClass().add("status-bar");
        statusBar.setAlignment(Pos.CENTER_LEFT);
        statusBar.setPadding(new Insets(6, 16, 6, 16));

        Button newCaptureButton = new Button("New Capture");
        newCaptureButton.getStyleClass().addAll("button", "button-primary");
        newCaptureButton.setOnAction(e -> displayCaptureConfigurationDialog());

        Button viewLogButton = new Button("View Log File");
        viewLogButton.getStyleClass().addAll("button", "button-secondary");
        viewLogButton.setOnAction(e -> openLogFileInEditor(DEFAULT_LOG_FILE));

        HBox toolbar = new HBox(10);
        toolbar.getStyleClass().add("toolbar");
        toolbar.setAlignment(Pos.CENTER_LEFT);
        toolbar.getChildren().addAll(newCaptureButton, viewLogButton);

        HBox appHeader = new HBox(12);
        appHeader.getStyleClass().add("app-header");
        appHeader.setAlignment(Pos.CENTER_LEFT);
        appHeader.setPadding(new Insets(12, 20, 12, 20));
        Label titleLabel = new Label("NetPackSys");
        titleLabel.getStyleClass().add("app-title");
        Label subtitleLabel = new Label("Network Packet Capture & Delay Analysis");
        subtitleLabel.getStyleClass().add("app-subtitle");
        appHeader.getChildren().addAll(titleLabel, subtitleLabel);

        VBox packetListSection = new VBox(8);
        packetListSection.getStyleClass().add("section");
        packetListSection.setPadding(new Insets(16));
        Label listTitle = new Label("Packet list");
        listTitle.getStyleClass().add("section-title");
        VBox.setVgrow(packetRecordTableView, Priority.ALWAYS);
        packetListSection.getChildren().addAll(listTitle, packetRecordTableView);

        VBox packetDetailsSection = new VBox(8);
        packetDetailsSection.getStyleClass().add("section");
        packetDetailsSection.setPadding(new Insets(16));
        Label detailsTitle = new Label("Packet details");
        detailsTitle.getStyleClass().add("section-title");
        VBox.setVgrow(packetDetailsTextArea, Priority.ALWAYS);
        packetDetailsSection.getChildren().addAll(detailsTitle, packetDetailsTextArea);

        SplitPane mainSplitPane = new SplitPane();
        mainSplitPane.setOrientation(javafx.geometry.Orientation.VERTICAL);
        mainSplitPane.getItems().addAll(packetListSection, packetDetailsSection);
        mainSplitPane.setDividerPositions(0.62);

        VBox topBar = new VBox(appHeader, toolbar);
        topBar.setSpacing(0);

        BorderPane mainLayout = new BorderPane();
        mainLayout.setTop(topBar);
        mainLayout.setCenter(mainSplitPane);
        mainLayout.setBottom(statusBar);
        mainLayout.setBackground(new Background(new BackgroundFill(javafx.scene.paint.Color.valueOf("#f1f5f9"), null, null)));

        Scene mainScene = new Scene(mainLayout, 1100, 820);
        String css = getClass().getClassLoader().getResource("styles.css") != null
                ? getClass().getClassLoader().getResource("styles.css").toExternalForm()
                : null;
        if (css != null) mainScene.getStylesheets().add(css);

        primaryStage.setTitle("NetPackSys – Network Packet Capture & Delay Analysis");
        primaryStage.setScene(mainScene);
        primaryStage.setMinWidth(900);
        primaryStage.setMinHeight(600);
        primaryStage.show();

        loadLogFile(DEFAULT_LOG_FILE);
    }

    private TableView<PacketRecord> createPacketTableView() {
        TableView<PacketRecord> table = new TableView<>();

        TableColumn<PacketRecord, String> frameNumberColumn = new TableColumn<>("No.");
        frameNumberColumn.setCellValueFactory(data -> new SimpleStringProperty(String.valueOf(data.getValue().frameNo())));
        frameNumberColumn.setPrefWidth(52);

        TableColumn<PacketRecord, String> timestampColumn = new TableColumn<>("Time");
        timestampColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().timestamp()));
        timestampColumn.setPrefWidth(180);

        TableColumn<PacketRecord, String> sourceIpColumn = new TableColumn<>("Source");
        sourceIpColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().srcIp()));
        sourceIpColumn.setPrefWidth(110);

        TableColumn<PacketRecord, String> destinationIpColumn = new TableColumn<>("Destination");
        destinationIpColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().dstIp()));
        destinationIpColumn.setPrefWidth(110);

        TableColumn<PacketRecord, String> protocolColumn = new TableColumn<>("Protocol");
        protocolColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().protocol()));
        protocolColumn.setPrefWidth(78);

        TableColumn<PacketRecord, String> lengthColumn = new TableColumn<>("Length");
        lengthColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().length()));
        lengthColumn.setPrefWidth(64);

        TableColumn<PacketRecord, String> informationColumn = new TableColumn<>("Info");
        informationColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().info()));
        informationColumn.setPrefWidth(240);

        TableColumn<PacketRecord, String> nodalDelayColumn = new TableColumn<>("Nodal delay");
        nodalDelayColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().totalDelay()));
        nodalDelayColumn.setPrefWidth(100);

        table.getColumns().addAll(
                frameNumberColumn, timestampColumn, sourceIpColumn, destinationIpColumn,
                protocolColumn, lengthColumn, informationColumn, nodalDelayColumn
        );

        table.getSelectionModel().selectedItemProperty().addListener((o, oldVal, newVal) -> {
            if (newVal != null) packetDetailsTextArea.setText(newVal.rawContent());
            else packetDetailsTextArea.clear();
        });

        return table;
    }

    private void loadLogFile(String logFilePath) {
        LogPresenter.LogData logData = logPresenter.loadLog(logFilePath);

        if (logData.hasError()) {
            packetDetailsTextArea.setText("Error loading log: " + logData.errorMessage);
            packetRecordTableView.getItems().clear();
            statusBarLabel.setText("Error: " + logData.errorMessage);
        } else {
            packetRecordTableView.getItems().setAll(logData.records);
            if (!logData.records.isEmpty()) {
                packetRecordTableView.getSelectionModel().selectFirst();
            }
            int n = logData.records.size();
            statusBarLabel.setText(n + " packet" + (n == 1 ? "" : "s") + " loaded · " + logFilePath);
        }
    }

    private void displayCaptureConfigurationDialog() {
        List<PcapNetworkInterface> availableDevices = null;
        try {
            availableDevices = Pcaps.findAllDevs();
        } catch (PcapNativeException e) {
            showAlert(Alert.AlertType.WARNING, "Live capture unavailable",
                    "Could not list interfaces (" + e.getMessage() + "). Simulation mode is still available.");
        } catch (LinkageError e) {
            showAlert(Alert.AlertType.WARNING, "Live capture unavailable",
                    "Npcap/WinPcap is not installed. Use Simulation mode, or install Npcap from https://npcap.com for live capture.");
        }

        try {
            Dialog<Config> captureDialog = new Dialog<>();
            captureDialog.setTitle("New packet capture");
            captureDialog.setHeaderText("Capture configuration");

            String css = getClass().getClassLoader().getResource("styles.css") != null
                    ? getClass().getClassLoader().getResource("styles.css").toExternalForm()
                    : null;
            if (css != null) captureDialog.getDialogPane().getStylesheets().add(css);

            captureDialog.getDialogPane().getStyleClass().add("dialog-pane");

            ButtonType startButtonType = new ButtonType("Start capture", ButtonBar.ButtonData.OK_DONE);
            captureDialog.getDialogPane().getButtonTypes().addAll(startButtonType, ButtonType.CANCEL);

            GridPane grid = new GridPane();
            grid.setHgap(14);
            grid.setVgap(12);
            grid.setPadding(new Insets(20, 24, 16, 24));

            ComboBox<Object> networkInterfaceComboBox = new ComboBox<>();
            networkInterfaceComboBox.getItems().add("Simulation mode");
            if (availableDevices != null && !availableDevices.isEmpty()) {
                networkInterfaceComboBox.getItems().addAll(availableDevices);
            }
            networkInterfaceComboBox.getSelectionModel().selectFirst();
            networkInterfaceComboBox.setCellFactory(param -> new ListCell<>() {
                @Override
                protected void updateItem(Object item, boolean empty) {
                    super.updateItem(item, empty);
                    if (empty || item == null) setText(null);
                    else if (item instanceof PcapNetworkInterface nif) {
                        String desc = nif.getDescription() != null ? nif.getDescription() : nif.getName();
                        setText(desc + " [" + nif.getName() + "]");
                    } else setText(item.toString());
                }
            });
            networkInterfaceComboBox.setButtonCell(networkInterfaceComboBox.getCellFactory().call(null));
            networkInterfaceComboBox.setPrefWidth(420);
            networkInterfaceComboBox.getStyleClass().add("combo-box");

            TextField durationTextField = new TextField("10");
            durationTextField.getStyleClass().add("text-field");
            
            ComboBox<String> protocolComboBox = new ComboBox<>();
            protocolComboBox.setEditable(true);
            protocolComboBox.getItems().addAll(
                    "ALL",
                    "HTTP",
                    "DNS",
                    "HTTPS",
                    "TCP",
                    "UDP",
                    "HTTP,DNS",
                    "HTTP,HTTPS",
                    "HTTP,DNS,HTTPS"
            );
            protocolComboBox.setValue("ALL");
            protocolComboBox.setPrefWidth(420);
            protocolComboBox.getStyleClass().add("combo-box");
            protocolComboBox.setPromptText("Select or type protocols (e.g. ALL, HTTP, DNS)");
            
            TextField outputFileTextField = new TextField(DEFAULT_LOG_FILE);
            outputFileTextField.getStyleClass().add("text-field");

            grid.add(new Label("Interface"), 0, 0);
            grid.add(networkInterfaceComboBox, 1, 0);
            grid.add(new Label("Duration (sec)"), 0, 1);
            grid.add(durationTextField, 1, 1);
            grid.add(new Label("Protocols"), 0, 2);
            grid.add(protocolComboBox, 1, 2);
            grid.add(new Label("Output file"), 0, 3);
            grid.add(outputFileTextField, 1, 3);

            Label adminHint = new Label(
                    "Live capture requires running the app as Administrator (right‑click shortcut → Run as administrator). " +
                    "Use \"Simulation mode\" if you cannot elevate, or to test without admin.");
            adminHint.setWrapText(true);
            adminHint.setMaxWidth(420);
            adminHint.getStyleClass().addAll("dialog-hint", "dialog-hint-warning");
            grid.add(adminHint, 1, 4);

            captureDialog.getDialogPane().setContent(grid);

            captureDialog.setResultConverter(btn -> {
                if (btn != startButtonType) return null;

                Object selected = networkInterfaceComboBox.getValue();
                String ifaceName;
                String networkDesc;
                if (selected instanceof PcapNetworkInterface nif) {
                    ifaceName = nif.getName();
                    networkDesc = nif.getDescription() != null ? nif.getDescription() : nif.getName();
                } else {
                    ifaceName = "sim";
                    networkDesc = "SIMULATED";
                }

                int durationSec = 10;
                try {
                    String d = durationTextField.getText().trim();
                    if (!d.isEmpty()) durationSec = Integer.parseInt(d);
                } catch (NumberFormatException ignored) { }
                String protocolValue = protocolComboBox.getValue() != null 
                        ? protocolComboBox.getValue().trim() 
                        : protocolComboBox.getEditor().getText().trim();
                if (protocolValue.isEmpty()) protocolValue = "ALL";
                Set<String> protocols = Config.parseProtocols(protocolValue);
                String outFile = outputFileTextField.getText().trim();
                if (outFile.isEmpty()) outFile = DEFAULT_LOG_FILE;

                return new Config(ifaceName, networkDesc, durationSec, protocols, outFile);
            });

            captureDialog.showAndWait().ifPresent(this::executePacketCapture);

        } catch (Exception e) {
            showAlert(Alert.AlertType.ERROR, "Error", "Failed to open capture dialog: " + e.getMessage());
        }
    }

    private void executePacketCapture(Config configuration) {
        Alert progressAlert = new Alert(Alert.AlertType.INFORMATION);
        progressAlert.setTitle("Capturing…");
        progressAlert.setHeaderText("Packet capture in progress");
        boolean isSim = "sim".equalsIgnoreCase(configuration.iface());
        progressAlert.setContentText(
                isSim ? "Simulation running for " + configuration.durationSec() + " s…"
                        : "Capture on " + configuration.iface() + " for " + configuration.durationSec() + " s… " +
                          "If this hangs, exit and run the app as Administrator.");
        progressAlert.initModality(Modality.WINDOW_MODAL);
        progressAlert.initOwner(primaryStage);
        progressAlert.getDialogPane().lookupButton(ButtonType.OK).setDisable(true);

        String css = getClass().getClassLoader().getResource("styles.css") != null
                ? getClass().getClassLoader().getResource("styles.css").toExternalForm()
                : null;
        if (css != null) progressAlert.getDialogPane().getStylesheets().add(css);

        progressAlert.show();

        Task<Long> captureTask = new Task<>() {
            @Override
            protected Long call() throws Exception {
                return new PacketAnalyzerApp(configuration).run();
            }
        };

        final String dialogCss = css;
        captureTask.setOnSucceeded(we -> {
            progressAlert.setResult(ButtonType.OK);
            progressAlert.close();
            long count = (long) we.getSource().getValue();
            loadLogFile(configuration.outFile());

            Alert completeAlert = new Alert(Alert.AlertType.INFORMATION);
            completeAlert.setTitle("Capture complete");
            completeAlert.setHeaderText("Capture finished successfully");
            completeAlert.setContentText("Captured " + count + " packet" + (count == 1 ? "" : "s") + ".\nTable updated.");
            completeAlert.initOwner(primaryStage);
            if (dialogCss != null) completeAlert.getDialogPane().getStylesheets().add(dialogCss);
            ButtonType viewLog = new ButtonType("View log file", ButtonBar.ButtonData.OTHER);
            completeAlert.getButtonTypes().add(viewLog);
            completeAlert.showAndWait().ifPresent(bt -> {
                if (bt == viewLog) openLogFileInEditor(configuration.outFile());
            });
        });

        captureTask.setOnFailed(we -> {
            progressAlert.setResult(ButtonType.OK);
            progressAlert.close();
            Throwable t = we.getSource().getException();
            showAlert(Alert.AlertType.ERROR, "Capture failed", t != null ? t.getMessage() : "Unknown error");
        });

        new Thread(captureTask).start();
    }

    private void openLogFileInEditor(String filePath) {
        try {
            File logFile = new File(filePath);
            if (logFile.exists()) {
                if (Desktop.isDesktopSupported()) {
                    Desktop.getDesktop().open(logFile);
                } else {
                    new ProcessBuilder("notepad.exe", filePath).start();
                }
            } else {
                showAlert(Alert.AlertType.ERROR, "File not found", "Log file does not exist: " + filePath);
            }
        } catch (Exception e) {
            showAlert(Alert.AlertType.ERROR, "Open error", "Failed to open log: " + e.getMessage());
        }
    }

    private void showAlert(Alert.AlertType type, String title, String content) {
        Alert a = new Alert(type);
        a.setTitle(title);
        a.setHeaderText(null);
        a.setContentText(content);
        a.initOwner(primaryStage);
        String css = getClass().getClassLoader().getResource("styles.css") != null
                ? getClass().getClassLoader().getResource("styles.css").toExternalForm()
                : null;
        if (css != null) a.getDialogPane().getStylesheets().add(css);
        a.showAndWait();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
