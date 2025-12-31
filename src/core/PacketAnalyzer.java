package core;

import core.ui.ConsoleUI;
import core.ui.UserSelection;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.util.*;
import java.util.stream.Collectors;

public class PacketAnalyzer {

    public static void main(String[] args) throws Exception {

        String initialSelection = "sim";
        int durationSec = 10;
        String protocolsCSV = "ALL";

        List<PcapNetworkInterface> allDevs = Collections.emptyList();
        List<PcapNetworkInterface> activeDevs = Collections.emptyList();

        String finalUsedNetwork = "N/A";
        final String OUTPUT_FILE = "packet_analysis_log.txt";

        try {
            allDevs = Pcaps.findAllDevs();
            activeDevs = allDevs.stream()
                    .filter(dev -> !dev.getName().toLowerCase().contains("wan miniport") && !dev.getName().toLowerCase().contains("loopback"))
                    .collect(Collectors.toList());

            String suggestedIndex = activeDevs.isEmpty() ? "1" : String.valueOf(allDevs.indexOf(activeDevs.get(0)) + 1);
            try (ConsoleUI ui = new ConsoleUI(System.in, System.out, System.err)) {
                UserSelection selection = ui.collect(allDevs, activeDevs, suggestedIndex);
                initialSelection = Optional.ofNullable(selection.interfaceSelection()).orElse("sim");
                durationSec = selection.durationSec() > 0 ? selection.durationSec() : 10;
                protocolsCSV = Optional.ofNullable(selection.protocolsCsv()).filter(s -> !s.isEmpty()).orElse("ALL");
            }

        } catch (PcapNativeException e) {
            System.err.println("❌ Failed to list interfaces (PcapNativeException). Using simulation mode.");
            initialSelection = "sim";
            if (durationSec <= 0) durationSec = 10;
        } catch (NumberFormatException e) {
            System.err.println("❌ Invalid number input. Using default values.");
            if (durationSec <= 0) durationSec = 10;
        } catch (Exception e) {
            System.err.println("❌ Unexpected error: " + e.getMessage() + ". Using default values.");
            initialSelection = "sim";
            if (durationSec <= 0) durationSec = 10;
        }

        if (durationSec <= 0) {
            durationSec = 10;
        }
        if (initialSelection == null) {
            initialSelection = "sim";
        }

        final Set<String> protocols = Config.parseProtocols(protocolsCSV);


        System.out.printf(" Protocols selected: %s (Output logged to console AND %s)%n", protocols, OUTPUT_FILE);

        List<Integer> liveInterfaceIndices = new ArrayList<>();
        for (int i = 0; i < allDevs.size(); i++) {
            if (activeDevs.contains(allDevs.get(i))) {
                liveInterfaceIndices.add(i + 1);
            }
        }

        boolean isSimulation = "sim".equalsIgnoreCase(initialSelection);
        int startIndex = -1;
        if (!isSimulation && initialSelection != null) {
            try {
                int selectedIndex = Integer.parseInt(initialSelection);
                if (selectedIndex >= 1 && selectedIndex <= allDevs.size()) {
                    startIndex = liveInterfaceIndices.indexOf(selectedIndex);
                }
            } catch (NumberFormatException ignored) {
            }
        }

        if (startIndex == -1 && !isSimulation && !liveInterfaceIndices.isEmpty()) {
            startIndex = 0;
        }

        boolean successfulCapture = false;

        if (isSimulation) {
            final String currentUsedNetwork = "SIMULATED";
            System.out.println("🧪 Running in SIMULATION mode.");
            finalUsedNetwork = currentUsedNetwork;
            Config cfg = new Config("sim", currentUsedNetwork, durationSec, protocols, OUTPUT_FILE);
            long processedPackets = new PacketAnalyzerApp(cfg).run();
            successfulCapture = processedPackets > 0;
        }

        else if (!liveInterfaceIndices.isEmpty()) {
            int currentIfaceIndex = startIndex;

            while (!successfulCapture && currentIfaceIndex < liveInterfaceIndices.size()) {
                int interfaceNumber = liveInterfaceIndices.get(currentIfaceIndex);
                PcapNetworkInterface selectedDev = allDevs.get(interfaceNumber - 1);

                final String currentUsedNetwork = selectedDev.getDescription() != null ? selectedDev.getDescription() : selectedDev.getName();
                final String ifaceName = selectedDev.getName();

                System.out.printf("\n=======================================================\n");
                System.out.printf("Attempting capture on: [%d] %s\n", interfaceNumber, currentUsedNetwork);
                System.out.printf("=======================================================\n");

                try {
                    Config cfg = new Config(ifaceName, currentUsedNetwork, durationSec, protocols, OUTPUT_FILE);
                    long processedPackets = new PacketAnalyzerApp(cfg).run();

                    if (processedPackets > 0) {
                        System.out.printf(" Capture successful with %d packets on %s.\n", processedPackets, currentUsedNetwork);
                        finalUsedNetwork = currentUsedNetwork;
                        successfulCapture = true;
                    } else {
                        System.out.printf(" Capture yielded 0 packets on %s. Retrying on next active interface.\n", currentUsedNetwork);
                    }
                } catch (PcapNativeException e) {
                    System.err.printf(" Capture initialization failed on %s: %s. Retrying on next active interface.\n", currentUsedNetwork, e.getMessage());
                } catch (Throwable t) {
                    System.err.printf(" Unexpected error during capture on %s: %s. Retrying on next active interface.\n", currentUsedNetwork, t.getMessage());
                }

                currentIfaceIndex++;
            }
        }

        if (!successfulCapture) {
            System.out.println("\n--- FINAL STATUS ---\nFailed to capture packets after trying all available active interfaces.");
        } else {
            System.out.printf("\n--- FINAL STATUS ---\nSuccessfully captured packets on %s.\n", finalUsedNetwork);
        }
    }
}


