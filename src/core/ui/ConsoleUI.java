package core.ui;

import org.pcap4j.core.PcapNetworkInterface;

import java.io.InputStream;
import java.io.PrintStream;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;
import java.util.stream.Collectors;

public final class ConsoleUI implements AutoCloseable {
    private final Scanner scanner;
    private final PrintStream out;
    private final PrintStream err;

    public ConsoleUI(InputStream in, PrintStream out, PrintStream err) {
        this.scanner = new Scanner(in);
        this.out = out;
        this.err = err;
    }

    public UserSelection collect(List<PcapNetworkInterface> allDevs, List<PcapNetworkInterface> activeDevs, String suggestedIndex) {
        String initialSelection = "sim";
        int durationSec = 10;
        String protocolsCSV = "ALL";

        try {
            if (activeDevs.isEmpty()) {
                err.println(" No active network interfaces found. Forcing simulated capture mode ('sim').");
                initialSelection = "sim";
            } else {
                out.println("\n Available Network Interfaces (requires Administrator privileges for capture):");
                for (int i = 0; i < allDevs.size(); i++) {
                    PcapNetworkInterface dev = allDevs.get(i);
                    String desc = dev.getDescription() != null ? dev.getDescription() : "No description";
                    String marker = activeDevs.contains(dev) ? "" : " -";
                    out.printf("  [%d]%s %s (%s)%n", i + 1, marker, dev.getName(), desc);
                }

                out.printf("\n-> Enter the **number** of the interface to capture on (Suggestion: %s), or 'sim' for simulation: ", suggestedIndex);
                initialSelection = scanner.nextLine().trim();
                if (initialSelection.isEmpty()) {
                    initialSelection = "sim";
                }
            }

            out.print("-> Enter capture duration in seconds (e.g., 10): ");
            String durationInput = scanner.nextLine().trim();
            if (durationInput.isEmpty()) {
                err.println(" Duration cannot be empty. Using default 10 seconds.");
                durationSec = 10;
            } else {
                durationSec = Integer.parseInt(durationInput);
                if (durationSec <= 0) {
                    err.println(" Duration must be a positive number. Using default 10 seconds.");
                    durationSec = 10;
                }
            }

            out.print("-> Enter protocols to capture (e.g., HTTP,DNS,HTTPS, or ALL): ");
            protocolsCSV = scanner.nextLine().trim();
            if (protocolsCSV.isEmpty()) protocolsCSV = "ALL";
        } catch (NumberFormatException e) {
            err.println(" Invalid number input. Using default values.");
        } catch (Exception e) {
            err.println(" Unexpected error: " + e.getMessage() + ". Using default values.");
        }

        return new UserSelection(initialSelection, durationSec, protocolsCSV);
    }

    @Override
    public void close() {
        scanner.close();
    }
}


