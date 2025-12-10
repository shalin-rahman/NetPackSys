package netpacksys.output;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class ConsoleOutputAccumulator implements OutputWriter {
    private final List<String> buffer = Collections.synchronizedList(new ArrayList<>());
    private final PrintWriter consoleOut = new PrintWriter(System.out, true);

    @Override
    public void writeRows(List<String> rows) {
        buffer.addAll(rows);
    }

    public void printFinalReport(long filteredPackets, long totalPackets) {
        consoleOut.println();
        consoleOut.println("===================================");
        consoleOut.printf("=== FINAL PACKET ANALYSIS REPORT (%d filtered packets / %d total) ===%n", filteredPackets, totalPackets);
        consoleOut.println("===================================");
        buffer.forEach(consoleOut::println);
        consoleOut.println("===================================");
    }

    @Override
    public void close() {
        // nothing to close
    }
}

