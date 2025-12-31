package processor;

import java.util.List;

public interface LogProcessor {
    /**
     * Processes the raw log lines and returns relevant lines.
     * @param lines The list of all lines from the log file.
     * @return A list of processed/filtered lines.
     */
    List<String> process(List<String> lines);
}
