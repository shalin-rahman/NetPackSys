package netpacksys.support;

import netpacksys.output.OutputWriter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Simple in-memory OutputWriter for assertions.
 */
public final class TestOutputWriter implements OutputWriter {
    private final List<String> rows = new ArrayList<>();

    @Override
    public void writeRows(java.util.List<String> newRows) {
        rows.addAll(newRows);
    }

    @Override
    public void close() throws IOException {
        // no-op
    }

    public List<String> rows() {
        return rows;
    }
}

