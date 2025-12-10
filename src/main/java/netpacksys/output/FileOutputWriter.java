package netpacksys;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

public final class FileOutputWriter implements OutputWriter {
    private final PrintWriter out;

    public FileOutputWriter(String path) {
        try {
            this.out = new PrintWriter(new FileWriter(path, true));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public synchronized void writeRows(List<String> rows) {
        for (String r : rows) out.println(r);
        out.flush();
    }

    @Override
    public void close() {
        if (out != null) out.close();
    }
}

