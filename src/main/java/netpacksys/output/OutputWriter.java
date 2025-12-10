package netpacksys.output;

import java.io.Closeable;
import java.util.List;

public interface OutputWriter extends Closeable {
    void writeRows(List<String> rows);
}

