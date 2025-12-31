package processor;

import java.util.List;

public interface LogProcessor<T> {
    List<T> process(List<String> lines);
}
