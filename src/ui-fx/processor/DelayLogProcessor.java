package processor;

import java.util.ArrayList;
import java.util.List;

public class DelayLogProcessor implements LogProcessor {
    
    @Override
    public List<String> process(List<String> lines) {
        List<String> result = new ArrayList<>();
        if (lines == null || lines.isEmpty()) {
            return result;
        }
        
        for (String line : lines) {
            if (line.toLowerCase().contains("delay")) {
                result.add(line);
            }
        }
        return result;
    }
}
