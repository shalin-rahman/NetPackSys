package processor;

import java.util.ArrayList;
import java.util.List;

public class DetailLogProcessor implements LogProcessor {
    
    @Override
    public List<String> process(List<String> lines) {
        List<String> result = new ArrayList<>();
        if (lines == null || lines.isEmpty()) {
            return result;
        }
        
        for (String line : lines) {
            if (!line.startsWith("DELAY_SUMMARY") && !line.startsWith("----")) {
                result.add(line);
            }
        }
        return result;
    }
}
