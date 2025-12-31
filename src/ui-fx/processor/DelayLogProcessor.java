package processor;

import java.util.ArrayList;
import java.util.List;

public class DelayLogProcessor implements LogProcessor<String> {
    
    @Override
    public List<String> process(List<String> lines) {
        List<String> result = new ArrayList<>();
        if (lines == null) return result;
        
        for (String line : lines) {
            String lower = line.toLowerCase();
            if (lower.contains("delay")) {
                result.add(line);
            }
        }
        return result;
    }
}
