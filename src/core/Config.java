package core;

import java.util.Set;

public record Config(String iface, String usedNetwork, int durationSec, Set<String> protocols, String outFile) {
}


