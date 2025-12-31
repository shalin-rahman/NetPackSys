package core;

import java.util.Set;

public record Config(String iface, String usedNetwork, int durationSec, Set<String> protocols, String outFile) {
    public Config {
        // Normalize TLS to HTTPS centrally
        if (protocols != null && protocols.contains("TLS")) {
            java.util.Set<String> mutable = new java.util.HashSet<>(protocols);
            mutable.remove("TLS");
            mutable.add("HTTPS");
            protocols = java.util.Collections.unmodifiableSet(mutable);
        }
    }

    public static Set<String> parseProtocols(String csv) {
        if (csv == null || csv.trim().isEmpty() || "ALL".equalsIgnoreCase(csv.trim())) {
            return java.util.Collections.singleton("ALL");
        }
        return java.util.Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(String::toUpperCase)
                .collect(java.util.stream.Collectors.toSet());
    }
}


