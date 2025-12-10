package netpacksys;

public record DelayInfo(
        double processingDelay,
        double transmissionDelay,
        double propagationDelay,
        double queuingDelay,
        String calculation
) {
    public double totalDelay() {
        return processingDelay + transmissionDelay + propagationDelay + queuingDelay;
    }
}

