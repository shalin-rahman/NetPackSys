package netpacksys;

public record TransportInfo(int srcPort, int dstPort, String proto, int payloadLen, String flags) {
}

