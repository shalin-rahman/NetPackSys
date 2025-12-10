package netpacksys;

import java.time.Instant;

public final class PcapPacketStub {
    private final long frameNo;
    private final byte[] rawData;
    private final Instant timestamp;
    private final int length;
    private final int capLength;

    public PcapPacketStub(long frameNo, byte[] rawData, Instant timestamp, int length, int capLength) {
        this.frameNo = frameNo;
        this.rawData = rawData;
        this.timestamp = timestamp;
        this.length = length;
        this.capLength = capLength;
    }

    public long frameNo() {
        return frameNo;
    }

    public byte[] rawData() {
        return rawData;
    }

    public Instant timestamp() {
        return timestamp;
    }

    public int length() {
        return length;
    }

    public int capLength() {
        return capLength;
    }
}

