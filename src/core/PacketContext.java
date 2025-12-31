package core;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.DoubleStream;

public final class PacketContext {
    private final long frameNo;
    private final PcapPacketStub stub;
    private final Map<String, Map<String, String>> layers = new LinkedHashMap<>();
    private TransportInfo transportInfo;
    private byte[] currentLayerPayload;
    private Map<String, String> appData;
    private final Map<String, DelayInfo> delayInfo = new LinkedHashMap<>();
    private long processingStartTime;

    public PacketContext(long frameNo, PcapPacketStub stub) {
        this.frameNo = frameNo;
        this.stub = stub;
        this.currentLayerPayload = stub.rawData();
        this.processingStartTime = System.nanoTime();
    }

    public long frameNo() {
        return frameNo;
    }

    public PcapPacketStub stub() {
        return stub;
    }

    public Map<String, Map<String, String>> layers() {
        return layers;
    }

    public byte[] payload() {
        return currentLayerPayload;
    }

    public TransportInfo transport() {
        return transportInfo;
    }

    public Map<String, String> app() {
        return appData;
    }

    public Map<String, DelayInfo> delayInfo() {
        return delayInfo;
    }

    public void addLayer(String layerName, Map<String, String> data, byte[] newPayload) {
        layers.put(layerName, data);
        this.currentLayerPayload = newPayload;
        if ("TRANSPORT".equals(layerName)) {
            this.transportInfo = new TransportInfo(
                    Integer.parseInt(data.get("SrcPort")),
                    Integer.parseInt(data.get("DstPort")),
                    data.get("Proto"),
                    Integer.parseInt(data.get("PayloadLen")),
                    data.get("Flags")
            );
        }
    }

    public void setApp(Map<String, String> data) {
        this.appData = data;
    }

    public void addDelayInfo(String layerName, DelayInfo info) {
        delayInfo.put(layerName, info);
    }

    public double getTotalNodalDelay() {
        return delayInfo.values().stream()
                .mapToDouble(DelayInfo::totalDelay)
                .sum();
    }

    public double getTotalProcessingDelay() {
        return delayInfo.values().stream()
                .mapToDouble(DelayInfo::processingDelay)
                .sum();
    }

    public double getTotalTransmissionDelay() {
        return delayInfo.values().stream()
                .mapToDouble(DelayInfo::transmissionDelay)
                .sum();
    }

    public double getTotalPropagationDelay() {
        return delayInfo.values().stream()
                .mapToDouble(DelayInfo::propagationDelay)
                .sum();
    }

    public double getTotalQueuingDelay() {
        return delayInfo.values().stream()
                .mapToDouble(DelayInfo::queuingDelay)
                .sum();
    }
}


