package core.capture;

public interface CaptureService extends AutoCloseable {
    void startCapture(PacketHandler handler, int maxSeconds) throws Exception;
}


