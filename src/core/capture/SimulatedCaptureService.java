package core.capture;

import core.PcapPacketStub;
import core.util.SyntheticPacketFactory;

import java.time.Instant;

public final class SimulatedCaptureService implements CaptureService {
    private volatile boolean closed = false;

    @Override
    public void startCapture(PacketHandler handler, int maxSeconds) {
        int total = Math.max(1, maxSeconds * 5);
        for (int i = 0; i < total && !closed; i++) {
            final PcapPacketStub stub;
            if (i % 3 == 0) {
                stub = SyntheticPacketFactory.httpRequestStub(i + 1);
            } else if (i % 3 == 1) {
                stub = SyntheticPacketFactory.dnsQueryStub(i + 1);
            } else {
                stub = SyntheticPacketFactory.tlsClientHelloStub(i + 1);
            }
            if (!handler.handle(stub)) break;

            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    @Override
    public void close() {
        closed = true;
    }
}


