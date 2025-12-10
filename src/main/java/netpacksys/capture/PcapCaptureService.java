package netpacksys;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

public final class PcapCaptureService implements CaptureService {
    private final PcapHandle handle;
    private final AtomicLong frameCounter = new AtomicLong(0);
    private volatile boolean shouldStop = false;

    public PcapCaptureService(String iface) throws PcapNativeException {
        PcapNetworkInterface nif = Pcaps.getDevByName(iface);
        if (nif == null) throw new PcapNativeException("Interface not found: " + iface);
        this.handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 50);
    }

    @Override
    public void startCapture(PacketHandler handler, int maxSeconds) throws Exception {
        final long startTime = System.currentTimeMillis();
        final long timeoutMs = maxSeconds * 1000L;

        try {
            while (!shouldStop && (System.currentTimeMillis() - startTime) < timeoutMs) {
                org.pcap4j.packet.Packet packet = handle.getNextPacket();
                if (packet == null) {
                    Thread.sleep(10);
                    continue;
                }

                final long frameNo = frameCounter.incrementAndGet();
                final byte[] rawData = packet.getRawData();
                final Instant timestamp = Instant.now();

                final PcapPacketStub stub = new PcapPacketStub(
                        frameNo,
                        rawData,
                        timestamp,
                        packet.length(),
                        rawData.length
                );

                if (!handler.handle(stub)) {
                    break;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.out.println("Capture interrupted by user");
        } catch (Exception e) {
            System.err.println("Capture error: " + e.getMessage());
        }
    }

    @Override
    public void close() {
        shouldStop = true;
        if (handle != null && handle.isOpen()) {
            handle.close();
        }
    }
}

