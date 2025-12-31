package core.capture;

import core.PcapPacketStub;

public interface PacketHandler {
    /**
     * @return true to continue capture, false to terminate.
     */
    boolean handle(PcapPacketStub packet);
}


