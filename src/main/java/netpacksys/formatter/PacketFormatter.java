package netpacksys;

import java.util.List;

public interface PacketFormatter {
    List<String> format(PacketContext ctx);
}

