package netpacksys.parser;

import netpacksys.PacketContext;

public interface LayerParser {
    void parse(PacketContext ctx);
}

