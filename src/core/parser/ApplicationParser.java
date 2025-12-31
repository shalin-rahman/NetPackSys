package core.parser;

import core.PacketContext;
import core.TransportInfo;

import java.util.Map;

import java.util.Map;

public interface ApplicationParser {
    boolean canParse(PacketContext ctx, TransportInfo transportInfo);

    Map<String, String> parse(PacketContext ctx, TransportInfo transportInfo);
}


