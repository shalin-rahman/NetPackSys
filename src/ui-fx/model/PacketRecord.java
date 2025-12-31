package model;

public record PacketRecord(
    long frameNo,
    String timestamp,
    String srcIp,
    String dstIp,
    String protocol,
    String length,
    String info,
    String totalDelay,
    String rawContent
) {}
