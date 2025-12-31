package core.parser;

import core.DelayInfo;
import core.PacketContext;
import core.TransportInfo;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public final class TlsParser implements ApplicationParser {
    @Override
    public boolean canParse(PacketContext ctx, TransportInfo t) {
        return "TCP".equals(t.proto()) && (t.dstPort() == 443 || t.srcPort() == 443);
    }

    @Override
    public Map<String, String> parse(PacketContext ctx, TransportInfo t) {
        long startTime = System.nanoTime();
        Map<String, String> m = new LinkedHashMap<>();
        m.put("AppProto", "TLS");
        byte[] raw = ctx.payload();
        if (raw.length < 5) {
            m.put("Error", "Packet too short");
            return m;
        }

        try {
            int contentType = raw[0] & 0xFF;
            int versionMajor = raw[1] & 0xFF;
            int versionMinor = raw[2] & 0xFF;
            int length = ((raw[3] & 0xFF) << 8) | (raw[4] & 0xFF);

            m.put("ContentType", getTlsContentType(contentType));
            m.put("Version", String.format("%d.%d", versionMajor, versionMinor));
            m.put("TLSVersion", getTlsVersion(versionMajor, versionMinor));
            m.put("Length", String.valueOf(length));

            if (contentType == 0x16 && raw.length >= 6) {
                int handshakeType = raw[5] & 0xFF;
                m.put("HandshakeType", getTlsHandshakeType(handshakeType));

                if (handshakeType == 0x01) {
                    String sni = extractSni(raw);
                    if (sni != null) {
                        m.put("SNI", sni);
                    }
                    m.put("Info", "Client Hello");
                } else if (handshakeType == 0x02) {
                    m.put("Info", "Server Hello");
                }
            }

        } catch (Exception e) {
            m.put("Error", "Malformed TLS");
        }

        double processingDelay = (System.nanoTime() - startTime) / 1_000_000.0;
        double tlsProcessingDelay = 0.2;
        double queuingDelay = 0.3 + (Math.random() * 0.5);

        DelayInfo delayInfo = new DelayInfo(
                processingDelay + tlsProcessingDelay,
                0,
                0,
                queuingDelay,
                String.format("Proc: %.3f ms (crypto), Queue: %.3f ms", tlsProcessingDelay, queuingDelay)
        );

        ctx.addDelayInfo("APP", delayInfo);

        m.put("ProcessingDelay", String.format("%.6f ms", processingDelay + tlsProcessingDelay));
        m.put("TransmissionDelay", "0.000000 ms");
        m.put("PropagationDelay", "0.000000 ms");
        m.put("QueuingDelay", String.format("%.3f ms", queuingDelay));
        m.put("TotalDelay", String.format("%.6f ms", delayInfo.totalDelay()));

        return m;
    }

    private String getTlsContentType(int type) {
        return switch (type) {
            case 0x14 -> "ChangeCipherSpec";
            case 0x15 -> "Alert";
            case 0x16 -> "Handshake";
            case 0x17 -> "ApplicationData";
            default -> "Unknown(" + type + ")";
        };
    }

    private String getTlsVersion(int major, int minor) {
        if (major == 3 && minor == 3) return "TLS 1.2";
        if (major == 3 && minor == 4) return "TLS 1.3";
        if (major == 3 && minor == 1) return "TLS 1.0";
        if (major == 3 && minor == 2) return "TLS 1.1";
        return String.format("Unknown(%d.%d)", major, minor);
    }

    private String getTlsHandshakeType(int type) {
        return switch (type) {
            case 0x01 -> "ClientHello";
            case 0x02 -> "ServerHello";
            case 0x0B -> "Certificate";
            case 0x10 -> "ClientKeyExchange";
            case 0x14 -> "Finished";
            default -> "Unknown(" + type + ")";
        };
    }

    private String extractSni(byte[] raw) {
        try {
            int offset = 43;
            if (offset >= raw.length) return null;

            int sessionIdLen = raw[offset] & 0xFF;
            offset += 1 + sessionIdLen;

            if (offset + 2 >= raw.length) return null;
            int cipherSuitesLen = ((raw[offset] & 0xFF) << 8) | (raw[offset + 1] & 0xFF);
            offset += 2 + cipherSuitesLen;

            if (offset >= raw.length) return null;
            int compressionLen = raw[offset] & 0xFF;
            offset += 1 + compressionLen;

            if (offset + 2 >= raw.length) return null;
            int extensionsLen = ((raw[offset] & 0xFF) << 8) | (raw[offset + 1] & 0xFF);
            offset += 2;

            int endOffset = offset + extensionsLen;
            while (offset < endOffset && offset + 4 < raw.length) {
                int extType = ((raw[offset] & 0xFF) << 8) | (raw[offset + 1] & 0xFF);
                int extLen = ((raw[offset + 2] & 0xFF) << 8) | (raw[offset + 3] & 0xFF);
                offset += 4;

                if (extType == 0x0000) {
                    if (offset + 2 < raw.length) {
                        int sniListOffset = offset + 2;
                        if (sniListOffset + 3 < raw.length) {
                            int hostLen = ((raw[sniListOffset + 1] & 0xFF) << 8) | (raw[sniListOffset + 2] & 0xFF);
                            if (sniListOffset + 3 + hostLen <= raw.length) {
                                return new String(raw, sniListOffset + 3, hostLen, StandardCharsets.US_ASCII);
                            }
                        }
                    }
                    break;
                }
                offset += extLen;
            }
        } catch (Exception ignored) {
        }
        return null;
    }
}


