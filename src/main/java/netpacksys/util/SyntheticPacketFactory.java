package netpacksys;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

public final class SyntheticPacketFactory {
    private SyntheticPacketFactory() {}

    public static final String SIM_HOST = "example.com";
    public static final int SIM_DNS_PORT = 53;
    public static final int SIM_HTTP_PORT = 80;
    public static final int SIM_TLS_PORT = 443;
    public static final int SIM_CLIENT_PORT = 51322;

    public static PcapPacketStub httpRequestStub(long frameNo) {
        byte[] payload = ("GET /index.html HTTP/1.1\r\nHost: " + SIM_HOST + "\r\nUser-Agent: PacketAnalyzer/1.0\r\nAccept: text/html\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
        byte[] raw = makeEthernetIpv4TcpPacket(payload, SIM_CLIENT_PORT, SIM_HTTP_PORT);
        return new PcapPacketStub(frameNo, raw, Instant.now(), raw.length, raw.length);
    }

    public static PcapPacketStub dnsQueryStub(long frameNo) {
        byte[] payload = buildSyntheticDnsQuery(SIM_HOST);
        byte[] raw = makeEthernetIpv4UdpPacket(payload, SIM_CLIENT_PORT, SIM_DNS_PORT);
        return new PcapPacketStub(frameNo, raw, Instant.now(), raw.length, raw.length);
    }

    public static PcapPacketStub tlsClientHelloStub(long frameNo) {
        byte[] payload = buildSyntheticTlsClientHello(SIM_HOST);
        byte[] raw = makeEthernetIpv4TcpPacket(payload, SIM_CLIENT_PORT, SIM_TLS_PORT);
        return new PcapPacketStub(frameNo, raw, Instant.now(), raw.length, raw.length);
    }

    public static byte[] makeEthernetIpv4TcpPacket(byte[] payload, int sport, int dport) {
        byte[] eth = new byte[14];
        eth[6] = 0x00;
        eth[7] = 0x11;
        eth[8] = 0x22;
        eth[9] = 0x33;
        eth[10] = 0x44;
        eth[11] = 0x55;
        eth[12] = 0x08;
        eth[13] = 0x00;
        byte[] ip = new byte[20];
        ip[0] = 0x45;
        ip[1] = 0x00;
        int totalLen = ip.length + 20 + payload.length;
        ip[2] = (byte) ((totalLen >> 8) & 0xff);
        ip[3] = (byte) (totalLen & 0xff);
        ip[8] = 64;
        ip[9] = 6;
        ip[12] = (byte) 192;
        ip[13] = (byte) 168;
        ip[14] = 0;
        ip[15] = 2;
        ip[16] = (byte) 142;
        ip[17] = (byte) 250;
        ip[18] = (byte) 193;
        ip[19] = (byte) 110;
        byte[] tcp = new byte[20];
        tcp[0] = (byte) ((sport >> 8) & 0xff);
        tcp[1] = (byte) (sport & 0xff);
        tcp[2] = (byte) ((dport >> 8) & 0xff);
        tcp[3] = (byte) (dport & 0xff);
        tcp[12] = 0x50;
        tcp[13] = 0x18;
        tcp[14] = 0x00;
        tcp[15] = 0x64;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            baos.write(eth);
            baos.write(ip);
            baos.write(tcp);
            baos.write(payload);
        } catch (IOException ignored) {
        }
        return baos.toByteArray();
    }

    public static byte[] makeEthernetIpv4UdpPacket(byte[] payload, int sport, int dport) {
        byte[] eth = new byte[14];
        eth[6] = 0x00;
        eth[7] = 0x11;
        eth[8] = 0x22;
        eth[9] = 0x33;
        eth[10] = 0x44;
        eth[11] = 0x55;
        eth[12] = 0x08;
        eth[13] = 0x00;
        byte[] ip = new byte[20];
        ip[0] = 0x45;
        ip[1] = 0x00;
        int totalLen = ip.length + 8 + payload.length;
        ip[2] = (byte) ((totalLen >> 8) & 0xff);
        ip[3] = (byte) (totalLen & 0xff);
        ip[8] = 64;
        ip[9] = 17;
        ip[12] = (byte) 192;
        ip[13] = (byte) 168;
        ip[14] = 0;
        ip[15] = 2;
        ip[16] = (byte) 8;
        ip[17] = (byte) 8;
        ip[18] = 8;
        ip[19] = 8;
        byte[] udp = new byte[8];
        udp[0] = (byte) ((sport >> 8) & 0xff);
        udp[1] = (byte) (sport & 0xff);
        udp[2] = (byte) ((dport >> 8) & 0xff);
        udp[3] = (byte) (dport & 0xff);
        udp[4] = (byte) (((8 + payload.length) >> 8) & 0xff);
        udp[5] = (byte) ((8 + payload.length) & 0xff);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            baos.write(eth);
            baos.write(ip);
            baos.write(udp);
            baos.write(payload);
        } catch (IOException ignored) {
        }
        return baos.toByteArray();
    }

    public static byte[] buildSyntheticDnsQuery(String qname) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(0x12);
        b.write(0x34);
        b.write(0x01);
        b.write(0x00);
        b.write(0x00);
        b.write(0x01);
        b.write(0x00);
        b.write(0x00);
        b.write(0x00);
        b.write(0x00);
        b.write(0x00);
        b.write(0x00);
        for (String label : qname.split("\\.")) {
            b.write(label.length());
            try {
                b.write(label.getBytes(StandardCharsets.US_ASCII));
            } catch (IOException ignored) {
            }
        }
        b.write(0x00);
        b.write(0x00);
        b.write(0x01);
        b.write(0x00);
        b.write(0x01);
        return b.toByteArray();
    }

    public static byte[] buildSyntheticTlsClientHello(String sni) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        try {
            b.write(0x16);
            b.write(0x03);
            b.write(0x03);
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            body.write(0x01);
            ByteArrayOutputStream hello = new ByteArrayOutputStream();
            hello.write(0x03);
            hello.write(0x03);
            for (int i = 0; i < 32; i++) hello.write(0);
            hello.write(0);
            hello.write(0x00);
            hello.write(0x02);
            hello.write(0x00);
            hello.write(0x2f);
            hello.write(0x01);
            hello.write(0x00);
            byte[] host = sni.getBytes(StandardCharsets.US_ASCII);
            ByteArrayOutputStream sniExt = new ByteArrayOutputStream();
            sniExt.write(0x00);
            sniExt.write(0x00);
            sniExt.write((byte) (((host.length + 5) >> 8) & 0xff));
            sniExt.write((byte) ((host.length + 5) & 0xff));
            sniExt.write(0x00);
            sniExt.write((byte) (((host.length + 3) >> 8) & 0xff));
            sniExt.write((byte) ((host.length + 3) & 0xff));
            sniExt.write(0x00);
            sniExt.write((byte) ((host.length >> 8) & 0xff));
            sniExt.write((byte) (host.length & 0xff));
            sniExt.write(host);
            byte[] ext = sniExt.toByteArray();
            hello.write((byte) ((ext.length >> 8) & 0xff));
            hello.write((byte) (ext.length & 0xff));
            hello.write(ext);
            byte[] hBytes = hello.toByteArray();
            body.write((byte) ((hBytes.length >> 16) & 0xff));
            body.write((byte) ((hBytes.length >> 8) & 0xff));
            body.write((byte) (hBytes.length & 0xff));
            body.write(hBytes);
            byte[] bodyBytes = body.toByteArray();
            b.write((byte) ((bodyBytes.length >> 8) & 0xff));
            b.write((byte) (bodyBytes.length & 0xff));
            b.write(bodyBytes);
        } catch (IOException ignored) {
        }
        return b.toByteArray();
    }
}

