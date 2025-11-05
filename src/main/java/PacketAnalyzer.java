/*
 * Concurrent Network Packet Analyzer
 * -----------------------------------
 * • Java 21 (Virtual Threads)
 * • Structured Batch Execution
 * • Ethernet / IPv4 / TCP / UDP / HTTP / DNS / TLS (SNI)
 * • Tab-separated Wireshark-style output
 * • Optional file logging
 *
 * Example usage:
 * mvn package
 * sudo java -jar target/packet-analyzer-1.0-SNAPSHOT.jar wlan0 30 HTTP,DNS,TLS output.txt
 *
 * Simulated mode (no root required):
 * java -jar target/packet-analyzer-1.0-SNAPSHOT.jar sim 5 HTTP,DNS,TLS
 */

import org.pcap4j.core.*;

import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

public class PacketAnalyzer {

    // ============================================================
    // MAIN ENTRY
    // ============================================================
    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("Usage: sudo java -jar packet-analyzer.jar <iface|sim> <durationSec> <protocolsCSV> [outputFile]");
            System.err.println("Example: sudo java -jar packet-analyzer.jar wlan0 30 HTTP,DNS,TLS output.txt");
            System.exit(1);
        }

        String iface = args[0];
        int durationSec = Integer.parseInt(args[1]);
        Set<String> protocols = Arrays.stream(args[2].split(","))
                .map(String::trim).map(String::toUpperCase).collect(Collectors.toSet());
        String outFile = args.length >= 4 ? args[3] : null;

        Config cfg = new Config(iface, durationSec, protocols, outFile);
        new PacketAnalyzerApp(cfg).run();
    }

    // ============================================================
    // CAPTURE SERVICE
    // ============================================================
    public interface CaptureService extends AutoCloseable {
        void startCapture(PacketHandler handler, int maxSeconds) throws Exception;
    }

    public interface PacketHandler {
        boolean handle(PcapPacketStub packet);
    }

    // ============================================================
    // LAYER PARSERS
    // ============================================================
    public interface LayerParser {
        void parse(PacketContext ctx);
    }

    public interface ApplicationParser {
        boolean canParse(PacketContext ctx, TransportInfo t);

        Map<String, String> parse(PacketContext ctx, TransportInfo t);
    }

    // ============================================================
    // OUTPUT FORMATTER
    // ============================================================
    public interface PacketFormatter {
        List<String> format(PacketContext ctx);
    }

    // ============================================================
    //OUTPUT WRITERS
    // ============================================================
    public interface OutputWriter {
        void writeRows(List<String> rows);
    }

    // ============================================================
    //CONFIGURATION
    // ============================================================
    public record Config(String iface, int durationSec, Set<String> protocols, String outFile) {
    }

    // ============================================================
    //APPLICATION
    // ============================================================
    public static final class PacketAnalyzerApp {
        private final Config cfg;
        private final CaptureService capture;
        private final PacketProcessor processor;
        private final StructuredBatchExecutor executor;

        public PacketAnalyzerApp(Config cfg) {
            this.cfg = cfg;
            CaptureService cs;
            if ("sim".equalsIgnoreCase(cfg.iface())) {
                cs = new SimulatedCaptureService();
            } else {
                try {
                    cs = new PcapCaptureService(cfg.iface());
                    System.out.println("✅ Live capture on: " + cfg.iface());
                } catch (Throwable t) {
                    System.err.println("⚠ Live capture init failed: " + t.getMessage());
                    System.err.println("🧪 Falling back to simulated capture");
                    cs = new SimulatedCaptureService();
                }
            }

            this.capture = cs;
            OutputWriter writer = (cfg.outFile() != null) ? new FileOutputWriter(cfg.outFile()) : new ConsoleOutputWriter();

            List<LayerParser> parsers = List.of(
                    new FrameParser(),
                    new LinkParser(),
                    new NetworkParser(),
                    new TransportParser()
            );

            this.processor = new PacketProcessor(parsers, new TabRowPacketFormatter(), writer, cfg.protocols());
            this.executor = new StructuredBatchExecutor(Executors.newVirtualThreadPerTaskExecutor());
        }

        public void run() throws Exception {
            System.out.printf("📡 Capturing for %ds, protocols=%s%n", cfg.durationSec(), cfg.protocols());
            AtomicLong count = new AtomicLong(0);
            long deadline = System.currentTimeMillis() + cfg.durationSec() * 1000L;

            try (capture) {
                capture.startCapture(packet -> {
                    if (System.currentTimeMillis() > deadline) return false;
                    long n = count.incrementAndGet();
                    executor.submitBatchTask(() -> {
                        processor.process(packet, n);
                        return Boolean.TRUE;
                    });
                    return true;
                }, cfg.durationSec());
            } finally {
                executor.shutdownAndAwait();
                System.out.printf("✅ Total packets processed: %d%n", count.get());
            }
        }
    }

    // -------- Live pcap ----------
    public static final class PcapCaptureService implements CaptureService {
        private final PcapHandle handle;
        private final AtomicLong frameCounter = new AtomicLong(0);

        public PcapCaptureService(String iface) throws PcapNativeException {
            PcapNetworkInterface nif = Pcaps.getDevByName(iface);
            if (nif == null) throw new PcapNativeException("Interface not found: " + iface);
            this.handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 50);
        }

        @Override
        public void startCapture(PacketHandler handler, int maxSeconds) throws Exception {
            PacketListener pl = pcapPacket -> {
                long frameNo = frameCounter.incrementAndGet();
                byte[] raw = pcapPacket.getRawData();
                PcapPacketStub stub = new PcapPacketStub(frameNo, raw, pcapPacket.getTimestamp(), raw.length, raw.length);
                if (!handler.handle(stub)) {
                    try {
                        handle.breakLoop();
                    } catch (NotOpenException ignored) {
                    }
                }
            };
            try {
                handle.loop(-1, pl);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        @Override
        public void close() {
            if (handle != null && handle.isOpen()) handle.close();
        }
    }

    // -------- Simulated mode ----------
    public static final class SimulatedCaptureService implements CaptureService {
        private volatile boolean closed = false;

        // Minimal synthetic helpers (Ethernet+IPv4+TCP/UDP + payload)
        private static byte[] makeEthernetIpv4TcpPacket(byte[] payload, int sport, int dport) {
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

        private static byte[] makeEthernetIpv4UdpPacket(byte[] payload, int sport, int dport) {
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

        private static byte[] buildSyntheticDnsQuery(String qname) {
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

        private static byte[] buildSyntheticTlsClientHello(String sni) {
            // Minimal fake TLS ClientHello with SNI (simplified)
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
                sniExt.write((byte) ((host.length + 5) >> 8));
                sniExt.write((byte) ((host.length + 5) & 0xff));
                sniExt.write(0x00);
                sniExt.write((byte) ((host.length + 3) >> 8));
                sniExt.write((byte) ((host.length + 3) & 0xff));
                sniExt.write(0x00);
                sniExt.write((byte) ((host.length) >> 8));
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

        @Override
        public void startCapture(PacketHandler handler, int maxSeconds) {
            byte[] httpPayload = ("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
            byte[] dnsPayload = buildSyntheticDnsQuery("example.com");
            byte[] tlsPayload = buildSyntheticTlsClientHello("example.com");

            int total = Math.max(1, maxSeconds * 5);
            for (int i = 0; i < total && !closed; i++) {
                byte[] raw;
                if (i % 3 == 0) raw = makeEthernetIpv4TcpPacket(httpPayload, 12345, 80);
                else if (i % 3 == 1) raw = makeEthernetIpv4UdpPacket(dnsPayload, 51322, 53);
                else raw = makeEthernetIpv4TcpPacket(tlsPayload, 51322, 443);

                PcapPacketStub stub = new PcapPacketStub(i + 1, raw, Instant.now(), raw.length, raw.length);
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

    // ============================================================
    // PCAP PACKET STUB
    // ============================================================
    public static final class PcapPacketStub {
        public final long frameNo;
        public final byte[] raw;
        public final Instant ts;
        public final int origLen;
        public final int capLen;

        public PcapPacketStub(long frameNo, byte[] raw, Instant ts, int origLen, int capLen) {
            this.frameNo = frameNo;
            this.raw = raw;
            this.ts = ts;
            this.origLen = origLen;
            this.capLen = capLen;
        }
    }

    // ============================================================
    // STRUCTURED BATCH EXECUTOR (Virtual Threads)
    // ============================================================
    public static final class StructuredBatchExecutor {
        private final ExecutorService executor;
        private final List<Callable<Boolean>> queue = Collections.synchronizedList(new ArrayList<>());

        public StructuredBatchExecutor(ExecutorService executor) {
            this.executor = executor;
        }

        public void submitBatchTask(Callable<Boolean> task) {
            queue.add(task);
            if (queue.size() >= 50) flush();
        }

        public void shutdownAndAwait() {
            flush();
            executor.shutdown();
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) executor.shutdownNow();
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        private void flush() {
            List<Callable<Boolean>> batch;
            synchronized (queue) {
                if (queue.isEmpty()) return;
                batch = new ArrayList<>(queue);
                queue.clear();
            }
            List<Future<Boolean>> futures = new ArrayList<>();
            for (Callable<Boolean> c : batch) futures.add(executor.submit(c));
            for (Future<Boolean> f : futures) {
                try {
                    f.get();
                } catch (Exception e) {
                    futures.forEach(x -> {
                        if (!x.isDone()) x.cancel(true);
                    });
                    break;
                }
            }
        }
    }

    // ============================================================
    //PROCESSOR PIPELINE
    // ============================================================
    public static final class PacketProcessor {
        private final List<LayerParser> parsers;
        private final PacketFormatter formatter;
        private final OutputWriter writer;
        private final Set<String> filter;

        public PacketProcessor(List<LayerParser> parsers, PacketFormatter formatter, OutputWriter writer, Set<String> filter) {
            this.parsers = parsers;
            this.formatter = formatter;
            this.writer = writer;
            this.filter = filter;
        }

        public void process(PcapPacketStub pkt, long seq) {
            PacketContext ctx = new PacketContext(seq, pkt);
            for (LayerParser p : parsers) p.parse(ctx);
            if (!filter.isEmpty() && !ctx.matchesAny(filter)) return;
            writer.writeRows(formatter.format(ctx));
        }
    }

    // ============================================================
    // PARSING CONTEXT
    // ============================================================
    public static final class PacketContext {
        public final long seq;
        public final PcapPacketStub pkt;
        public final Map<String, Map<String, String>> layers = new LinkedHashMap<>();

        public PacketContext(long seq, PcapPacketStub pkt) {
            this.seq = seq;
            this.pkt = pkt;
        }

        public void putLayer(String name, Map<String, String> fields) {
            layers.put(name, fields);
        }

        public boolean matchesAny(Set<String> protocols) {
            for (Map<String, String> m : layers.values())
                for (String v : m.values())
                    if (v != null && protocols.contains(v.toUpperCase())) return true;
            return false;
        }
    }

    // ---------- Frame ----------
    public static final class FrameParser implements LayerParser {
        private static final DateTimeFormatter ISO = DateTimeFormatter.ISO_INSTANT;

        public void parse(PacketContext ctx) {
            Map<String, String> m = new LinkedHashMap<>();
            m.put("FrameNo", String.valueOf(ctx.seq));
            m.put("Len", String.valueOf(ctx.pkt.origLen));
            m.put("CapLen", String.valueOf(ctx.pkt.capLen));
            m.put("WireBits", String.valueOf(ctx.pkt.origLen * 8));
            m.put("Timestamp", ISO.format(ctx.pkt.ts.atZone(ZoneOffset.UTC)));
            ctx.putLayer("FRAME", m);
        }
    }

    // ---------- Link ----------
    public static final class LinkParser implements LayerParser {
        private static String mac(byte[] b, int off) {
            if (b.length < off + 6) return "-";
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 6; i++) {
                if (i > 0) sb.append(":");
                sb.append(String.format("%02x", b[off + i]));
            }
            return sb.toString();
        }

        public void parse(PacketContext ctx) {
            byte[] r = ctx.pkt.raw;
            Map<String, String> m = new LinkedHashMap<>();
            if (r.length >= 14) {
                m.put("DstMAC", mac(r, 0));
                m.put("SrcMAC", mac(r, 6));
                int ethType = ((r[12] & 0xff) << 8) | (r[13] & 0xff);
                m.put("EtherType", String.format("0x%04x", ethType));
            } else {
                m.put("DstMAC", "-");
                m.put("SrcMAC", "-");
                m.put("EtherType", "-");
            }
            ctx.putLayer("LINK", m);
        }
    }

    // ---------- Network ----------
    public static final class NetworkParser implements LayerParser {
        public void parse(PacketContext ctx) {
            byte[] r = ctx.pkt.raw;
            Map<String, String> m = new LinkedHashMap<>();
            if (r.length >= 34) {
                int ipStart = 14;
                String src = String.format("%d.%d.%d.%d", r[ipStart + 12] & 0xff, r[ipStart + 13] & 0xff, r[ipStart + 14] & 0xff, r[ipStart + 15] & 0xff);
                String dst = String.format("%d.%d.%d.%d", r[ipStart + 16] & 0xff, r[ipStart + 17] & 0xff, r[ipStart + 18] & 0xff, r[ipStart + 19] & 0xff);
                m.put("SrcIP", src);
                m.put("DstIP", dst);
                m.put("TTL", String.valueOf(r[ipStart + 8] & 0xff));
                m.put("Proto", String.valueOf(r[ipStart + 9] & 0xff));
                int totLen = ((r[ipStart + 2] & 0xff) << 8) | (r[ipStart + 3] & 0xff);
                m.put("TotLen", String.valueOf(totLen));
                m.put("IHL", String.valueOf((r[ipStart] & 0x0f) * 4));
            } else {
                m.put("SrcIP", "-");
                m.put("DstIP", "-");
                m.put("TTL", "-");
                m.put("Proto", "-");
                m.put("TotLen", "-");
                m.put("IHL", "-");
            }
            ctx.putLayer("NETWORK", m);
        }
    }

    // ---------- Transport ----------
    public static final class TransportParser implements LayerParser {
        public void parse(PacketContext ctx) {
            byte[] r = ctx.pkt.raw;
            Map<String, String> m = new LinkedHashMap<>();
            if (r.length >= 34) {
                int ipStart = 14;
                int ihl = (r[ipStart] & 0x0f) * 4;
                int proto = r[ipStart + 9] & 0xff;
                int tStart = ipStart + ihl;
                int sport = ((r[tStart] & 0xff) << 8) | (r[tStart + 1] & 0xff);
                int dport = ((r[tStart + 2] & 0xff) << 8) | (r[tStart + 3] & 0xff);
                m.put("SrcPort", String.valueOf(sport));
                m.put("DstPort", String.valueOf(dport));
                m.put("Proto", proto == 6 ? "TCP" : proto == 17 ? "UDP" : String.valueOf(proto));
                int payloadLen = Math.max(0, r.length - (tStart + (proto == 6 ? 20 : 8)));
                m.put("PayloadLen", String.valueOf(payloadLen));
                m.put("Flags", proto == 6 ? String.format("0x%02x", r[tStart + 13] & 0xff) : "-");
                ctx.putLayer("TRANSPORT", m);
                ctx.putLayer("APP", ApplicationParserRegistry.parse(ctx, new TransportInfo(sport, dport, proto)));
            } else {
                ctx.putLayer("TRANSPORT", Map.of("SrcPort", "-", "DstPort", "-", "Proto", "-", "PayloadLen", "-", "Flags", "-"));
                ctx.putLayer("APP", Map.of("AppProto", "-"));
            }
        }
    }

    // ============================================================
    // APPLICATION PARSER REGISTRY
    // ============================================================
    public static record TransportInfo(int sport, int dport, int proto) {
    }

    public static final class ApplicationParserRegistry {
        private static final List<ApplicationParser> PARSERS = List.of(
                new HttpParser(),
                new DnsParser(),
                new TlsParser()
        );

        public static Map<String, String> parse(PacketContext ctx, TransportInfo t) {
            for (ApplicationParser p : PARSERS)
                if (p.canParse(ctx, t)) return p.parse(ctx, t);
            return Map.of("AppProto", "-");
        }
    }

    // ---------- HTTP ----------
    public static final class HttpParser implements ApplicationParser {
        public boolean canParse(PacketContext ctx, TransportInfo t) {
            if (t.proto != 6) return false;
            int port = t.dport != 0 ? t.dport : t.sport;
            if (port != 80 && port != 8080 && port != 443) return false;
            String s = new String(ctx.pkt.raw, StandardCharsets.US_ASCII);
            return s.startsWith("GET") || s.startsWith("POST") || s.contains("HTTP/");
        }

        public Map<String, String> parse(PacketContext ctx, TransportInfo t) {
            Map<String, String> m = new LinkedHashMap<>();
            String ascii = new String(ctx.pkt.raw, StandardCharsets.US_ASCII);
            int idx = ascii.indexOf("\r\n");
            m.put("AppProto", "HTTP");
            m.put("FirstLine", idx > 0 ? ascii.substring(0, idx) : ascii);
            return m;
        }
    }

    // ---------- DNS ----------
    public static final class DnsParser implements ApplicationParser {
        public boolean canParse(PacketContext ctx, TransportInfo t) {
            if (t.proto != 17) return false;
            return (t.sport == 53 || t.dport == 53) && ctx.pkt.raw.length >= 42;
        }

        public Map<String, String> parse(PacketContext ctx, TransportInfo t) {
            Map<String, String> m = new LinkedHashMap<>();
            byte[] r = ctx.pkt.raw;
            int ipStart = 14;
            int ihl = (r[ipStart] & 0x0f) * 4;
            int udpStart = ipStart + ihl;
            int dnsStart = udpStart + 8;
            int id = ((r[dnsStart] & 0xff) << 8) | (r[dnsStart + 1] & 0xff);
            int flags = ((r[dnsStart + 2] & 0xff) << 8) | (r[dnsStart + 3] & 0xff);
            int qd = ((r[dnsStart + 4] & 0xff) << 8) | (r[dnsStart + 5] & 0xff);
            int an = ((r[dnsStart + 6] & 0xff) << 8) | (r[dnsStart + 7] & 0xff);
            m.put("AppProto", "DNS");
            m.put("ID", String.format("0x%04x", id));
            m.put("Flags", String.format("0x%04x", flags));
            m.put("QD", String.valueOf(qd));
            m.put("AN", String.valueOf(an));
            try {
                int pos = dnsStart + 12;
                StringBuilder qname = new StringBuilder();
                while (pos < r.length) {
                    int len = r[pos++] & 0xff;
                    if (len == 0) break;
                    if (qname.length() > 0) qname.append('.');
                    for (int i = 0; i < len; i++) qname.append((char) r[pos++]);
                }
                m.put("QNAME", qname.toString());
            } catch (Exception e) {
                m.put("QNAME", "?");
            }
            return m;
        }
    }

    // ---------- TLS (SNI) ----------
    public static final class TlsParser implements ApplicationParser {
        public boolean canParse(PacketContext ctx, TransportInfo t) {
            if (t.proto != 6) return false;
            int port = t.dport != 0 ? t.dport : t.sport;
            return port == 443 && ctx.pkt.raw.length > 60 && ctx.pkt.raw[54] == 0x16;
        }

        public Map<String, String> parse(PacketContext ctx, TransportInfo t) {
            Map<String, String> m = new LinkedHashMap<>();
            m.put("AppProto", "TLS");
            try {
                byte[] r = ctx.pkt.raw;
                int ipStart = 14;
                int ihl = (r[ipStart] & 0x0f) * 4;
                int tStart = ipStart + ihl;
                int tlsStart = tStart + 20;
                int pos = tlsStart + 43;
                int extLen = ((r[pos] & 0xff) << 8) | (r[pos + 1] & 0xff);
                pos += 2;
                int extEnd = pos + extLen;
                while (pos + 4 < extEnd) {
                    int type = ((r[pos] & 0xff) << 8) | (r[pos + 1] & 0xff);
                    int len = ((r[pos + 2] & 0xff) << 8) | (r[pos + 3] & 0xff);
                    pos += 4;
                    if (type == 0x00) {
                        int sniLen = ((r[pos + 5] & 0xff) << 8) | (r[pos + 6] & 0xff);
                        String sni = new String(r, pos + 7, sniLen, StandardCharsets.US_ASCII);
                        m.put("SNI", sni);
                        return m;
                    }
                    pos += len;
                }
            } catch (Exception e) {
                m.put("SNI", "?");
            }
            return m;
        }
    }

    public static final class TabRowPacketFormatter implements PacketFormatter {
        public List<String> format(PacketContext ctx) {
            List<String> rows = new ArrayList<>();
            for (Map.Entry<String, Map<String, String>> e : ctx.layers.entrySet()) {
                String row = e.getKey() + "\t" +
                        e.getValue().entrySet().stream()
                                .map(x -> x.getKey() + "=" + x.getValue())
                                .collect(Collectors.joining("\t"));
                rows.add(row);
            }
            rows.add("----");
            return rows;
        }
    }

    public static final class ConsoleOutputWriter implements OutputWriter {
        public void writeRows(List<String> rows) {
            rows.forEach(System.out::println);
        }
    }

    public static final class FileOutputWriter implements OutputWriter {
        private final PrintWriter out;

        public FileOutputWriter(String path) {
            try {
                this.out = new PrintWriter(new FileWriter(path, true));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        public synchronized void writeRows(List<String> rows) {
            for (String r : rows) out.println(r);
            out.flush();
        }
    }
}