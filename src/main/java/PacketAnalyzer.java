/*
 * Concurrent Network Packet Analyzer
 * -----------------------------------
 * • Java 21 (Virtual Threads)
 * • Structured Batch Execution
 * • Ethernet / IPv4 / TCP / UDP / HTTP / DNS / TLS (SNI)
 * • Tab-separated Wireshark-style output
 * • Logs to console AND "packet_analysis_log.txt" simultaneously
 * • Program automatically terminates after specified duration.
 *
 * Example usage:
 * mvn package
 * sudo java -jar target/packet-analyzer-1.0-SNAPSHOT.jar
 *
 * Simulated mode (no root required):
 * java -jar target/packet-analyzer-1.0-SNAPSHOT.jar
 * (Then enter 'sim' for interface)
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
        String ifaceName = null;
        String usedNetwork = null;
        int durationSec = 0;
        String protocolsCSV = null;
        // HARDCODED OUTPUT FILE: All filtered output goes here.
        final String OUTPUT_FILE = "packet_analysis_log.txt";
        Scanner scanner = new Scanner(System.in);

        try {
            // 1. Interface Selection (Interactive with Filtering/Suggestion)
            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            List<PcapNetworkInterface> activeDevs = allDevs.stream()
                    .filter(dev -> !dev.getName().toLowerCase().contains("wan miniport") && !dev.getName().toLowerCase().contains("loopback"))
                    .collect(Collectors.toList());

            if (activeDevs.isEmpty()) {
                System.err.println("⚠️ No active network interfaces found. Forcing simulated capture mode ('sim').");
                usedNetwork = "SIMULATED";
                ifaceName = "sim";
            } else {
                PcapNetworkInterface suggestedDev = activeDevs.get(0);
                String suggestedIndex = String.valueOf(allDevs.indexOf(suggestedDev) + 1);

                System.out.println("\n🌐 Available Network Interfaces (requires Administrator privileges for capture):");
                for (int i = 0; i < allDevs.size(); i++) {
                    PcapNetworkInterface dev = allDevs.get(i);
                    String desc = dev.getDescription() != null ? dev.getDescription() : "No description";
                    String marker = activeDevs.contains(dev) ? "✨" : " -";
                    System.out.printf("  [%d]%s %s (%s)%n", i + 1, marker, dev.getName(), desc);
                }

                System.out.printf("\n-> Enter the **number** of the interface to capture on (Suggestion: %s), or 'sim' for simulation: ", suggestedIndex);
                String selection = scanner.nextLine().trim();

                if ("sim".equalsIgnoreCase(selection)) {
                    usedNetwork = "SIMULATED";
                    ifaceName = "sim";
                } else {
                    int index = Integer.parseInt(selection) - 1;
                    if (index >= 0 && index < allDevs.size()) {
                        PcapNetworkInterface selectedDev = allDevs.get(index);
                        ifaceName = selectedDev.getName();
                        usedNetwork = selectedDev.getDescription() != null ? selectedDev.getDescription() : selectedDev.getName();
                    } else {
                        System.err.println("❌ Invalid interface selection. Exiting.");
                        System.exit(1);
                    }
                }
            }

            // 2. Duration Input
            System.out.print("-> Enter capture duration in seconds (e.g., 10): ");
            durationSec = Integer.parseInt(scanner.nextLine().trim());
            if (durationSec <= 0) {
                System.err.println("❌ Duration must be a positive number. Exiting.");
                System.exit(1);
            }

            // 3. Protocols Input
            System.out.print("-> Enter protocols to capture (e.g., HTTP,DNS,HTTPS, or ALL): ");
            protocolsCSV = scanner.nextLine().trim();
            if (protocolsCSV.isEmpty()) protocolsCSV = "ALL"; // Default to ALL if empty

        } catch (PcapNativeException e) {
            System.err.println("❌ Failed to list interfaces (PcapNativeException). Forcing simulation.");
            usedNetwork = "SIMULATED";
            ifaceName = "sim";
            durationSec = 10;
        } catch (NumberFormatException e) {
            System.err.println("❌ Invalid number input. Exiting.");
            System.exit(1);
        } finally {
            scanner.close();
        }

        // --- CONFIGURATION & RUN ---
        Set<String> protocols = Arrays.stream(protocolsCSV.split(","))
                .map(String::trim).map(String::toUpperCase).collect(Collectors.toSet());

        // Map 'TLS' to 'HTTPS' for consistency with parser output
        if (protocols.contains("TLS")) {
            protocols.remove("TLS");
            protocols.add("HTTPS");
        }

        System.out.printf("✅ Protocols selected: %s (Output logged to console AND %s)%n", protocols, OUTPUT_FILE);
        Config cfg = new Config(ifaceName, usedNetwork, durationSec, protocols, OUTPUT_FILE);
        new PacketAnalyzerApp(cfg).run();
    }

    // ============================================================
    // CAPTURE SERVICE
    // ============================================================
    public interface CaptureService extends AutoCloseable {
        void startCapture(PacketHandler handler, int maxSeconds) throws Exception;
    }

    public interface PacketHandler {
        /**
         * @return true to continue capture, false to terminate.
         */
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
    public interface OutputWriter extends AutoCloseable {
        void writeRows(List<String> rows);
    }

    // ============================================================
    //CONFIGURATION
    // ============================================================
    public record Config(String iface, String usedNetwork, int durationSec, Set<String> protocols, String outFile) {
    }

    // ============================================================
    //APPLICATION
    // ============================================================
    public static final class PacketAnalyzerApp {
        private final Config cfg;
        private final CaptureService capture;
        private final PacketProcessor processor;
        private final StructuredBatchExecutor executor;
        private final ConsoleOutputAccumulator consoleAccumulator;
        private final FileOutputWriter fileWriter; // Added as a field for try-with-resources

        public PacketAnalyzerApp(Config cfg) {
            this.cfg = cfg;
            CaptureService cs;
            if ("sim".equalsIgnoreCase(cfg.iface())) {
                cs = new SimulatedCaptureService();
            } else {
                try {
                    cs = new PcapCaptureService(cfg.iface());
                    System.out.println("✅ Live capture on: " + cfg.usedNetwork());
                } catch (Throwable t) {
                    System.err.println("⚠ Live capture init failed: " + t.getMessage());
                    System.err.println("🧪 Falling back to simulated capture");
                    cs = new SimulatedCaptureService();
                }
            }

            this.capture = cs;
            this.consoleAccumulator = new ConsoleOutputAccumulator();
            this.fileWriter = new FileOutputWriter(cfg.outFile());

            List<LayerParser> parsers = List.of(
                    new FrameParser(cfg.usedNetwork()),
                    new LinkParser(),
                    new NetworkParser(),
                    new TransportParser()
            );

            this.processor = new PacketProcessor(parsers, new TabRowPacketFormatter(), consoleAccumulator, fileWriter, cfg.protocols());
            this.executor = new StructuredBatchExecutor(Executors.newVirtualThreadPerTaskExecutor());
        }

        public void run() throws Exception {
            System.out.printf("📡 Capturing for %ds, protocols=%s%n", cfg.durationSec(), cfg.protocols());
            AtomicLong count = new AtomicLong(0);
            long start = System.currentTimeMillis();
            long deadline = start + cfg.durationSec() * 1000L;

            // Use a separate executor for the blocking capture task
            ExecutorService captureExecutor = Executors.newSingleThreadExecutor();

            // All closeable resources are handled here.
            try (CaptureService cap = capture; FileOutputWriter fw = fileWriter) {
                // Submit the capture task
                Future<Void> captureFuture = captureExecutor.submit(() -> {
                    try {
                        capture.startCapture(packet -> {
                            // **TERMINATION LOGIC**: Check if the deadline has passed.
                            if (System.currentTimeMillis() > deadline) return false;

                            long n = count.incrementAndGet();
                            executor.submitBatchTask(() -> {
                                processor.process(packet, n);
                                return Boolean.TRUE;
                            });
                            return true;
                        }, cfg.durationSec());
                        return null;
                    } catch (Exception e) {
                        System.err.println("\n❌ Capture failed: " + e.getMessage());
                        return null;
                    }
                });

                // Main thread runs the countdown timer
                while (!captureFuture.isDone()) {
                    long remainingSec = (deadline - System.currentTimeMillis() + 999) / 1000;
                    if (remainingSec < 0) remainingSec = 0;

                    // Use \r to return to the start of the line, creating a "live" countdown
                    System.out.printf("\r⏳ Time Remaining: %d seconds. Packets processed: %d", remainingSec, count.get());

                    if (remainingSec == 0) break;

                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }

                // Newline after countdown
                System.out.println();

                // FIX: Use a timed get() to ensure the program doesn't hang waiting for the native capture thread.
                try {
                    // Wait for capture thread to stop (duration + 2 seconds grace period)
                    captureFuture.get(cfg.durationSec() + 2, TimeUnit.SECONDS);
                } catch (TimeoutException e) {
                    System.err.println("⚠ Capture thread timed out during termination, forcing shutdown.");
                    captureFuture.cancel(true);
                }

            } finally {
                // **CLEANUP AND TERMINATION**: Shut down all executors.
                captureExecutor.shutdownNow();
                executor.shutdownAndAwait();

                // Print the accumulated console output here
                consoleAccumulator.printFinalReport(count.get());

                // Program terminates cleanly after this block closes all resources.
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
            // Open live handle with a timeout (read timeout is secondary to the application's deadline)
            this.handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 50);
        }

        @Override
        public void startCapture(PacketHandler handler, int maxSeconds) throws Exception {
            PacketListener pl = packet -> {
                long frameNo = frameCounter.incrementAndGet();
                byte[] raw = packet.getRawData();
                Instant timestamp = Instant.ofEpochMilli(handle.getTimestamp().getTime());

                PcapPacketStub stub = new PcapPacketStub(
                        frameNo,
                        raw,
                        timestamp,
                        raw.length,
                        raw.length
                );

                if (!handler.handle(stub)) {
                    // **TERMINATION**: Called when handler.handle() returns false (time's up)
                    try {
                        handle.breakLoop();
                    } catch (NotOpenException ignored) { }
                }
            };

            try {
                // Loop indefinitely (-1) until handle.breakLoop() is called
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
    /**
     * Simulates packet capture, generating synthetic packets for HTTP (Port 80), DNS (Port 53),
     * and TLS (Port 443/HTTPS) destined for external servers.
     * The packets simulate outbound traffic from a client (192.168.0.2) to servers.
     * This simulates the client as the **transmitting** network and the servers as the **receiving** network.
     */
    public static final class SimulatedCaptureService implements CaptureService {
        private volatile boolean closed = false;

        // Configuration Constants for Simulation
        private static final String SIM_HOST = "example.com";
        private static final String CLIENT_IP = "192.168.0.2";
        private static final String HTTP_SERVER_IP = "142.250.193.110"; // A common public IP
        private static final String DNS_SERVER_IP = "8.8.8.8"; // Google DNS
        private static final int SIM_CLIENT_PORT = 51322; // High ephemeral client port
        private static final int SIM_HTTP_PORT = 80;
        private static final int SIM_DNS_PORT = 53;
        private static final int SIM_TLS_PORT = 443;

        // Minimal synthetic helpers (Ethernet+IPv4+TCP/UDP + payload)
        private static byte[] makeEthernetIpv4TcpPacket(byte[] payload, int sport, int dport, String srcIp, String dstIp) {
            byte[] eth = new byte[14];
            // Source MAC (00:11:22:33:44:55)
            eth[6] = 0x00;
            eth[7] = 0x11;
            eth[8] = 0x22;
            eth[9] = 0x33;
            eth[10] = 0x44;
            eth[11] = 0x55;
            // EtherType (IPv4)
            eth[12] = 0x08;
            eth[13] = 0x00;

            byte[] ip = new byte[20];
            // Version (4) + IHL (5 words) = 0x45
            ip[0] = 0x45;
            ip[1] = 0x00; // DSCP/ECN
            int totalLen = ip.length + 20 + payload.length; // IP Header (20) + TCP Header (20) + Payload
            ip[2] = (byte) ((totalLen >> 8) & 0xff);
            ip[3] = (byte) (totalLen & 0xff);
            ip[8] = 64; // TTL
            ip[9] = 6; // Protocol (TCP=6)

            // IP addresses
            String[] srcParts = srcIp.split("\\.");
            ip[12] = (byte) Integer.parseInt(srcParts[0]);
            ip[13] = (byte) Integer.parseInt(srcParts[1]);
            ip[14] = (byte) Integer.parseInt(srcParts[2]);
            ip[15] = (byte) Integer.parseInt(srcParts[3]);

            String[] dstParts = dstIp.split("\\.");
            ip[16] = (byte) Integer.parseInt(dstParts[0]);
            ip[17] = (byte) Integer.parseInt(dstParts[1]);
            ip[18] = (byte) Integer.parseInt(dstParts[2]);
            ip[19] = (byte) Integer.parseInt(dstParts[3]);

            byte[] tcp = new byte[20];
            // Ports
            tcp[0] = (byte) ((sport >> 8) & 0xff);
            tcp[1] = (byte) (sport & 0xff);
            tcp[2] = (byte) ((dport >> 8) & 0xff);
            tcp[3] = (byte) (dport & 0xff);
            // Data Offset (5 words)
            tcp[12] = 0x50;
            tcp[13] = 0x18; // Flags (PSH, ACK)
            tcp[14] = 0x00; // Window Size
            tcp[15] = 0x64; // Window Size

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

        private static byte[] makeEthernetIpv4UdpPacket(byte[] payload, int sport, int dport, String srcIp, String dstIp) {
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
            int totalLen = ip.length + 8 + payload.length; // IP Header (20) + UDP Header (8) + Payload
            ip[2] = (byte) ((totalLen >> 8) & 0xff);
            ip[3] = (byte) (totalLen & 0xff);
            ip[8] = 64; // TTL
            ip[9] = 17; // Protocol (UDP=17)

            // IP addresses
            String[] srcParts = srcIp.split("\\.");
            ip[12] = (byte) Integer.parseInt(srcParts[0]);
            ip[13] = (byte) Integer.parseInt(srcParts[1]);
            ip[14] = (byte) Integer.parseInt(srcParts[2]);
            ip[15] = (byte) Integer.parseInt(srcParts[3]);

            String[] dstParts = dstIp.split("\\.");
            ip[16] = (byte) Integer.parseInt(dstParts[0]);
            ip[17] = (byte) Integer.parseInt(dstParts[1]);
            ip[18] = (byte) Integer.parseInt(dstParts[2]);
            ip[19] = (byte) Integer.parseInt(dstParts[3]);

            byte[] udp = new byte[8];
            // Ports
            udp[0] = (byte) ((sport >> 8) & 0xff);
            udp[1] = (byte) (sport & 0xff);
            udp[2] = (byte) ((dport >> 8) & 0xff);
            udp[3] = (byte) (dport & 0xff);
            // Length
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
            // Transaction ID (0x1234)
            b.write(0x12);
            b.write(0x34);
            // Flags (0x0100 -> Standard query)
            b.write(0x01);
            b.write(0x00);
            // Questions (1)
            b.write(0x00);
            b.write(0x01);
            // Answer RRs (0), Authority RRs (0), Additional RRs (0)
            b.write(0x00); b.write(0x00);
            b.write(0x00); b.write(0x00);
            b.write(0x00); b.write(0x00);

            // QNAME section
            for (String label : qname.split("\\.")) {
                b.write(label.length());
                try {
                    b.write(label.getBytes(StandardCharsets.US_ASCII));
                } catch (IOException ignored) {
                }
            }
            b.write(0x00); // Null terminator

            // QTYPE (A record = 0x0001)
            b.write(0x00);
            b.write(0x01);
            // QCLASS (IN = 0x0001)
            b.write(0x00);
            b.write(0x01);
            return b.toByteArray();
        }

        private static byte[] buildSyntheticTlsClientHello(String sni) {
            // Minimal fake TLS ClientHello with SNI (simplified)
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            try {
                // TLS Record Layer Header: Content Type (Handshake=0x16), Version (TLS 1.2/1.1/1.0=0x0303)
                b.write(0x16);
                b.write(0x03);
                b.write(0x03);

                ByteArrayOutputStream body = new ByteArrayOutputStream();
                // Handshake Layer: Handshake Type (Client Hello=0x01)
                body.write(0x01);

                ByteArrayOutputStream hello = new ByteArrayOutputStream();
                // Client Hello: Version (TLS 1.2=0x0303)
                hello.write(0x03);
                hello.write(0x03);

                // Random (32 bytes of zeros for simplicity)
                for (int i = 0; i < 32; i++) hello.write(0);

                // Session ID Length (0)
                hello.write(0);

                // Cipher Suites Length (2 bytes)
                hello.write(0x00);
                hello.write(0x02);

                // Cipher Suite (TLS_RSA_WITH_AES_128_CBC_SHA)
                hello.write(0x00);
                hello.write(0x2f);

                // Compression Methods Length (1 byte)
                hello.write(0x01);

                // Compression Method (Null)
                hello.write(0x00);

                // Extensions (SNI)
                byte[] host = sni.getBytes(StandardCharsets.US_ASCII);
                ByteArrayOutputStream sniExt = new ByteArrayOutputStream();

                // Extension Type (server_name=0x0000)
                sniExt.write(0x00);
                sniExt.write(0x00);

                // Extension Length
                sniExt.write((byte) (((host.length + 5) >> 8) & 0xff));
                sniExt.write((byte) ((host.length + 5) & 0xff));

                // Server Name List Length
                sniExt.write(0x00);
                sniExt.write((byte) (((host.length + 3) >> 8) & 0xff));
                sniExt.write((byte) ((host.length + 3) & 0xff));

                // Name Type (Hostname=0x00)
                sniExt.write(0x00);

                // Hostname Length
                sniExt.write((byte) ((host.length >> 8) & 0xff));
                sniExt.write((byte) (host.length & 0xff));

                // Hostname
                sniExt.write(host);

                byte[] ext = sniExt.toByteArray();

                // Total Extensions Length
                hello.write((byte) ((ext.length >> 8) & 0xff));
                hello.write((byte) (ext.length & 0xff));
                hello.write(ext);

                byte[] hBytes = hello.toByteArray();

                // Handshake Length (3 bytes)
                body.write((byte) ((hBytes.length >> 16) & 0xff));
                body.write((byte) ((hBytes.length >> 8) & 0xff));
                body.write((byte) (hBytes.length & 0xff));
                body.write(hBytes);

                byte[] bodyBytes = body.toByteArray();

                // TLS Record Length (2 bytes)
                b.write((byte) ((bodyBytes.length >> 8) & 0xff));
                b.write((byte) (bodyBytes.length & 0xff));
                b.write(bodyBytes);
            } catch (IOException ignored) {
            }
            return b.toByteArray();
        }

        @Override
        public void startCapture(PacketHandler handler, int maxSeconds) {
            byte[] httpPayload = ("GET /index.html HTTP/1.1\r\nHost: " + SIM_HOST + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
            byte[] dnsPayload = buildSyntheticDnsQuery(SIM_HOST);
            byte[] tlsPayload = buildSyntheticTlsClientHello(SIM_HOST);

            int totalPacketsToSimulate = Math.max(1, maxSeconds * 5); // Approximate rate of 5 packets/second

            for (int i = 0; i < totalPacketsToSimulate && !closed; i++) {
                byte[] raw;

                // Simulate various outbound client packets
                if (i % 3 == 0) {
                    // Outbound HTTP Request (Client to Server)
                    raw = makeEthernetIpv4TcpPacket(httpPayload, SIM_CLIENT_PORT, SIM_HTTP_PORT, CLIENT_IP, HTTP_SERVER_IP);
                }
                else if (i % 3 == 1) {
                    // Outbound DNS Query (Client to DNS Server)
                    raw = makeEthernetIpv4UdpPacket(dnsPayload, SIM_CLIENT_PORT, SIM_DNS_PORT, CLIENT_IP, DNS_SERVER_IP);
                }
                else {
                    // Outbound TLS Client Hello (HTTPS Request, Client to Server)
                    raw = makeEthernetIpv4TcpPacket(tlsPayload, SIM_CLIENT_PORT, SIM_TLS_PORT, CLIENT_IP, HTTP_SERVER_IP);
                }

                PcapPacketStub stub = new PcapPacketStub(i + 1, raw, Instant.now(), raw.length, raw.length);
                if (!handler.handle(stub)) break; // **TERMINATION**: Stops simulation loop if time's up

                try {
                    Thread.sleep(200); // Wait 200ms to spread out the packets
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
        private final ConsoleOutputAccumulator consoleAccumulator;
        private final OutputWriter fileWriter;
        private final Set<String> filter;

        public PacketProcessor(List<LayerParser> parsers, PacketFormatter formatter, ConsoleOutputAccumulator consoleAccumulator, OutputWriter fileWriter, Set<String> filter) {
            this.parsers = parsers;
            this.formatter = formatter;
            this.consoleAccumulator = consoleAccumulator;
            this.fileWriter = fileWriter;
            this.filter = filter;
        }

        public void process(PcapPacketStub pkt, long seq) {
            PacketContext ctx = new PacketContext(seq, pkt);
            for (LayerParser p : parsers) p.parse(ctx);

            // Check if the packet matches any required protocol filter or if ALL is requested
            boolean isMatch = filter.contains("ALL");
            if (!isMatch) {
                for (Map.Entry<String, Map<String, String>> layer : ctx.layers.entrySet()) {
                    for (String value : layer.getValue().values()) {
                        if (value != null && filter.contains(value.toUpperCase())) {
                            isMatch = true;
                            break;
                        }
                    }
                    if (isMatch) break;
                }
            }

            if (!isMatch) return;

            List<String> rows = formatter.format(ctx);

            // Output is sent to both console accumulator (for final report) and the file writer (for immediate logging)
            fileWriter.writeRows(rows);
            consoleAccumulator.writeRows(rows);
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
    }

    // ---------- Frame ----------
    public static final class FrameParser implements LayerParser {
        private static final DateTimeFormatter ISO = DateTimeFormatter.ISO_INSTANT;
        private final String usedNetwork;

        public FrameParser(String usedNetwork) {
            this.usedNetwork = usedNetwork;
        }

        public void parse(PacketContext ctx) {
            Map<String, String> m = new LinkedHashMap<>();
            m.put("FrameNo", String.valueOf(ctx.seq));
            m.put("UsedNetwork", usedNetwork);
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
            String[] parts = new String[6];
            for (int i = 0; i < 6; i++) {
                parts[i] = String.format("%02x", b[off + i]);
            }
            return String.join(":", parts);
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
    public record TransportInfo(int sport, int dport, int proto) {
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
            if (port != 80 && port != 8080) return false;

            String s = new String(ctx.pkt.raw, StandardCharsets.US_ASCII);
            return s.contains("GET") || s.contains("POST") || s.contains("HTTP/");
        }

        public Map<String, String> parse(PacketContext ctx, TransportInfo t) {
            Map<String, String> m = new LinkedHashMap<>();
            String ascii = new String(ctx.pkt.raw, StandardCharsets.US_ASCII);
            if (ascii.length() > 54) {
                ascii = ascii.substring(54);
            }
            ascii = ascii.replaceAll("[^\\p{Print}\\r\\n]", "").trim();
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
                    if (!qname.isEmpty()) qname.append('.');
                    for (int i = 0; i < len; i++) qname.append((char) r[pos++]);
                }
                m.put("QNAME", qname.toString());
            } catch (Exception e) {
                m.put("QNAME", "?");
            }
            return m;
        }
    }

    // ---------- TLS (SNI/HTTPS) ----------
    public static final class TlsParser implements ApplicationParser {
        public boolean canParse(PacketContext ctx, TransportInfo t) {
            if (t.proto != 6) return false;
            int port = t.dport != 0 ? t.dport : t.sport;
            return port == 443 && ctx.pkt.raw.length > 60 && ctx.pkt.raw[54] == 0x16;
        }

        public Map<String, String> parse(PacketContext ctx, TransportInfo t) {
            Map<String, String> m = new LinkedHashMap<>();
            m.put("AppProto", "HTTPS");
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

    // Accumulates output for final console display
    public static final class ConsoleOutputAccumulator {
        private final List<String> allOutput = Collections.synchronizedList(new ArrayList<>());

        public void writeRows(List<String> rows) {
            allOutput.addAll(rows);
        }

        public void printFinalReport(long totalPackets) {
            if (allOutput.isEmpty()) {
                System.out.printf("✅ Capture finished. Total packets processed: %d%n", totalPackets);
                System.out.println("No packets matched the selected filter protocols.");
                return;
            }
            System.out.println("\n\n\n===================================");
            System.out.printf("=== FINAL PACKET ANALYSIS REPORT (%d filtered packets / %d total) ===", allOutput.size() / 2, totalPackets);
            System.out.println("\n===================================");
            allOutput.forEach(System.out::println);
            System.out.println("===================================\n");
        }
    }

    // File output writer (immediate write to file)
    public static final class FileOutputWriter implements OutputWriter {
        private final PrintWriter out;

        public FileOutputWriter(String path) {
            try {
                // Overwrite the file at the start of capture
                this.out = new PrintWriter(new FileWriter(path, false));
            } catch (IOException e) {
                throw new RuntimeException("Failed to open output file: " + path, e);
            }
        }

        public synchronized void writeRows(List<String> rows) {
            for (String r : rows) out.println(r);
            out.flush();
        }

        @Override
        public void close() {
            if (out != null) out.close();
        }
    }
}