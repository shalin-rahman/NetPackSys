/*
 * Concurrent Network Packet Analyzer
 * -----------------------------------
 * • Java 21 (Virtual Threads)
 * • Structured Batch Execution
 * • Ethernet / IPv4 / TCP / UDP / HTTP / DNS / TLS (SNI)
 * • Tab-separated Wireshark-style output
 * • Logs to console AND "packet_analysis_log.txt" simultaneously
 * • Program automatically terminates after specified duration.
 * • NEW: Attempts to auto-retry on next active interface if current capture yields 0 packets.
 */

import org.pcap4j.core.*;
import org.pcap4j.packet.Dot1qVlanTagPacket;
import org.pcap4j.packet.IllegalRawDataException;

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
import java.util.stream.IntStream;

public class PacketAnalyzer {

    // ============================================================
    // MAIN ENTRY
    // ============================================================
    public static void main(String[] args) throws Exception {

        String initialSelection = null;
        int durationSec = 0;
        String protocolsCSV = "ALL"; // Default value

        // Initialize with empty lists
        List<PcapNetworkInterface> allDevs = Collections.emptyList();
        List<PcapNetworkInterface> activeDevs = Collections.emptyList();

        String finalUsedNetwork = "N/A";
        final String OUTPUT_FILE = "packet_analysis_log.txt";

        try (Scanner scanner = new Scanner(System.in)) {

            try {
                allDevs = Pcaps.findAllDevs();
                activeDevs = allDevs.stream()
                        .filter(dev -> !dev.getName().toLowerCase().contains("wan miniport") && !dev.getName().toLowerCase().contains("loopback"))
                        .collect(Collectors.toList());

                // 1. Interface Selection (Interactive with Filtering/Suggestion)
                if (activeDevs.isEmpty()) {
                    System.err.println("⚠️ No active network interfaces found. Forcing simulated capture mode ('sim').");
                    initialSelection = "sim";
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
                    initialSelection = scanner.nextLine().trim();
                }

                // 2. Duration Input
                System.out.print("-> Enter capture duration in seconds (e.g., 10): ");
                String durationInput = scanner.nextLine().trim();
                if (durationInput.isEmpty()) {
                    System.err.println("❌ Duration cannot be empty. Using default 10 seconds.");
                    durationSec = 10;
                } else {
                    durationSec = Integer.parseInt(durationInput);
                    if (durationSec <= 0) {
                        System.err.println("❌ Duration must be a positive number. Using default 10 seconds.");
                        durationSec = 10;
                    }
                }

                // 3. Protocols Input
                System.out.print("-> Enter protocols to capture (e.g., HTTP,DNS,HTTPS, or ALL): ");
                protocolsCSV = scanner.nextLine().trim();
                if (protocolsCSV.isEmpty()) protocolsCSV = "ALL";

            } catch (PcapNativeException e) {
                System.err.println("❌ Failed to list interfaces (PcapNativeException). Using simulation mode.");
                initialSelection = "sim";
                if (durationSec <= 0) durationSec = 10; // Set default duration
            } catch (NumberFormatException e) {
                System.err.println("❌ Invalid number input. Using default values.");
                if (durationSec <= 0) durationSec = 10; // Set default duration
            } catch (Exception e) {
                System.err.println("❌ Unexpected error: " + e.getMessage() + ". Using default values.");
                initialSelection = "sim";
                if (durationSec <= 0) durationSec = 10;
            }
        } // Scanner closed

        // Ensure we have valid values after any exceptions
        if (protocolsCSV == null) {
            protocolsCSV = "ALL";
        }
        if (durationSec <= 0) {
            durationSec = 10;
        }
        if (initialSelection == null) {
            initialSelection = "sim";
        }

        // --- CONFIGURATION & RUN LOOP ---
        final Set<String> protocols = Arrays.stream(protocolsCSV.split(","))
                .map(String::trim).map(String::toUpperCase).collect(Collectors.toSet());
        if (protocols.contains("TLS")) {
            protocols.remove("TLS");
            protocols.add("HTTPS");
        }

        System.out.printf("✅ Protocols selected: %s (Output logged to console AND %s)%n", protocols, OUTPUT_FILE);

        // Use traditional loop instead of stream to avoid lambda issues
        List<Integer> liveInterfaceIndices = new ArrayList<>();
        for (int i = 0; i < allDevs.size(); i++) {
            if (activeDevs.contains(allDevs.get(i))) {
                liveInterfaceIndices.add(i + 1);
            }
        }

        // Determine initial interface based on user selection
        boolean isSimulation = "sim".equalsIgnoreCase(initialSelection);
        int startIndex = -1;
        if (!isSimulation && initialSelection != null) {
            try {
                int selectedIndex = Integer.parseInt(initialSelection);
                if (selectedIndex >= 1 && selectedIndex <= allDevs.size()) {
                    startIndex = liveInterfaceIndices.indexOf(selectedIndex);
                }
            } catch (NumberFormatException ignored) {
            }
        }

        if (startIndex == -1 && !isSimulation && !liveInterfaceIndices.isEmpty()) {
            startIndex = 0;
        }

        boolean successfulCapture = false;

        // --- SIMULATION RUN ---
        if (isSimulation) {
            final String currentUsedNetwork = "SIMULATED";
            System.out.println("🧪 Running in SIMULATION mode.");
            finalUsedNetwork = currentUsedNetwork;
            Config cfg = new Config("sim", currentUsedNetwork, durationSec, protocols, OUTPUT_FILE);
            long processedPackets = new PacketAnalyzerApp(cfg).run();
            successfulCapture = processedPackets > 0;
        }

        // --- LIVE CAPTURE RUN / RETRY LOOP ---
        else if (!liveInterfaceIndices.isEmpty()) {
            int currentIfaceIndex = startIndex;

            while (!successfulCapture && currentIfaceIndex < liveInterfaceIndices.size()) {
                int interfaceNumber = liveInterfaceIndices.get(currentIfaceIndex);
                PcapNetworkInterface selectedDev = allDevs.get(interfaceNumber - 1);

                final String currentUsedNetwork = selectedDev.getDescription() != null ? selectedDev.getDescription() : selectedDev.getName();
                final String ifaceName = selectedDev.getName();

                System.out.printf("\n=======================================================\n");
                System.out.printf("Attempting capture on: [%d] %s\n", interfaceNumber, currentUsedNetwork);
                System.out.printf("=======================================================\n");

                try {
                    Config cfg = new Config(ifaceName, currentUsedNetwork, durationSec, protocols, OUTPUT_FILE);
                    long processedPackets = new PacketAnalyzerApp(cfg).run();

                    if (processedPackets > 0) {
                        System.out.printf("✅ Capture successful with %d packets on %s.\n", processedPackets, currentUsedNetwork);
                        finalUsedNetwork = currentUsedNetwork;
                        successfulCapture = true;
                    } else {
                        System.out.printf("⚠ Capture yielded 0 packets on %s. Retrying on next active interface.\n", currentUsedNetwork);
                    }
                } catch (PcapNativeException e) {
                    System.err.printf("❌ Capture initialization failed on %s: %s. Retrying on next active interface.\n", currentUsedNetwork, e.getMessage());
                } catch (Throwable t) {
                    System.err.printf("❌ Unexpected error during capture on %s: %s. Retrying on next active interface.\n", currentUsedNetwork, t.getMessage());
                }

                currentIfaceIndex++;
            }
        }

        if (!successfulCapture) {
            System.out.println("\n--- FINAL STATUS ---\nFailed to capture packets after trying all available active interfaces.");
        } else {
            System.out.printf("\n--- FINAL STATUS ---\nSuccessfully captured packets on %s.\n", finalUsedNetwork);
        }
    }

    // ============================================================
    // UTILITY INTERFACES
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

    public interface LayerParser {
        void parse(PacketContext ctx);
    }

    public interface ApplicationParser {
        boolean canParse(PacketContext ctx, TransportInfo t);

        Map<String, String> parse(PacketContext ctx, TransportInfo t);
    }

    public interface PacketFormatter {
        List<String> format(PacketContext ctx);
    }

    public interface OutputWriter extends AutoCloseable {
        void writeRows(List<String> rows);
    }

    // ============================================================
    // CONFIGURATION & CONTEXT RECORDS
    // ============================================================
    public record Config(String iface, String usedNetwork, int durationSec, Set<String> protocols, String outFile) {
    }

    public record TransportInfo(int srcPort, int dstPort, String proto, int payloadLen, String flags) {
    }

    // ============================================================
    // APPLICATION
    // ============================================================
    public static final class PacketAnalyzerApp {
        private final Config cfg;
        private final CaptureService capture;
        private final PacketProcessor processor;
        private final StructuredBatchExecutor executor;
        private final ConsoleOutputAccumulator consoleAccumulator;
        private final FileOutputWriter fileWriter;

        public PacketAnalyzerApp(Config cfg) throws PcapNativeException {
            this.cfg = cfg;

            CaptureService cs;
            if ("sim".equalsIgnoreCase(cfg.iface())) {
                cs = new SimulatedCaptureService();
            } else {
                cs = new PcapCaptureService(cfg.iface());
                System.out.println("✅ Live capture initialized on: " + cfg.usedNetwork());
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

        public long run() throws Exception {
            System.out.printf("📡 Capturing for %ds, protocols=%s%n", cfg.durationSec(), cfg.protocols());
            final AtomicLong count = new AtomicLong(0);
            long start = System.currentTimeMillis();
            final long deadline = start + cfg.durationSec() * 1000L;

            final ExecutorService captureExecutor = Executors.newSingleThreadExecutor();

            // Create final references for lambda usage
            final StructuredBatchExecutor finalExecutor = this.executor;
            final PacketProcessor finalProcessor = this.processor;

            try (CaptureService cap = capture; FileOutputWriter fw = fileWriter) {
                Future<Void> captureFuture = captureExecutor.submit(() -> {
                    try {
                        capture.startCapture(packet -> {
                            if (System.currentTimeMillis() > deadline) {
                                return false; // Stop capture
                            }

                            final long n = count.incrementAndGet();
                            finalExecutor.submitBatchTask(() -> {
                                finalProcessor.process(packet, n);
                                return Boolean.TRUE;
                            });
                            return true; // Continue capture
                        }, cfg.durationSec());
                        return null;
                    } catch (Exception e) {
                        System.err.println("\n❌ Capture failed: " + e.getMessage());
                        return null;
                    }
                });

                while (!captureFuture.isDone()) {
                    long remainingSec = (deadline - System.currentTimeMillis() + 999) / 1000;
                    if (remainingSec < 0) remainingSec = 0;

                    System.out.printf("\r⏳ Time Remaining: %d seconds. Packets processed: %d", remainingSec, count.get());

                    if (remainingSec == 0) break;

                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }

                System.out.println();

                try {
                    captureFuture.get(cfg.durationSec() + 2, TimeUnit.SECONDS);
                } catch (TimeoutException e) {
                    System.err.println("⚠ Capture thread timed out during termination, forcing shutdown.");
                    captureFuture.cancel(true);
                }

            } finally {
                captureExecutor.shutdownNow();
                executor.shutdownAndAwait();

                long totalPackets = count.get();
                long filteredPackets = processor.getFilteredPacketCount();
                consoleAccumulator.printFinalReport(filteredPackets, totalPackets);
            }
            return count.get();
        }
    }

    // ============================================================
    // PCAP PACKET STUB
    // ============================================================
    public static final class PcapPacketStub {
        private final long frameNo;
        private final byte[] rawData;
        private final Instant timestamp;
        private final int length; // Wire length
        private final int capLength; // Captured length

        public PcapPacketStub(long frameNo, byte[] rawData, Instant timestamp, int length, int capLength) {
            this.frameNo = frameNo;
            this.rawData = rawData;
            this.timestamp = timestamp;
            this.length = length;
            this.capLength = capLength;
        }

        public long frameNo() { return frameNo; }
        public byte[] rawData() { return rawData; }
        public Instant timestamp() { return timestamp; }
        public int length() { return length; }
        public int capLength() { return capLength; }
    }

    // ============================================================
    // STRUCTURED BATCH EXECUTOR
    // ============================================================
    public static final class StructuredBatchExecutor {
        private final ExecutorService executor;
        private final List<Future<?>> tasks = Collections.synchronizedList(new ArrayList<>());
        private final Phaser phaser = new Phaser(1);

        public StructuredBatchExecutor(ExecutorService executor) {
            this.executor = executor;
        }

        public <T> Future<T> submitBatchTask(Callable<T> task) {
            phaser.register();
            Future<T> future = executor.submit(() -> {
                try {
                    return task.call();
                } finally {
                    phaser.arriveAndDeregister();
                }
            });
            tasks.add(future);
            return future;
        }

        public void shutdownAndAwait() {
            phaser.arriveAndAwaitAdvance();
            executor.shutdown();
            try {
                if (!executor.awaitTermination(60, TimeUnit.SECONDS)) {
                    System.err.println("⚠ Batch executor did not terminate in time. Forcing shutdown.");
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                executor.shutdownNow();
            }
        }
    }

    // ============================================================
    // PROCESSOR PIPELINE
    // ============================================================
    public static final class PacketProcessor {
        private final List<LayerParser> parsers;
        private final PacketFormatter formatter;
        private final OutputWriter consoleWriter;
        private final OutputWriter fileWriter;
        private final Set<String> protocols;
        private final ApplicationParserRegistry appRegistry = new ApplicationParserRegistry();
        private final AtomicLong filteredPacketCount = new AtomicLong(0);

        public PacketProcessor(List<LayerParser> parsers, PacketFormatter formatter, OutputWriter consoleWriter, OutputWriter fileWriter, Set<String> protocols) {
            this.parsers = parsers;
            this.formatter = formatter;
            this.consoleWriter = consoleWriter;
            this.fileWriter = fileWriter;
            this.protocols = protocols;
        }

        public long getFilteredPacketCount() {
            return filteredPacketCount.get();
        }

        public void process(PcapPacketStub packet, long frameNo) {
            PacketContext ctx = new PacketContext(frameNo, packet);

            // 1. Run all Layer Parsers
            for (LayerParser parser : parsers) {
                parser.parse(ctx);
            }

            // 2. Run Application Parsers (now adds proper APP layer)
            TransportInfo t = ctx.transport();
            if (t != null) {
                appRegistry.parse(ctx, t);
            }

            // 3. Filter and Format
            boolean filter = protocols.contains("ALL");
            if (!filter) {
                // Check if any APP layer matches our protocol filter
                Map<String, String> appLayer = ctx.layers().get("APP");
                if (appLayer != null) {
                    String appProto = appLayer.get("AppProto");
                    filter = protocols.contains(appProto);
                }
            }
            if (!filter) return;

            filteredPacketCount.incrementAndGet();

            // 4. Format and Write Output
            List<String> rows = formatter.format(ctx);
            consoleWriter.writeRows(rows);
            fileWriter.writeRows(rows);
        }
    }

    // ============================================================
    // PARSING CONTEXT
    // ============================================================
    public static final class PacketContext {
        private final long frameNo;
        private final PcapPacketStub stub;
        private final Map<String, Map<String, String>> layers = new LinkedHashMap<>();
        private TransportInfo transportInfo;
        private byte[] currentLayerPayload;
        private Map<String, String> appData;

        public PacketContext(long frameNo, PcapPacketStub stub) {
            this.frameNo = frameNo;
            this.stub = stub;
            this.currentLayerPayload = stub.rawData();
        }

        public long frameNo() { return frameNo; }
        public PcapPacketStub stub() { return stub; }
        public Map<String, Map<String, String>> layers() { return layers; }
        public byte[] payload() { return currentLayerPayload; }
        public TransportInfo transport() { return transportInfo; }
        public Map<String, String> app() { return appData; }

        public void addLayer(String layerName, Map<String, String> data, byte[] newPayload) {
            layers.put(layerName, data);
            this.currentLayerPayload = newPayload;
            if ("TRANSPORT".equals(layerName)) {
                this.transportInfo = new TransportInfo(
                        Integer.parseInt(data.get("SrcPort")),
                        Integer.parseInt(data.get("DstPort")),
                        data.get("Proto"),
                        Integer.parseInt(data.get("PayloadLen")),
                        data.get("Flags")
                );
            }
        }

        public void setApp(Map<String, String> data) {
            this.appData = data;
        }
    }

    // ============================================================
    // LAYER PARSERS - ENHANCED FOR HTTP/HTTPS
    // ============================================================
    public static final class FrameParser implements LayerParser {
        private final String usedNetwork;
        private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSS'Z'").withZone(ZoneOffset.UTC);

        public FrameParser(String usedNetwork) {
            this.usedNetwork = usedNetwork;
        }

        @Override
        public void parse(PacketContext ctx) {
            PcapPacketStub stub = ctx.stub();
            Map<String, String> m = new LinkedHashMap<>();
            m.put("FrameNo", String.valueOf(stub.frameNo()));
            m.put("UsedNetwork", usedNetwork);
            m.put("Len", String.valueOf(stub.length()));
            m.put("CapLen", String.valueOf(stub.capLength()));
            m.put("WireBits", String.valueOf(stub.length() * 8));
            m.put("Timestamp", ISO_FORMATTER.format(stub.timestamp()));

            // Calculate time since first packet for sequence analysis
            m.put("RelativeTime", String.format("%.6f", System.currentTimeMillis() / 1000.0));

            ctx.addLayer("FRAME", m, ctx.payload());
        }
    }

    public static final class LinkParser implements LayerParser {
        private static String mac(byte[] b, int off) {
            if (b.length < off + 6) return "-";
            String[] parts = new String[6];
            for (int i = 0; i < 6; i++) {
                parts[i] = String.format("%02x", b[off + i]);
            }
            return String.join(":", parts);
        }

        @Override
        public void parse(PacketContext ctx) {
            byte[] raw = ctx.payload();
            if (raw.length < 14) return;
            int etherType = ((raw[12] & 0xFF) << 8) | (raw[13] & 0xFF);

            Map<String, String> m = new LinkedHashMap<>();
            m.put("DstMAC", mac(raw, 0));
            m.put("SrcMAC", mac(raw, 6));
            m.put("EtherType", String.format("0x%04x", etherType));

            // Enhanced Ethernet type information
            String etherTypeDesc = getEtherTypeDescription(etherType);
            m.put("EtherTypeDesc", etherTypeDesc);

            // Handle 802.1Q (VLAN) - skip 4 bytes and re-read EtherType
            if (etherType == 0x8100 || etherType == 0x88a8) {
                if (raw.length < 18) return;
                int vlanId = ((raw[14] & 0x0F) << 8) | (raw[15] & 0xFF);
                etherType = ((raw[16] & 0xFF) << 8) | (raw[17] & 0xFF);

                Map<String, String> vlan = new LinkedHashMap<>();
                vlan.put("VLANID", String.valueOf(vlanId));
                vlan.put("Priority", String.valueOf((raw[14] & 0xE0) >> 5));
                vlan.put("CFI", String.valueOf((raw[14] & 0x10) >> 4));
                vlan.put("EtherType", String.format("0x%04x", etherType));
                vlan.put("EtherTypeDesc", getEtherTypeDescription(etherType));

                ctx.addLayer("VLAN", vlan, Arrays.copyOfRange(raw, 18, raw.length));
                raw = Arrays.copyOfRange(raw, 18, raw.length);

                // Update main link layer with new ethertype
                m.put("EtherType", String.format("0x%04x", etherType));
                m.put("EtherTypeDesc", getEtherTypeDescription(etherType));
            }

            // IPv4 (0x0800), IPv6 (0x86DD)
            if (etherType == 0x0800) {
                ctx.addLayer("LINK", m, Arrays.copyOfRange(raw, 14, raw.length));
            } else {
                ctx.addLayer("LINK", m, new byte[0]); // Stop parsing if not IPv4
            }
        }

        private String getEtherTypeDescription(int etherType) {
            return switch (etherType) {
                case 0x0800 -> "IPv4";
                case 0x0806 -> "ARP";
                case 0x0835 -> "RARP";
                case 0x86DD -> "IPv6";
                case 0x8100 -> "VLAN-tagged";
                case 0x88A8 -> "Q-in-Q";
                case 0x8864 -> "PPPoE Discovery";
                case 0x8863 -> "PPPoE Session";
                default -> "Unknown";
            };
        }
    }

    public static final class NetworkParser implements LayerParser {
        private static String ip(byte[] b, int off) {
            if (b.length < off + 4) return "-";
            return String.format("%d.%d.%d.%d", b[off] & 0xFF, b[off + 1] & 0xFF, b[off + 2] & 0xFF, b[off + 3] & 0xFF);
        }

        private static String getProtocolName(int proto) {
            return switch (proto) {
                case 1 -> "ICMP";
                case 2 -> "IGMP";
                case 6 -> "TCP";
                case 17 -> "UDP";
                case 41 -> "IPv6";
                case 89 -> "OSPF";
                default -> "Unknown(" + proto + ")";
            };
        }

        @Override
        public void parse(PacketContext ctx) {
            byte[] raw = ctx.payload();
            if (raw.length < 20 || (raw[0] & 0xF0) != 0x40) return; // Not IPv4

            int version = (raw[0] >> 4) & 0x0F;
            int ihl = (raw[0] & 0x0F) * 4;
            if (raw.length < ihl) return;

            int totLen = ((raw[2] & 0xFF) << 8) | (raw[3] & 0xFF);
            int id = ((raw[4] & 0xFF) << 8) | (raw[5] & 0xFF);
            int flags = (raw[6] >> 5) & 0x07;
            int fragOffset = ((raw[6] & 0x1F) << 8) | (raw[7] & 0xFF);
            int ttl = raw[8] & 0xFF;
            int proto = raw[9] & 0xFF; // Protocol
            int checksum = ((raw[10] & 0xFF) << 8) | (raw[11] & 0xFF);

            Map<String, String> m = new LinkedHashMap<>();
            m.put("SrcIP", ip(raw, 12));
            m.put("DstIP", ip(raw, 16));
            m.put("Version", String.valueOf(version));
            m.put("IHL", String.valueOf(ihl));
            m.put("DSCP", String.valueOf((raw[1] >> 2) & 0x3F));
            m.put("ECN", String.valueOf(raw[1] & 0x03));
            m.put("TotLen", String.valueOf(totLen));
            m.put("ID", String.format("0x%04x", id));
            m.put("Flags", String.format("0x%01x", flags));
            m.put("FragOffset", String.valueOf(fragOffset));
            m.put("TTL", String.valueOf(ttl));
            m.put("Proto", String.valueOf(proto));
            m.put("ProtoName", getProtocolName(proto));
            m.put("Checksum", String.format("0x%04x", checksum));

            ctx.addLayer("NETWORK", m, Arrays.copyOfRange(raw, ihl, raw.length));
        }
    }

    public static final class TransportParser implements LayerParser {
        private static String getTcpFlags(int flags) {
            List<String> flagList = new ArrayList<>();
            if ((flags & 0x01) != 0) flagList.add("FIN");
            if ((flags & 0x02) != 0) flagList.add("SYN");
            if ((flags & 0x04) != 0) flagList.add("RST");
            if ((flags & 0x08) != 0) flagList.add("PSH");
            if ((flags & 0x10) != 0) flagList.add("ACK");
            if ((flags & 0x20) != 0) flagList.add("URG");
            if ((flags & 0x40) != 0) flagList.add("ECE");
            if ((flags & 0x80) != 0) flagList.add("CWR");
            return flagList.isEmpty() ? "None" : String.join(",", flagList);
        }

        @Override
        public void parse(PacketContext ctx) {
            Map<String, String> network = ctx.layers().get("NETWORK");
            if (network == null) return;

            int proto = Integer.parseInt(network.get("Proto"));
            byte[] raw = ctx.payload();
            if (raw.length < 8) return;

            Map<String, String> m = new LinkedHashMap<>();
            int headerLen = 0;

            if (proto == 6) { // TCP
                if (raw.length < 20) return;
                int srcPort = ((raw[0] & 0xFF) << 8) | (raw[1] & 0xFF);
                int dstPort = ((raw[2] & 0xFF) << 8) | (raw[3] & 0xFF);
                int seqNum = ((raw[4] & 0xFF) << 24) | ((raw[5] & 0xFF) << 16) | ((raw[6] & 0xFF) << 8) | (raw[7] & 0xFF);
                int ackNum = ((raw[8] & 0xFF) << 24) | ((raw[9] & 0xFF) << 16) | ((raw[10] & 0xFF) << 8) | (raw[11] & 0xFF);
                headerLen = (raw[12] >> 4) * 4;
                int flags = raw[13] & 0xFF;
                int window = ((raw[14] & 0xFF) << 8) | (raw[15] & 0xFF);
                int checksum = ((raw[16] & 0xFF) << 8) | (raw[17] & 0xFF);
                int urgPtr = ((raw[18] & 0xFF) << 8) | (raw[19] & 0xFF);

                m.put("SrcPort", String.valueOf(srcPort));
                m.put("DstPort", String.valueOf(dstPort));
                m.put("Proto", "TCP");
                m.put("SeqNum", String.valueOf(seqNum));
                m.put("AckNum", String.valueOf(ackNum));
                m.put("HeaderLen", String.valueOf(headerLen));
                m.put("Flags", String.format("0x%02x", flags));
                m.put("FlagsDesc", getTcpFlags(flags));
                m.put("Window", String.valueOf(window));
                m.put("Checksum", String.format("0x%04x", checksum));
                m.put("UrgPtr", String.valueOf(urgPtr));
                m.put("PayloadLen", String.valueOf(raw.length - headerLen));

                // HTTP/HTTPS detection for enhanced info
                if (dstPort == 80 || dstPort == 8080 || srcPort == 80 || srcPort == 8080) {
                    m.put("Service", "HTTP");
                } else if (dstPort == 443 || srcPort == 443) {
                    m.put("Service", "HTTPS");
                } else if (dstPort == 53 || srcPort == 53) {
                    m.put("Service", "DNS");
                }

            } else if (proto == 17) { // UDP
                int srcPort = ((raw[0] & 0xFF) << 8) | (raw[1] & 0xFF);
                int dstPort = ((raw[2] & 0xFF) << 8) | (raw[3] & 0xFF);
                int length = ((raw[4] & 0xFF) << 8) | (raw[5] & 0xFF);
                int checksum = ((raw[6] & 0xFF) << 8) | (raw[7] & 0xFF);
                headerLen = 8;

                m.put("SrcPort", String.valueOf(srcPort));
                m.put("DstPort", String.valueOf(dstPort));
                m.put("Proto", "UDP");
                m.put("Length", String.valueOf(length));
                m.put("Checksum", String.format("0x%04x", checksum));
                m.put("PayloadLen", String.valueOf(raw.length - headerLen));
                m.put("Flags", "-");
                m.put("FlagsDesc", "-");

                // DNS detection
                if (dstPort == 53 || srcPort == 53) {
                    m.put("Service", "DNS");
                }
            }

            if (!m.isEmpty()) {
                ctx.addLayer("TRANSPORT", m, Arrays.copyOfRange(raw, headerLen, raw.length));
            }
        }
    }

    // ============================================================
    // APPLICATION PARSERS - ENHANCED FOR HTTP/HTTPS
    // ============================================================
    public static final class ApplicationParserRegistry {
        private final List<ApplicationParser> parsers = List.of(
                new HttpParser(),
                new TlsParser(),
                new DnsParser()
        );

        public void parse(PacketContext ctx, TransportInfo t) {
            for (ApplicationParser parser : parsers) {
                if (parser.canParse(ctx, t)) {
                    Map<String, String> appData = parser.parse(ctx, t);
                    if (appData != null && !appData.isEmpty()) {
                        // Add as proper APP layer instead of setting app data
                        ctx.addLayer("APP", appData, new byte[0]); // No more payload after app layer
                        return;
                    }
                }
            }

            // If no specific app parser matched, add generic APP info
            Map<String, String> genericApp = new LinkedHashMap<>();
            genericApp.put("AppProto", "UNKNOWN");
            genericApp.put("Info", "No specific application protocol detected");
            ctx.addLayer("APP", genericApp, new byte[0]);
        }
    }

    public static final class HttpParser implements ApplicationParser {
        @Override
        public boolean canParse(PacketContext ctx, TransportInfo t) {
            return "TCP".equals(t.proto()) && (t.dstPort() == 80 || t.dstPort() == 8080 || t.srcPort() == 80 || t.srcPort() == 8080);
        }

        @Override
        public Map<String, String> parse(PacketContext ctx, TransportInfo t) {
            Map<String, String> m = new LinkedHashMap<>();
            m.put("AppProto", "HTTP");

            try {
                String payload = new String(ctx.payload(), StandardCharsets.US_ASCII);
                if (!payload.trim().isEmpty()) {
                    // Extract first line for request/response identification
                    String firstLine = payload.lines().findFirst().orElse("").trim();
                    if (!firstLine.isEmpty()) {
                        m.put("FirstLine", firstLine);

                        // Determine if it's request or response
                        if (firstLine.startsWith("HTTP/")) {
                            m.put("Type", "Response");
                            // Extract status code and version
                            String[] parts = firstLine.split(" ");
                            if (parts.length >= 3) {
                                m.put("Version", parts[0]);
                                m.put("StatusCode", parts[1]);
                                m.put("StatusMsg", parts[2]);

                                // Classify status codes
                                int statusCode = Integer.parseInt(parts[1]);
                                if (statusCode >= 100 && statusCode < 200) m.put("StatusClass", "Informational");
                                else if (statusCode >= 200 && statusCode < 300) m.put("StatusClass", "Success");
                                else if (statusCode >= 300 && statusCode < 400) m.put("StatusClass", "Redirection");
                                else if (statusCode >= 400 && statusCode < 500) m.put("StatusClass", "Client Error");
                                else if (statusCode >= 500) m.put("StatusClass", "Server Error");
                            }
                        } else {
                            m.put("Type", "Request");
                            // Extract method and path
                            String[] parts = firstLine.split(" ");
                            if (parts.length >= 3) {
                                m.put("Method", parts[0]);
                                m.put("Path", parts[1]);
                                m.put("Version", parts[2]);

                                // Common method classification
                                switch (parts[0]) {
                                    case "GET", "HEAD", "OPTIONS" -> m.put("MethodType", "Safe");
                                    case "POST", "PUT", "DELETE", "PATCH" -> m.put("MethodType", "State-Changing");
                                    default -> m.put("MethodType", "Other");
                                }
                            }
                        }
                    }

                    // Parse headers
                    String[] lines = payload.split("\r\n");
                    boolean inHeaders = true;
                    int contentLength = 0;
                    String contentType = "";
                    String userAgent = "";
                    String host = "";

                    for (int i = 1; i < lines.length && inHeaders; i++) {
                        String line = lines[i].trim();
                        if (line.isEmpty()) {
                            inHeaders = false;
                            continue;
                        }

                        if (line.toLowerCase().startsWith("content-length:")) {
                            try {
                                contentLength = Integer.parseInt(line.substring(15).trim());
                                m.put("ContentLength", String.valueOf(contentLength));
                            } catch (NumberFormatException e) {
                                // Ignore
                            }
                        } else if (line.toLowerCase().startsWith("content-type:")) {
                            contentType = line.substring(13).trim();
                            m.put("ContentType", contentType);
                        } else if (line.toLowerCase().startsWith("user-agent:")) {
                            userAgent = line.substring(11).trim();
                            m.put("UserAgent", userAgent.length() > 50 ? userAgent.substring(0, 47) + "..." : userAgent);
                        } else if (line.toLowerCase().startsWith("host:")) {
                            host = line.substring(5).trim();
                            m.put("Host", host);
                        } else if (line.toLowerCase().startsWith("cookie:")) {
                            m.put("HasCookies", "Yes");
                        } else if (line.toLowerCase().startsWith("authorization:")) {
                            m.put("HasAuth", "Yes");
                        }
                    }

                    // Calculate body size
                    int headerEnd = payload.indexOf("\r\n\r\n");
                    if (headerEnd != -1) {
                        int bodySize = payload.length() - headerEnd - 4;
                        m.put("BodySize", String.valueOf(bodySize));
                    }

                    m.put("PayloadSize", String.valueOf(payload.length()));
                    m.put("HeaderCount", String.valueOf(lines.length - 1)); // Exclude first line
                }
            } catch (Exception e) {
                m.put("Error", "Malformed HTTP");
            }
            return m;
        }
    }

    public static final class DnsParser implements ApplicationParser {
        @Override
        public boolean canParse(PacketContext ctx, TransportInfo t) {
            return "UDP".equals(t.proto()) && (t.dstPort() == 53 || t.srcPort() == 53);
        }

        @Override
        public Map<String, String> parse(PacketContext ctx, TransportInfo t) {
            Map<String, String> m = new LinkedHashMap<>();
            m.put("AppProto", "DNS");
            byte[] raw = ctx.payload();
            if (raw.length < 12) {
                m.put("Error", "Packet too short");
                return m;
            }

            try {
                int id = ((raw[0] & 0xFF) << 8) | (raw[1] & 0xFF);
                int flags = ((raw[2] & 0xFF) << 8) | (raw[3] & 0xFF);
                int qdCount = ((raw[4] & 0xFF) << 8) | (raw[5] & 0xFF);
                int anCount = ((raw[6] & 0xFF) << 8) | (raw[7] & 0xFF);
                int nsCount = ((raw[8] & 0xFF) << 8) | (raw[9] & 0xFF);
                int arCount = ((raw[10] & 0xFF) << 8) | (raw[11] & 0xFF);

                m.put("ID", String.format("0x%04x", id));
                m.put("Flags", String.format("0x%04x", flags));
                m.put("Questions", String.valueOf(qdCount));
                m.put("Answers", String.valueOf(anCount));
                m.put("Authority", String.valueOf(nsCount));
                m.put("Additional", String.valueOf(arCount));

                // Determine query/response
                boolean isResponse = (flags & 0x8000) != 0;
                m.put("Type", isResponse ? "Response" : "Query");

                // Extract QNAME for queries
                if (qdCount > 0 && !isResponse) {
                    StringBuilder qname = new StringBuilder();
                    int offset = 12;
                    while (offset < raw.length && offset < 512) { // DNS max 512 bytes
                        int len = raw[offset] & 0xFF;
                        if (len == 0) break;
                        if (len > 63) break; // Compression or invalid

                        if (!qname.isEmpty()) qname.append('.');
                        qname.append(new String(raw, offset + 1, len, StandardCharsets.US_ASCII));
                        offset += len + 1;

                        if (offset + 1 < raw.length && raw[offset] == 0) {
                            // Query type
                            int qtype = ((raw[offset + 1] & 0xFF) << 8) | (raw[offset + 2] & 0xFF);
                            m.put("QueryType", getDnsType(qtype));
                            break;
                        }
                    }
                    if (!qname.isEmpty()) {
                        m.put("Query", qname.toString());
                    }
                }

            } catch (Exception e) {
                m.put("Error", "Malformed DNS");
            }
            return m;
        }

        private String getDnsType(int qtype) {
            return switch (qtype) {
                case 1 -> "A";
                case 28 -> "AAAA";
                case 5 -> "CNAME";
                case 15 -> "MX";
                case 2 -> "NS";
                case 12 -> "PTR";
                case 6 -> "SOA";
                case 16 -> "TXT";
                default -> "UNKNOWN(" + qtype + ")";
            };
        }
    }

    public static final class TlsParser implements ApplicationParser {
        @Override
        public boolean canParse(PacketContext ctx, TransportInfo t) {
            return "TCP".equals(t.proto()) && (t.dstPort() == 443 || t.srcPort() == 443);
        }

        @Override
        public Map<String, String> parse(PacketContext ctx, TransportInfo t) {
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

                // Handle Client Hello for SNI extraction
                if (contentType == 0x16 && raw.length >= 6) { // Handshake
                    int handshakeType = raw[5] & 0xFF;
                    m.put("HandshakeType", getTlsHandshakeType(handshakeType));

                    if (handshakeType == 0x01) { // Client Hello
                        String sni = extractSni(raw);
                        if (sni != null) {
                            m.put("SNI", sni);
                        }
                        m.put("Info", "Client Hello");

                        // Extract cipher suites count
                        if (raw.length >= 45) {
                            int cipherSuitesLen = ((raw[43] & 0xFF) << 8) | (raw[44] & 0xFF);
                            int cipherSuitesCount = cipherSuitesLen / 2;
                            m.put("CipherSuites", String.valueOf(cipherSuitesCount));
                        }
                    } else if (handshakeType == 0x02) {
                        m.put("Info", "Server Hello");
                    } else if (handshakeType == 0x0B) {
                        m.put("Info", "Certificate");
                    } else if (handshakeType == 0x10) {
                        m.put("Info", "Client Key Exchange");
                    } else if (handshakeType == 0x14) {
                        m.put("Info", "Finished");
                    }
                } else if (contentType == 0x17) {
                    m.put("Info", "Application Data");
                    m.put("Encrypted", "Yes");
                } else if (contentType == 0x14) {
                    m.put("Info", "Change Cipher Spec");
                } else if (contentType == 0x15) {
                    m.put("Info", "Alert");
                    if (raw.length >= 6) {
                        m.put("AlertLevel", String.format("0x%02x", raw[5] & 0xFF));
                        m.put("AlertDescription", String.format("0x%02x", raw[6] & 0xFF));
                    }
                }

            } catch (Exception e) {
                m.put("Error", "Malformed TLS");
            }
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
            if (major == 2 && minor == 0) return "SSL 2.0";
            if (major == 3 && minor == 0) return "SSL 3.0";
            return String.format("Unknown(%d.%d)", major, minor);
        }

        private String getTlsHandshakeType(int type) {
            return switch (type) {
                case 0x01 -> "ClientHello";
                case 0x02 -> "ServerHello";
                case 0x0B -> "Certificate";
                case 0x10 -> "ClientKeyExchange";
                case 0x0C -> "ServerKeyExchange";
                case 0x0D -> "CertificateRequest";
                case 0x0E -> "ServerHelloDone";
                case 0x0F -> "CertificateVerify";
                case 0x14 -> "Finished";
                default -> "Unknown(" + type + ")";
            };
        }

        private String extractSni(byte[] raw) {
            try {
                int offset = 43; // Skip to Session ID Length
                if (offset >= raw.length) return null;

                int sessionIdLen = raw[offset] & 0xFF;
                offset += 1 + sessionIdLen; // Skip Session ID

                if (offset + 2 >= raw.length) return null;
                int cipherSuitesLen = ((raw[offset] & 0xFF) << 8) | (raw[offset+1] & 0xFF);
                offset += 2 + cipherSuitesLen; // Skip Cipher Suites

                if (offset >= raw.length) return null;
                int compressionLen = raw[offset] & 0xFF;
                offset += 1 + compressionLen; // Skip Compression Methods

                if (offset + 2 >= raw.length) return null;
                int extensionsLen = ((raw[offset] & 0xFF) << 8) | (raw[offset+1] & 0xFF);
                offset += 2;

                int endOffset = offset + extensionsLen;
                while (offset < endOffset && offset + 4 < raw.length) {
                    int extType = ((raw[offset] & 0xFF) << 8) | (raw[offset+1] & 0xFF);
                    int extLen = ((raw[offset+2] & 0xFF) << 8) | (raw[offset+3] & 0xFF);
                    offset += 4;

                    if (extType == 0x0000) { // Server Name Indication (SNI)
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
            } catch (Exception e) {
                // Ignore extraction errors
            }
            return null;
        }
    }

    // ============================================================
    // OUTPUT FORMATTER
    // ============================================================
    public static final class TabRowPacketFormatter implements PacketFormatter {
        @Override
        public List<String> format(PacketContext ctx) {
            List<String> rows = new ArrayList<>();
            for (Map.Entry<String, Map<String, String>> e : ctx.layers().entrySet()) {
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

    // ============================================================
    // OUTPUT WRITERS
    // ============================================================
    public static final class ConsoleOutputAccumulator implements OutputWriter {
        private final List<String> buffer = Collections.synchronizedList(new ArrayList<>());
        private final PrintWriter consoleOut = new PrintWriter(System.out, true);

        @Override
        public void writeRows(List<String> rows) {
            buffer.addAll(rows);
        }

        public void printFinalReport(long filteredPackets, long totalPackets) {
            consoleOut.println();
            consoleOut.println("===================================");
            consoleOut.printf("=== FINAL PACKET ANALYSIS REPORT (%d filtered packets / %d total) ===%n", filteredPackets, totalPackets);
            consoleOut.println("===================================");
            buffer.forEach(consoleOut::println);
            consoleOut.println("===================================");
        }

        @Override
        public void close() {}
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

        @Override
        public synchronized void writeRows(List<String> rows) {
            for (String r : rows) out.println(r);
            out.flush();
        }

        @Override
        public void close() {
            if (out != null) out.close();
        }
    }

    // ============================================================
    // PCAP CAPTURE SERVICE
    // ============================================================
    public static final class PcapCaptureService implements CaptureService {
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
                    // Use getNextPacket for more control over the capture loop
                    org.pcap4j.packet.Packet packet = handle.getNextPacket();
                    if (packet == null) {
                        Thread.sleep(10); // Small delay when no packets available
                        continue;
                    }

                    final long frameNo = frameCounter.incrementAndGet();
                    final byte[] rawData = packet.getRawData();
                    final Instant timestamp = Instant.now(); // Use current time as approximation

                    final PcapPacketStub stub = new PcapPacketStub(
                            frameNo,
                            rawData,
                            timestamp,
                            packet.length(),    // Original wire length
                            rawData.length     // Captured length
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

    // ============================================================
    // SIMULATED CAPTURE SERVICE
    // ============================================================
    public static final class SimulatedCaptureService implements CaptureService {
        private volatile boolean closed = false;

        // Constants for synthetic data generation
        private static final String SIM_HOST = "example.com";
        private static final int SIM_DNS_PORT = 53;
        private static final int SIM_HTTP_PORT = 80;
        private static final int SIM_TLS_PORT = 443;
        private static final int SIM_CLIENT_PORT = 51322;

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

        @Override
        public void startCapture(PacketHandler handler, int maxSeconds) {
            // Use constants for payloads (SIM_HOST) and ports
            final byte[] httpPayload = ("GET /index.html HTTP/1.1\r\nHost: " + SIM_HOST + "\r\nUser-Agent: PacketAnalyzer/1.0\r\nAccept: text/html\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
            final byte[] dnsPayload = buildSyntheticDnsQuery(SIM_HOST);
            final byte[] tlsPayload = buildSyntheticTlsClientHello(SIM_HOST);

            int total = Math.max(1, maxSeconds * 5);
            for (int i = 0; i < total && !closed; i++) {
                final byte[] raw;
                if (i % 3 == 0) raw = makeEthernetIpv4TcpPacket(httpPayload, SIM_CLIENT_PORT, SIM_HTTP_PORT);
                else if (i % 3 == 1) raw = makeEthernetIpv4UdpPacket(dnsPayload, SIM_CLIENT_PORT, SIM_DNS_PORT);
                else raw = makeEthernetIpv4TcpPacket(tlsPayload, SIM_CLIENT_PORT, SIM_TLS_PORT);

                final PcapPacketStub stub = new PcapPacketStub(i + 1, raw, Instant.now(), raw.length, raw.length);
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
}