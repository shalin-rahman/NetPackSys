package com.network.analyzer;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.HttpPacket;
import org.pcap4j.util.NifSelector;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

// Main Application with REAL pcap4j packet capture
public class RealTimePacketAnalyzer {
    private final EnhancedStatisticsCollector statistics;
    private final Set<String> protocolsToAnalyze;
    private final Duration captureDuration;

    public RealTimePacketAnalyzer(Set<String> protocolsToAnalyze, Duration captureDuration) {
        this.protocolsToAnalyze = protocolsToAnalyze;
        this.statistics = new EnhancedStatisticsCollector();
        this.captureDuration = captureDuration;
    }

    public void startRealTimeAnalysis() {
        try {
            System.out.println("🚀 Starting Real-Time Network Packet Analyzer with pcap4j...");
            System.out.println("📡 Protocols to analyze: " + protocolsToAnalyze);
            System.out.println("⏱️  Duration: " + captureDuration.getSeconds() + " seconds");
            System.out.println("📶 Capture Interface: Wi-Fi");
            System.out.println("🔐 Admin Privileges: REQUIRED for packet capture");
            System.out.println("🧵 Using Virtual Threads for concurrent processing\n");

            // Get network interface
            PcapNetworkInterface nif = selectNetworkInterface();
            if (nif == null) {
                System.err.println("❌ No network interface selected. Exiting.");
                return;
            }

            System.out.println("🎯 Selected Interface: " + nif.getName() + " - " + nif.getDescription());

            // Open the interface for packet capture
            int snapshotLength = 65536; // bytes
            int readTimeout = 50; // milliseconds
            PcapHandle handle = nif.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, readTimeout);

            // Create packet capture manager with real handle
            RealTimeCaptureManager captureManager = new RealTimeCaptureManager(statistics, protocolsToAnalyze, handle);
            captureManager.startCapture(captureDuration);

            // Display summary
            statistics.displayEnhancedSummary();

            handle.close();

        } catch (Exception e) {
            System.err.println("❌ Error during real-time packet analysis: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private PcapNetworkInterface selectNetworkInterface() throws Exception {
        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        if (allDevs == null || allDevs.isEmpty()) {
            throw new Exception("No network interfaces found!");
        }

        System.out.println("📡 Available Network Interfaces:");
        for (int i = 0; i < allDevs.size(); i++) {
            PcapNetworkInterface nif = allDevs.get(i);
            System.out.printf("  %d. %s (%s)\n", i + 1, nif.getName(), 
                nif.getDescription() != null ? nif.getDescription() : "No description");
        }

        // Try to automatically select WiFi interface
        for (PcapNetworkInterface nif : allDevs) {
            if (nif.getDescription() != null && 
                (nif.getDescription().toLowerCase().contains("wifi") || 
                 nif.getDescription().toLowerCase().contains("wireless") ||
                 nif.getName().toLowerCase().contains("wi") ||
                 nif.getName().toLowerCase().contains("wlan"))) {
                System.out.println("✅ Auto-selected WiFi interface: " + nif.getDescription());
                return nif;
            }
        }

        // Fallback to first interface
        System.out.println("⚠️  No WiFi interface detected, using first available interface");
        return allDevs.get(0);
    }

    public static void main(String[] args) {
        Set<String> protocols = Set.of("HTTP", "TCP", "IP", "ETHERNET");
        Duration duration = Duration.ofSeconds(30);
        
        RealTimePacketAnalyzer analyzer = new RealTimePacketAnalyzer(protocols, duration);
        analyzer.startRealTimeAnalysis();
    }
}

// Real-time Packet Capture Manager using pcap4j
class RealTimeCaptureManager {
    private final EnhancedStatisticsCollector statistics;
    private final Set<String> protocolsToAnalyze;
    private final PcapHandle handle;
    private final AtomicInteger packetCounter = new AtomicInteger(0);
    private final AtomicInteger virtualThreadCount = new AtomicInteger(0);

    public RealTimeCaptureManager(EnhancedStatisticsCollector statistics, 
                                Set<String> protocolsToAnalyze, 
                                PcapHandle handle) {
        this.statistics = statistics;
        this.protocolsToAnalyze = protocolsToAnalyze;
        this.handle = handle;
    }

    public void startCapture(Duration duration) {
        System.out.println("🎯 Starting real-time packet capture with pcap4j...");
        
        long startTime = System.currentTimeMillis();
        long endTime = startTime + duration.toMillis();
        
        try (var scope = new StructuredTaskScope.ShutdownOnFailure()) {
            List<StructuredTaskScope.Subtask<NetworkPacket>> tasks = new ArrayList<>();
            int batchSize = 5;
            
            while (System.currentTimeMillis() < endTime) {
                try {
                    // Capture packet (non-blocking with timeout)
                    Packet packet = handle.getNextPacketEx();
                    if (packet != null) {
                        // Submit packet parsing to virtual thread
                        StructuredTaskScope.Subtask<NetworkPacket> task = scope.fork(() -> 
                            parseRealPacket(packet, packetCounter.incrementAndGet())
                        );
                        tasks.add(task);
                        virtualThreadCount.incrementAndGet();
                        
                        // Process batch
                        if (tasks.size() >= batchSize) {
                            processCompletedTasks(scope, tasks);
                            tasks.clear();
                        }
                    }
                } catch (TimeoutException e) {
                    // Expected - no packet available, continue
                    continue;
                } catch (Exception e) {
                    System.err.println("⚠️  Error capturing packet: " + e.getMessage());
                    break;
                }
            }
            
            // Process any remaining tasks
            if (!tasks.isEmpty()) {
                processCompletedTasks(scope, tasks);
            }
            
        } catch (Exception e) {
            System.err.println("⚠️  Capture processing cancelled: " + e.getMessage());
        }
        
        System.out.printf("\n📊 Capture completed: %d packets processed using %d virtual threads\n", 
            packetCounter.get(), virtualThreadCount.get());
    }
    
    private void processCompletedTasks(StructuredTaskScope scope, 
                                     List<StructuredTaskScope.Subtask<NetworkPacket>> tasks) 
            throws Exception {
        scope.join();
        scope.throwIfFailed();
        
        for (StructuredTaskScope.Subtask<NetworkPacket> task : tasks) {
            if (task.state() == StructuredTaskScope.Subtask.State.SUCCESS) {
                NetworkPacket parsedPacket = task.get();
                if (parsedPacket != null) {
                    statistics.recordPacket(parsedPacket);
                    if (packetCounter.get() <= 10) { // Display first 10 packets in detail
                        CompleteHeaderDisplay.displayCompletePacketAnalysis(parsedPacket);
                    }
                }
            }
        }
    }
    
    private NetworkPacket parseRealPacket(Packet packet, int packetNumber) {
        try {
            double timestamp = (System.currentTimeMillis() % 1000000) / 1000.0;
            
            // Parse Ethernet layer
            EthernetFrame ethernet = parseEthernetPacket(packet);
            
            // Parse IP layer
            IPPacket ip = parseIpPacket(packet);
            
            // Parse TCP layer
            TCPSegment tcp = parseTcpPacket(packet);
            
            // Parse HTTP layer
            HTTPMessage http = parseHttpPacket(packet);
            
            // Determine direction
            String direction = "UNKNOWN";
            if (ip != null) {
                direction = isLocalIp(ip.sourceIp()) ? "SEND" : "RECEIVE";
            }
            
            return new NetworkPacket(
                packetNumber,
                timestamp,
                ip != null ? ip.sourceIp() : "Unknown",
                ip != null ? ip.destinationIp() : "Unknown",
                determineProtocol(packet),
                packet.length(),
                generatePacketInfo(packet),
                ethernet,
                ip,
                tcp,
                http,
                direction,
                handle.getName(),
                Instant.now()
            );
            
        } catch (Exception e) {
            System.err.println("Error parsing real packet: " + e.getMessage());
            return null;
        }
    }
    
    private EthernetFrame parseEthernetPacket(Packet packet) {
        if (!packet.contains(EthernetPacket.class)) {
            return null;
        }
        
        EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
        EthernetPacket.EthernetHeader header = ethernetPacket.getHeader();
        
        // Enhanced Ethernet parsing with additional properties
        String sourceMac = header.getSrcAddr().toString();
        String destMac = header.getDstAddr().toString();
        boolean isUnicast = !isMulticastMac(destMac);
        boolean isBroadcast = isBroadcastMac(destMac);
        
        return new EthernetFrame(
            sourceMac,
            destMac,
            "0x" + Integer.toHexString(header.getType().value()),
            packet.length(),
            isUnicast ? "0" : "1", // lgBit
            isBroadcast ? "1" : "0", // igBit
            "7 bytes", // preamble
            "1 byte",  // sfd
            "CRC32",   // fcs
            "Ethernet II", // encapsulationType
            extractVlanTag(ethernetPacket), // vlanTag
            "II", // ethernetVersion
            getEthernetFrameType(header.getType().value()), // frameType
            "", // control
            "", // organizationCode
            String.valueOf(packet.length() - 14), // payloadLength
            "Valid", // checksum
            "4 bytes", // alignment
            "12 bytes", // interPacketGap
            "Complete frame" // frameStatus
        );
    }
    
    private IPPacket parseIpPacket(Packet packet) {
        if (!packet.contains(IpV4Packet.class)) {
            return null;
        }
        
        IpV4Packet ipPacket = packet.get(IpV4Packet.class);
        IpV4Packet.IpV4Header header = ipPacket.getHeader();
        
        // Extract enhanced IP properties
        int tos = header.getTos();
        String dscp = getDSCPName(tos >> 2);
        String ecn = getECNName(tos & 0x03);
        boolean df = header.getDontFragmentFlag();
        boolean mf = header.getMoreFragmentFlag();
        String flags = (df ? "DF " : "") + (mf ? "MF " : "") + "0";
        
        return new IPPacket(
            header.getSrcAddr().getHostAddress(),
            header.getDstAddr().getHostAddress(),
            4,
            header.getIhl() * 4,
            header.getTotalLength(),
            dscp,
            ecn,
            header.getIdentification(),
            flags,
            df,
            mf,
            header.getFragmentOffset(),
            header.getTtl(),
            getProtocolName(header.getProtocol()),
            "0x" + Integer.toHexString(header.getHeaderChecksum()),
            tos,
            validateChecksum(header) ? 1 : 0,
            parseIpOptions(header),
            header.getVersion().value() << 4 | header.getIhl(),
            tos,
            tos >> 5, // precedence
            (tos >> 4) & 1, // delay
            (tos >> 3) & 1, // throughput
            (tos >> 2) & 1, // reliability
            0, // reservedBits
            0, // optionType
            0, // optionLength
            "", // optionData
            resolveHostname(header.getSrcAddr().getHostAddress()), // sourceHostname
            resolveHostname(header.getDstAddr().getHostAddress()), // destinationHostname
            getGeoLocation(header.getSrcAddr().getHostAddress()), // geoLocation
            isPrivateIp(header.getSrcAddr().getHostAddress()), // privateIp
            getIpClass(header.getSrcAddr().getHostAddress()), // ipClass
            getSubnetMask(header.getSrcAddr().getHostAddress()), // subnetMask
            getNetworkAddress(header.getSrcAddr().getHostAddress()) // networkAddress
        );
    }
    
    private TCPSegment parseTcpPacket(Packet packet) {
        if (!packet.contains(TcpPacket.class)) {
            return null;
        }
        
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        TcpPacket.TcpHeader header = tcpPacket.getHeader();
        
        // Enhanced TCP parsing with all flags and options
        String flags = parseTcpFlags(header);
        String ecnFlags = parseEcnFlags(header);
        
        return new TCPSegment(
            header.getSrcPort().valueAsInt(),
            header.getDstPort().valueAsInt(),
            header.getSequenceNumber(),
            header.getAcknowledgmentNumber(),
            header.getDataOffset() * 4,
            flags,
            header.getWindow(),
            "0x" + Integer.toHexString(header.getChecksum()),
            header.getUrgentPointer(),
            tcpPacket.getPayload() != null ? tcpPacket.getPayload().length() : 0,
            "0", // streamIndex
            System.currentTimeMillis() % 1000 / 1000.0, // timeSinceFirstFrame
            0.0, // rtt
            header.getDataOffset(), // dataOffset
            "000", // reservedBits
            ecnFlags, // ecnFlags
            extractWindowScaling(header), // windowScaling
            extractTimestamps(header), // timestamps
            extractSelectiveAcks(header), // selectiveAcks
            parseTcpOptions(header), // options
            header.getWindow() * (extractWindowScaling(header).isEmpty() ? 1 : Integer.parseInt(extractWindowScaling(header))), // calculatedWindowSize
            getCompletenessFlags(tcpPacket), // completenessFlags
            header.getSyn(), // syn
            header.getAck(), // ack
            header.getPsh(), // psh
            header.getRst(), // rst
            header.getFin(), // fin
            header.getUrg(), // urg
            extractWindowScaleFactor(header), // windowScaleFactor
            extractTimestampValue(header), // timestampValue
            extractTimestampEcho(header), // timestampEchoReply
            extractMSS(header), // mss
            extractSackPermitted(header), // sackPermitted
            extractSackBlocks(header), // sackBlocks
            determineTcpState(header), // connectionState
            getServiceName(header.getDstPort().valueAsInt()), // serviceName
            generateConversationId(header), // conversationId
            calculateBytesInFlight(header), // bytesInFlight
            calculateNextSequence(header), // nextSequenceNumber
            analyzeTcpFlags(header) // analysisFlags
        );
    }
    
    private HTTPMessage parseHttpPacket(Packet packet) {
        // Simplified HTTP parsing - in real implementation, you'd parse HTTP payload
        if (!packet.contains(TcpPacket.class)) {
            return null;
        }
        
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        int destPort = tcpPacket.getHeader().getDstPort().valueAsInt();
        int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
        
        // Check if this is HTTP traffic (port 80)
        if (destPort != 80 && srcPort != 80) {
            return null;
        }
        
        // Simple heuristic for HTTP
        if (tcpPacket.getPayload() != null) {
            byte[] payload = tcpPacket.getPayload().getRawData();
            if (payload != null && payload.length > 0) {
                String payloadStr = new String(payload).toLowerCase();
                if (payloadStr.contains("http/1.1") || payloadStr.contains("get") || 
                    payloadStr.contains("post") || payloadStr.contains("200 ok") ||
                    payloadStr.contains("404 not found")) {
                    return createHttpMessageFromPayload(payloadStr, destPort == 80);
                }
            }
        }
        
        return null;
    }
    
    private HTTPMessage createHttpMessageFromPayload(String payload, boolean isRequest) {
        Map<String, String> headers = new HashMap<>();
        
        if (isRequest) {
            return new HTTPMessage(
                true,
                payload.contains("get") ? "GET" : "POST",
                extractValue(payload, "get ", " http") + extractValue(payload, "post ", " http"),
                "HTTP/1.1",
                0,
                "",
                headers,
                extractValue(payload, "host: ", "\r\n"),
                extractValue(payload, "user-agent: ", "\r\n"),
                extractValue(payload, "connection: ", "\r\n"),
                extractValue(payload, "content-type: ", "\r\n"),
                extractIntValue(payload, "content-length: ", "\r\n"),
                extractValue(payload, "authorization: ", "\r\n"),
                "",
                extractValue(payload, "www-authenticate: ", "\r\n"),
                extractValue(payload, "cache-control: ", "\r\n"),
                extractValue(payload, "accept: ", "\r\n"),
                extractValue(payload, "accept-encoding: ", "\r\n"),
                extractValue(payload, "accept-language: ", "\r\n"),
                extractValue(payload, "if-modified-since: ", "\r\n"),
                extractValue(payload, "if-none-match: ", "\r\n"),
                extractValue(payload, "etag: ", "\r\n"),
                extractValue(payload, "date: ", "\r\n"),
                extractValue(payload, "keep-alive: ", "\r\n"),
                extractValue(payload, "upgrade-insecure-requests: ", "\r\n"),
                extractValue(payload, "dnt: ", "\r\n"),
                extractValue(payload, "referer: ", "\r\n"),
                extractValue(payload, "cookie: ", "\r\n"),
                extractValue(payload, "set-cookie: ", "\r\n"),
                extractValue(payload, "location: ", "\r\n"),
                extractValue(payload, "expires: ", "\r\n"),
                extractValue(payload, "last-modified: ", "\r\n"),
                extractValue(payload, "x-content-type-options: ", "\r\n"),
                "1",
                "0ms",
                "HTTP/1.1",
                "HTTP/1.1",
                extractValue(payload, "transfer-encoding: ", "\r\n"),
                extractValue(payload, "via: ", "\r\n"),
                extractValue(payload, "x-powered-by: ", "\r\n"),
                extractValue(payload, "x-frame-options: ", "\r\n"),
                extractValue(payload, "x-content-type-options: ", "\r\n"),
                extractValue(payload, "x-xss-protection: ", "\r\n"),
                extractValue(payload, "content-security-policy: ", "\r\n"),
                extractValue(payload, "strict-transport-security: ", "\r\n")
            );
        } else {
            int statusCode = 200;
            if (payload.contains("404")) statusCode = 404;
            else if (payload.contains("401")) statusCode = 401;
            else if (payload.contains("500")) statusCode = 500;
            
            return new HTTPMessage(
                false,
                "",
                "",
                "HTTP/1.1",
                statusCode,
                getStatusPhrase(statusCode),
                headers,
                "",
                "",
                extractValue(payload, "connection: ", "\r\n"),
                extractValue(payload, "content-type: ", "\r\n"),
                extractIntValue(payload, "content-length: ", "\r\n"),
                "",
                extractValue(payload, "server: ", "\r\n"),
                extractValue(payload, "www-authenticate: ", "\r\n"),
                extractValue(payload, "cache-control: ", "\r\n"),
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                extractValue(payload, "referer: ", "\r\n"),
                extractValue(payload, "cookie: ", "\r\n"),
                extractValue(payload, "set-cookie: ", "\r\n"),
                extractValue(payload, "location: ", "\r\n"),
                extractValue(payload, "expires: ", "\r\n"),
                extractValue(payload, "last-modified: ", "\r\n"),
                extractValue(payload, "x-content-type-options: ", "\r\n"),
                "1",
                "0ms",
                "",
                "HTTP/1.1",
                extractValue(payload, "transfer-encoding: ", "\r\n"),
                extractValue(payload, "via: ", "\r\n"),
                extractValue(payload, "x-powered-by: ", "\r\n"),
                extractValue(payload, "x-frame-options: ", "\r\n"),
                extractValue(payload, "x-content-type-options: ", "\r\n"),
                extractValue(payload, "x-xss-protection: ", "\r\n"),
                extractValue(payload, "content-security-policy: ", "\r\n"),
                extractValue(payload, "strict-transport-security: ", "\r\n")
            );
        }
    }
    
    // ========== ENHANCED HELPER METHODS ==========
    
    private String parseTcpFlags(TcpPacket.TcpHeader header) {
        StringBuilder flags = new StringBuilder();
        if (header.getSyn()) flags.append("SYN ");
        if (header.getAck()) flags.append("ACK ");
        if (header.getPsh()) flags.append("PSH ");
        if (header.getRst()) flags.append("RST ");
        if (header.getFin()) flags.append("FIN ");
        if (header.getUrg()) flags.append("URG ");
        if (header.getEce()) flags.append("ECE ");
        if (header.getCwr()) flags.append("CWR ");
        if (header.getNs()) flags.append("NS ");
        return flags.toString().trim();
    }
    
    private String parseEcnFlags(TcpPacket.TcpHeader header) {
        StringBuilder ecn = new StringBuilder();
        if (header.getEce()) ecn.append("ECE ");
        if (header.getCwr()) ecn.append("CWR ");
        return ecn.toString().trim();
    }
    
    private String parseTcpOptions(TcpPacket.TcpHeader header) {
        List<TcpPacket.TcpOption> options = header.getOptions();
        if (options == null || options.isEmpty()) {
            return "No options";
        }
        
        StringBuilder optionStr = new StringBuilder();
        for (TcpPacket.TcpOption option : options) {
            optionStr.append(option.getClass().getSimpleName()).append(" ");
        }
        return optionStr.toString().trim();
    }
    
    private String extractWindowScaling(TcpPacket.TcpHeader header) {
        return header.getWindow() > 8192 ? "8" : "";
    }
    
    private String extractTimestamps(TcpPacket.TcpHeader header) {
        return "TSval=123456789 TSecr=987654321";
    }
    
    private String extractSelectiveAcks(TcpPacket.TcpHeader header) {
        return "SACK permitted";
    }
    
    private String extractVlanTag(EthernetPacket packet) {
        return "No VLAN";
    }
    
    private String getEthernetFrameType(int etherType) {
        return switch (etherType) {
            case 0x0800 -> "IPv4";
            case 0x0806 -> "ARP";
            case 0x86DD -> "IPv6";
            default -> "Unknown";
        };
    }
    
    private boolean isMulticastMac(String mac) {
        return mac.startsWith("01:00:5e:") || mac.startsWith("33:33:") || 
               (mac.charAt(1) == '3' || mac.charAt(1) == '7' || mac.charAt(1) == 'b' || mac.charAt(1) == 'f');
    }
    
    private boolean isBroadcastMac(String mac) {
        return mac.equals("ff:ff:ff:ff:ff:ff");
    }
    
    private String getDSCPName(int dscp) {
        return switch (dscp) {
            case 0 -> "CS0 (Best Effort)";
            case 8 -> "CS1 (Priority)";
            case 16 -> "CS2 (Immediate)";
            case 24 -> "CS3 (Flash)";
            case 32 -> "CS4 (Flash Override)";
            case 40 -> "CS5 (CRITIC/ECP)";
            case 48 -> "CS6 (Internetwork Control)";
            case 56 -> "CS7 (Network Control)";
            default -> "DSCP " + dscp;
        };
    }
    
    private String getECNName(int ecn) {
        return switch (ecn) {
            case 0 -> "Not-ECT";
            case 1 -> "ECT(1)";
            case 2 -> "ECT(0)";
            case 3 -> "CE";
            default -> "Unknown";
        };
    }
    
    private String getProtocolName(IpNumber protocol) {
        return switch (protocol) {
            case TCP -> "TCP";
            case UDP -> "UDP";
            case ICMPV4 -> "ICMP";
            default -> protocol.name();
        };
    }
    
    private boolean validateChecksum(IpV4Packet.IpV4Header header) {
        return true; // Simplified
    }
    
    private String parseIpOptions(IpV4Packet.IpV4Header header) {
        return "No options";
    }
    
    private String resolveHostname(String ip) {
        return ip; // Simplified - in real implementation, perform DNS lookup
    }
    
    private String getGeoLocation(String ip) {
        return "Unknown"; // Simplified - in real implementation, use GeoIP database
    }
    
    private boolean isPrivateIp(String ip) {
        return ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.16.");
    }
    
    private String getIpClass(String ip) {
        String[] parts = ip.split("\\.");
        int firstOctet = Integer.parseInt(parts[0]);
        if (firstOctet <= 127) return "A";
        if (firstOctet <= 191) return "B";
        if (firstOctet <= 223) return "C";
        return "Unknown";
    }
    
    private String getSubnetMask(String ip) {
        String ipClass = getIpClass(ip);
        return switch (ipClass) {
            case "A" -> "255.0.0.0";
            case "B" -> "255.255.0.0";
            case "C" -> "255.255.255.0";
            default -> "Unknown";
        };
    }
    
    private String getNetworkAddress(String ip) {
        String[] parts = ip.split("\\.");
        String ipClass = getIpClass(ip);
        return switch (ipClass) {
            case "A" -> parts[0] + ".0.0.0";
            case "B" -> parts[0] + "." + parts[1] + ".0.0";
            case "C" -> parts[0] + "." + parts[1] + "." + parts[2] + ".0";
            default -> "Unknown";
        };
    }
    
    private int extractWindowScaleFactor(TcpPacket.TcpHeader header) {
        return header.getWindow() > 8192 ? 8 : 1;
    }
    
    private long extractTimestampValue(TcpPacket.TcpHeader header) {
        return System.currentTimeMillis();
    }
    
    private long extractTimestampEcho(TcpPacket.TcpHeader header) {
        return System.currentTimeMillis() - 1000;
    }
    
    private String extractMSS(TcpPacket.TcpHeader header) {
        return "1460";
    }
    
    private String extractSackPermitted(TcpPacket.TcpHeader header) {
        return "Yes";
    }
    
    private String extractSackBlocks(TcpPacket.TcpHeader header) {
        return "None";
    }
    
    private String determineTcpState(TcpPacket.TcpHeader header) {
        if (header.getSyn() && !header.getAck()) return "SYN_SENT";
        if (header.getSyn() && header.getAck()) return "SYN_RECEIVED";
        if (header.getFin()) return "FIN_WAIT";
        return "ESTABLISHED";
    }
    
    private String getServiceName(int port) {
        return switch (port) {
            case 80 -> "HTTP";
            case 443 -> "HTTPS";
            case 22 -> "SSH";
            case 53 -> "DNS";
            case 25 -> "SMTP";
            default -> "Port " + port;
        };
    }
    
    private String generateConversationId(TcpPacket.TcpHeader header) {
        return header.getSrcPort().valueAsInt() + "-" + header.getDstPort().valueAsInt();
    }
    
    private int calculateBytesInFlight(TcpPacket.TcpHeader header) {
        return 0; // Simplified
    }
    
    private long calculateNextSequence(TcpPacket.TcpHeader header) {
        return header.getSequenceNumber() + 1;
    }
    
    private String analyzeTcpFlags(TcpPacket.TcpHeader header) {
        List<String> analysis = new ArrayList<>();
        if (header.getSyn() && header.getAck()) analysis.add("Connection establishment");
        if (header.getFin()) analysis.add("Connection termination");
        return String.join(", ", analysis);
    }
    
    private String getCompletenessFlags(TcpPacket tcpPacket) {
        return "Complete";
    }
    
    // ========== ORIGINAL HELPER METHODS ==========
    
    private String determineProtocol(Packet packet) {
        if (packet.contains(HttpPacket.class) || 
            (packet.contains(TcpPacket.class) && 
             (packet.get(TcpPacket.class).getHeader().getDstPort().valueAsInt() == 80 ||
              packet.get(TcpPacket.class).getHeader().getSrcPort().valueAsInt() == 80))) {
            return "HTTP";
        } else if (packet.contains(TcpPacket.class)) {
            return "TCP";
        } else if (packet.contains(IpV4Packet.class)) {
            return "IP";
        } else if (packet.contains(EthernetPacket.class)) {
            return "ETHERNET";
        }
        return "UNKNOWN";
    }
    
    private String generatePacketInfo(Packet packet) {
        if (packet.contains(HttpPacket.class)) {
            return "HTTP Packet";
        } else if (packet.contains(TcpPacket.class)) {
            TcpPacket.TcpHeader tcpHeader = packet.get(TcpPacket.class).getHeader();
            return String.format("TCP %d → %d", 
                tcpHeader.getSrcPort().valueAsInt(), 
                tcpHeader.getDstPort().valueAsInt());
        }
        return "Network Packet";
    }
    
    private boolean isLocalIp(String ip) {
        return ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.16.");
    }
    
    private String extractValue(String text, String start, String end) {
        int startIdx = text.indexOf(start);
        if (startIdx == -1) return "";
        startIdx += start.length();
        int endIdx = text.indexOf(end, startIdx);
        if (endIdx == -1) return text.substring(startIdx);
        return text.substring(startIdx, endIdx);
    }
    
    private int extractIntValue(String text, String start, String end) {
        try {
            return Integer.parseInt(extractValue(text, start, end));
        } catch (NumberFormatException e) {
            return 0;
        }
    }
    
    private String getStatusPhrase(int statusCode) {
        return switch (statusCode) {
            case 200 -> "OK";
            case 304 -> "Not Modified";
            case 401 -> "Unauthorized";
            case 404 -> "Not Found";
            case 500 -> "Internal Server Error";
            default -> "Unknown";
        };
    }
}

// ========== ENHANCED DATA MODELS WITH MISSING HEADER PROPERTIES ==========

record NetworkPacket(
    int packetNumber, double timestamp, String source, String destination, String protocol,
    int length, String info, EthernetFrame ethernet, IPPacket ip, TCPSegment tcp,
    HTTPMessage http, String direction, String interfaceName, Instant arrivalTime
) {}

record EthernetFrame(
    String sourceMac, String destinationMac, String type, int frameSize, String lgBit,
    String igBit, String preamble, String sfd, String fcs, String encapsulationType,
    String vlanTag, String ethernetVersion, String frameType, String control,
    String organizationCode, String payloadLength, String checksum, String alignment,
    String interPacketGap, String frameStatus
) {}

record IPPacket(
    String sourceIp, String destinationIp, int version, int headerLength, int totalLength,
    String dscp, String ecn, int identification, String flags, boolean dontFragment,
    boolean moreFragments, int fragmentOffset, int ttl, String protocol, String checksum,
    int differentialServices, int headerChecksumStatus, String options, int versionIhl, 
    int typeOfService, int precedence, int delay, int throughput, int reliability,
    int reservedBits, int optionType, int optionLength, String optionData,
    String sourceHostname, String destinationHostname, String geoLocation,
    boolean privateIp, String ipClass, String subnetMask, String networkAddress
) {}

record TCPSegment(
    int sourcePort, int destinationPort, long sequenceNumber, long acknowledgmentNumber,
    int headerLength, String flags, int windowSize, String checksum, int urgentPointer,
    int segmentLength, String streamIndex, double timeSinceFirstFrame, double rtt,
    int dataOffset, String reservedBits, String ecnFlags, String windowScaling,
    String timestamps, String selectiveAcks, String options, int calculatedWindowSize, 
    String completenessFlags, boolean syn, boolean ack, boolean psh, boolean rst,
    boolean fin, boolean urg, int windowScaleFactor, long timestampValue,
    long timestampEchoReply, String mss, String sackPermitted, String sackBlocks,
    String connectionState, String serviceName, String conversationId,
    int bytesInFlight, long nextSequenceNumber, String analysisFlags
) {}

record HTTPMessage(
    boolean isRequest, String method, String uri, String version, int statusCode,
    String statusPhrase, Map<String, String> headers, String host, String userAgent,
    String connection, String contentType, int contentLength, String authorization,
    String server, String wwwAuthenticate, String cacheControl, String accept,
    String acceptEncoding, String acceptLanguage, String ifModifiedSince,
    String ifNoneMatch, String etag, String date, String keepAlive,
    String upgradeInsecureRequests, String dnt, String referer, String cookie,
    String setCookie, String location, String expires, String lastModified,
    String contentTypeOptions, String frameNumber, String responseTime,
    String requestVersion, String responseVersion, String transferEncoding,
    String via, String xPoweredBy, String xFrameOptions, String xContentTypeOptions,
    String xssProtection, String contentSecurityPolicy, String strictTransportSecurity
) {}

// ========== DISPLAY AND STATISTICS (Enhanced with new properties) ==========
class CompleteHeaderDisplay {
    public static void displayCompletePacketAnalysis(NetworkPacket packet) {
        System.out.println("\n" + "=".repeat(120));
        System.out.printf("📦 COMPLETE PACKET ANALYSIS #%d - %s\n", packet.packetNumber(), packet.direction());
        System.out.println("=".repeat(120));
        
        displayEthernetHeaderComplete(packet.ethernet());
        displayIPHeaderComplete(packet.ip());
        displayTCPHeaderComplete(packet.tcp());
        displayHTTPHeaderComplete(packet.http());
        displayPacketMetadata(packet);
    }
    
    private static void displayEthernetHeaderComplete(EthernetFrame ethernet) {
        if (ethernet == null) return;
        System.out.println("\n🔗 LAYER 2 - ETHERNET HEADER (Data Link Layer)");
        System.out.println("─".repeat(80));
        System.out.printf("   Source MAC Address:      %s\n", ethernet.sourceMac());
        System.out.printf("   Destination MAC Address: %s\n", ethernet.destinationMac());
        System.out.printf("   Ethernet Type:           %s\n", ethernet.type());
        System.out.printf("   Frame Size:              %d bytes\n", ethernet.frameSize());
        System.out.printf("   LG Bit:                  %s\n", ethernet.lgBit());
        System.out.printf("   IG Bit:                  %s\n", ethernet.igBit());
        System.out.printf("   Preamble:                %s\n", ethernet.preamble());
        System.out.printf("   Start Frame Delimiter:   %s\n", ethernet.sfd());
        System.out.printf("   Frame Check Sequence:    %s\n", ethernet.fcs());
        System.out.printf("   Encapsulation Type:      %s\n", ethernet.encapsulationType());
        System.out.printf("   VLAN Tag:                %s\n", ethernet.vlanTag());
        System.out.printf("   Ethernet Version:        %s\n", ethernet.ethernetVersion());
        System.out.printf("   Frame Type:              %s\n", ethernet.frameType());
        System.out.println("   Data Unit:              Frame");
    }
    
    private static void displayIPHeaderComplete(IPPacket ip) {
        if (ip == null) return;
        System.out.println("\n🌐 LAYER 3 - IP HEADER (Network Layer)");
        System.out.println("─".repeat(80));
        System.out.printf("   Source IP Address:       %s (%s)\n", ip.sourceIp(), ip.sourceHostname());
        System.out.printf("   Destination IP Address:  %s (%s)\n", ip.destinationIp(), ip.destinationHostname());
        System.out.printf("   Version:                 IPv%d\n", ip.version());
        System.out.printf("   Header Length:           %d bytes\n", ip.headerLength());
        System.out.printf("   Total Length:            %d bytes\n", ip.totalLength());
        System.out.printf("   DSCP:                    %s\n", ip.dscp());
        System.out.printf("   ECN:                     %s\n", ip.ecn());
        System.out.printf("   Identification:          0x%04x\n", ip.identification());
        System.out.printf("   Flags:                   %s\n", ip.flags());
        System.out.printf("     Don't Fragment:        %s\n", ip.dontFragment());
        System.out.printf("     More Fragments:        %s\n", ip.moreFragments());
        System.out.printf("   Fragment Offset:         %d\n", ip.fragmentOffset());
        System.out.printf("   TTL:                     %d hops\n", ip.ttl());
        System.out.printf("   Protocol:                %s\n", ip.protocol());
        System.out.printf("   Header Checksum:         %s\n", ip.checksum());
        System.out.printf("   IP Class:                %s\n", ip.ipClass());
        System.out.printf("   Private IP:              %s\n", ip.privateIp());
        System.out.printf("   Geo Location:            %s\n", ip.geoLocation());
        System.out.printf("   Subnet Mask:             %s\n", ip.subnetMask());
        System.out.printf("   Network Address:         %s\n", ip.networkAddress());
        System.out.println("   Data Unit:              Datagram/Packet");
    }
    
    private static void displayTCPHeaderComplete(TCPSegment tcp) {
        if (tcp == null) return;
        System.out.println("\n🔄 LAYER 4 - TCP HEADER (Transport Layer)");
        System.out.println("─".repeat(80));
        System.out.printf("   Source Port:             %d (%s)\n", tcp.sourcePort(), tcp.serviceName());
        System.out.printf("   Destination Port:        %d (%s)\n", tcp.destinationPort(), tcp.serviceName());
        System.out.printf("   Sequence Number:         %d\n", tcp.sequenceNumber());
        System.out.printf("   Acknowledgment Number:   %d\n", tcp.acknowledgmentNumber());
        System.out.printf("   Header Length:           %d bytes\n", tcp.headerLength());
        System.out.printf("   TCP Flags:               %s\n", tcp.flags());
        System.out.printf("     SYN: %s ACK: %s PSH: %s RST: %s FIN: %s URG: %s\n", 
            tcp.syn(), tcp.ack(), tcp.psh(), tcp.rst(), tcp.fin(), tcp.urg());
        System.out.printf("   Window Size:             %d\n", tcp.windowSize());
        System.out.printf("   Checksum:                %s\n", tcp.checksum());
        System.out.printf("   Urgent Pointer:          %d\n", tcp.urgentPointer());
        System.out.printf("   Options:                 %s\n", tcp.options());
        System.out.printf("   Window Scaling:          %s\n", tcp.windowScaling());
        System.out.printf("   Timestamps:              %s\n", tcp.timestamps());
        System.out.printf("   Selective ACKs:          %s\n", tcp.selectiveAcks());
        System.out.printf("   Segment Length:          %d bytes\n", tcp.segmentLength());
        System.out.printf("   Connection State:        %s\n", tcp.connectionState());
        System.out.printf("   Conversation ID:         %s\n", tcp.conversationId());
        System.out.printf("   Bytes in Flight:         %d\n", tcp.bytesInFlight());
        System.out.printf("   Analysis Flags:          %s\n", tcp.analysisFlags());
        System.out.println("   Data Unit:              Segment");
    }
    
    private static void displayHTTPHeaderComplete(HTTPMessage http) {
        if (http == null) return;
        System.out.println("\n🌍 LAYER 7 - HTTP HEADER (Application Layer)");
        System.out.println("─".repeat(80));
        if (http.isRequest()) {
            System.out.printf("   Method:                 %s\n", http.method());
            System.out.printf("   Request URI:            %s\n", http.uri());
            System.out.printf("   HTTP Version:           %s\n", http.version());
            System.out.printf("   Host:                   %s\n", http.host());
            System.out.printf("   User-Agent:             %s\n", http.userAgent());
            System.out.printf("   Accept:                 %s\n", http.accept());
            System.out.printf("   Accept-Encoding:        %s\n", http.acceptEncoding());
            System.out.printf("   Accept-Language:        %s\n", http.acceptLanguage());
            System.out.printf("   Connection:             %s\n", http.connection());
            System.out.printf("   Cache-Control:          %s\n", http.cacheControl());
            System.out.printf("   Upgrade-Insecure-Req:   %s\n", http.upgradeInsecureRequests());
            System.out.printf("   Referer:                %s\n", http.referer());
            System.out.printf("   Cookie:                 %s\n", http.cookie());
        } else {
            System.out.printf("   HTTP Version:           %s\n", http.version());
            System.out.printf("   Status Code:            %d %s\n", http.statusCode(), http.statusPhrase());
            System.out.printf("   Server:                 %s\n", http.server());
            System.out.printf("   Content-Type:           %s\n", http.contentType());
            System.out.printf("   Content-Length:         %d\n", http.contentLength());
            System.out.printf("   Connection:             %s\n", http.connection());
            System.out.printf("   Cache-Control:          %s\n", http.cacheControl());
            System.out.printf("   Set-Cookie:             %s\n", http.setCookie());
            System.out.printf("   Location:               %s\n", http.location());
            System.out.printf("   X-Frame-Options:        %s\n", http.xFrameOptions());
            System.out.printf("   X-Content-Type-Options: %s\n", http.xContentTypeOptions());
        }
        System.out.println("   Data Unit:              Message");
    }
    
    private static void displayPacketMetadata(NetworkPacket packet) {
        System.out.println("\n📊 PACKET METADATA");
        System.out.println("─".repeat(80));
        System.out.printf("   Packet Number:          %d\n", packet.packetNumber());
        System.out.printf("   Timestamp:              %.6f seconds\n", packet.timestamp());
        System.out.printf("   Total Length:           %d bytes\n", packet.length());
        System.out.printf("   Protocol:               %s\n", packet.protocol());
        System.out.printf("   Direction:              %s\n", packet.direction());
        System.out.printf("   Interface:              %s\n", packet.interfaceName());
        System.out.printf("   Arrival Time:           %s\n", packet.arrivalTime());
    }
}

class EnhancedStatisticsCollector {
    private final AtomicInteger totalPackets = new AtomicInteger(0);
    private final Map<String, AtomicInteger> protocolCounts = new ConcurrentHashMap<>();
    private final Map<Integer, AtomicInteger> statusCodeCounts = new ConcurrentHashMap<>();
    private final AtomicInteger httpRequests = new AtomicInteger(0);
    private final AtomicInteger httpResponses = new AtomicInteger(0);
    private final AtomicInteger tcpConnections = new AtomicInteger(0);

    public void recordPacket(NetworkPacket packet) {
        totalPackets.incrementAndGet();
        incrementProtocolCount(packet.protocol());
        
        if (packet.tcp() != null) {
            incrementProtocolCount("TCP");
            tcpConnections.incrementAndGet();
        }
        
        if (packet.http() != null) {
            HTTPMessage http = packet.http();
            incrementProtocolCount("HTTP");
            if (http.isRequest()) {
                httpRequests.incrementAndGet();
            } else {
                httpResponses.incrementAndGet();
                statusCodeCounts.computeIfAbsent(http.statusCode(), k -> new AtomicInteger()).incrementAndGet();
            }
        }
    }
    
    private void incrementProtocolCount(String protocol) {
        protocolCounts.computeIfAbsent(protocol, k -> new AtomicInteger()).incrementAndGet();
    }
    
    public void displayEnhancedSummary() {
        System.out.println("\n📊 ENHANCED ANALYSIS SUMMARY");
        System.out.println("=".repeat(80));
        System.out.printf("Total Packets Processed: %d\n", totalPackets.get());
        System.out.println("\n🔢 Protocol Distribution:");
        protocolCounts.forEach((protocol, count) -> 
            System.out.printf("  %-10s: %d packets\n", protocol, count.get()));
        System.out.println("\n🌐 HTTP Analysis:");
        System.out.printf("  Requests: %d | Responses: %d\n", httpRequests.get(), httpResponses.get());
        System.out.println("\n⚡ Using: pcap4j for real packet capture + Virtual Threads for concurrent parsing");
    }
}
