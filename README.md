# Abstract

This report presents the design, implementation, and theoretical analysis of a Concurrent Network Packet Analyzer (NETPACKSYS)— a scalable network monitoring system developed using Java Virtual Threads and Structured Concurrency. The NETPACKSYS demonstrates how modern Java concurrency can be effectively combined with object-oriented design principles to achieve high performance, modularity, and clarity. It integrates advanced design patterns, domain modeling, and concurrency mechanisms to analyze packets in real-time with microsecond precision. Beyond implementation, this report systematically evaluates its object-oriented architecture, concurrency models, and performance trade-offs, while aligning its design with the SOLID principles and modern Java design patterns.

---

# Objective

The objective of the NETPACKSYS is to develop a modular and scalable network analyzer that:
• Captures and processes live network packets concurrently.
• Leverages Virtual Threads to achieve high concurrency with minimal memory overhead.
• Utilizes Structured Concurrency to maintain lifecycle safety.
• Applies design patterns and OOP principles systematically.
• Produces accurate delay metrics and transparent, reproducible results.

---

# Description

The analyzer leverages Java Virtual Threads, allowing the creation of thousands of lightweight tasks for concurrent I/O and processing. Structured Concurrency is applied to manage and synchronize concurrent packet-processing tasks safely. The system measures and records nodal delays at multiple levels and produces tab-separated Wireshark-style log files. Each packet’s timestamp, protocol, and computed delay are logged both to the console and a persistent file (packet_analysis_log.txt) for verification and analysis.

---

# Implementation Idea

The analyzer integrates object-oriented design, Java concurrency, and domain-driven modeling to build a scalable and maintainable architecture.

'' 1 Capture and Processing Flow
Using the pcap4j library, the system captures live packets from a network interface. Each packet is immediately dispatched to a virtual thread for parsing and delay computation. Packets are processed in structured batches, ensuring all tasks complete safely before new batches begin.
public final class PacketProcessor {
private final List<LayerParser> parsers;
private final StructuredBatchExecutor executor;

    public void process(PcapPacketStub packet, long frameNo) {
        PacketContext ctx = new PacketContext(frameNo, packet);
        for (LayerParser parser : parsers) {
            parser.parse(ctx);
        }
    }}

'' 2 Structured Concurrency Execution
The StructuredBatchExecutor component ensures controlled concurrency, using lightweight threads and batch task scopes:
public static final class StructuredBatchExecutor {
private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    public <T> Future<T> submitBatchTask(Callable<T> task) {
        return executor.submit(task);
    }}

'' 3 Delay Analysis and Output
Each packet’s delay is represented through a DelayInfo record:
    
    public  record DelayInfo(
    double processingDelay,
    double transmissionDelay,
    double propagationDelay,
    double queuingDelay
    ) { }
    
These delays are calculated based on packet size, link speed, and simulated propagation parameters. Output is logged in both console and file form for verification and reproducibility.

---

# Technologies Used

1. Language: Java 21+ / 22
2. Libraries: pcap4j (for live packet capture)
3. Concurrency: Virtual Threads, Structured Concurrency (ExecutorService, Phaser)
4. Utilities: Java Streams, Atomic Variables, File I/O
5. Patterns Applied: Template Method, Modular Composition, Record-based Domain Modeling
6. Environment: IntelliJ IDEA, Java SDK 22

---

# System Design Overview

The analyzer follows modular OOP design guided by SOLID principles. Each component serves a single purpose—packet capture, parsing, delay analysis, and logging. While some classical patterns (e.g., Factory, Strategy) are conceptually applied, the design emphasizes structured modularity and modern concurrency models.

---

# Architecture & Directory Structure
The project has been refactored for clarity and modularity (replacing the old `netpacksys` package structure):

*   **`src/core/`**: Core analyzer logic (Package: `core`).
*   **`src/tests/`**: Unit tests for the core analyzer (Package: `core`).
*   **`src/ui-fx/`**: JavaFX Log Viewer module (Package: `processor`, `presenter`, `service`).

# Building & Testing

## Core module
1) Ensure JDK 21+ is available.
2) Run tests:
```bash
mvn clean test
```
3) Package and Run:
```bash
mvn package
java -jar target/NetPackSys-1.0-SNAPSHOT-jar-with-dependencies.jar
```

## JavaFX viewer (independent module)
```powershell
cd src/ui-fx
mvn clean test
mvn javafx:run
```