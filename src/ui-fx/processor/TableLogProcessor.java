package processor;

import model.PacketRecord;
import java.util.ArrayList;
import java.util.List;

public class TableLogProcessor implements LogProcessor<PacketRecord> {

    @Override
    public List<PacketRecord> process(List<String> lines) {
        List<PacketRecord> records = new ArrayList<>();
        if (lines == null) return records;

        long frameNo = 0;
        String timestamp = "";
        String srcByIp = "";
        String dstByIp = "";
        String proto = "";
        String len = "";
        String info = "";
        String delay = "";
        StringBuilder currentBlock = new StringBuilder();
        
        boolean hasData = false;

        for (String line : lines) {
            String trimmed = line.trim();
            
            if (trimmed.isEmpty()) continue;
            
            if (trimmed.equals("----")) {
                if (hasData) {
                    records.add(new PacketRecord(frameNo, timestamp, srcByIp, dstByIp, proto, len, info, delay, currentBlock.toString()));
                    // Reset
                    frameNo = 0; timestamp = ""; srcByIp = ""; dstByIp = ""; proto = ""; len = ""; info = ""; delay = "";
                    hasData = false;
                    currentBlock.setLength(0);
                }
                continue;
            }
            
            currentBlock.append(line).append("\n");

            if (trimmed.startsWith("FRAME")) {
                hasData = true;
                frameNo = parseLong(trimmed, "FrameNo=");
                timestamp = parseVal(trimmed, "Timestamp=");
                len = parseVal(trimmed, "Len=");
            } else if (trimmed.startsWith("NETWORK")) {
                hasData = true;
                srcByIp = parseVal(trimmed, "SrcIP=");
                dstByIp = parseVal(trimmed, "DstIP=");
                proto = parseVal(trimmed, "ProtoName="); // TCP/UDP
            } else if (trimmed.startsWith("APP")) {
                 hasData = true;
                 String appProto = parseVal(trimmed, "AppProto=");
                 if (appProto != null && !appProto.isEmpty()) {
                     proto = appProto; // Upgrade proto to App
                     String fl = parseVal(trimmed, "FirstLine=");
                     String sn = parseVal(trimmed, "SNI=");
                     String q = parseVal(trimmed, "Query=");
                     String inf = parseVal(trimmed, "Info=");
                     
                     if (fl != null) info = fl;
                     else if (sn != null && !sn.isEmpty()) info = "Client Hello (SNI=" + sn + ")";
                     else if (q != null) info = "DNS Query " + q;
                     else if (inf != null) info = inf;
                     else info = appProto + " Packet";
                 }
            } else if (trimmed.startsWith("DELAY_SUMMARY")) {
                hasData = true;
                delay = parseVal(trimmed, "TotalNodalDelay=");
            }
        }
        return records;
    }
    
    private String parseVal(String line, String key) {
        int idx = line.indexOf(key);
        if (idx == -1) return null;
        int valStart = idx + key.length();
        int end = line.indexOf("\t", valStart);
        if (end == -1) end = line.length();
        return line.substring(valStart, end).trim();
    }
    
    private long parseLong(String line, String key) {
        String v = parseVal(line, key);
        if (v == null || v.isEmpty()) return 0;
        try {
            return Long.parseLong(v);
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
