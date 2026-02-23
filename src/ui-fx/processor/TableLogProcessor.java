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
        String proto = "N/A";
        String len = "0";
        String info = "";
        String delay = "";
        StringBuilder currentBlock = new StringBuilder();
        
        boolean hasData = false;

        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            
            // The "----" marks the end of a single packet's multi-layered data block.
            if (trimmed.equals("----")) {
                if (hasData) {
                    addRecord(records, frameNo, timestamp, srcByIp, dstByIp, proto, len, info, delay, currentBlock.toString());
                    // Reset everything for the next packet
                    frameNo = 0; timestamp = ""; srcByIp = ""; dstByIp = ""; proto = "N/A"; len = "0"; info = ""; delay = "";
                    hasData = false;
                    currentBlock.setLength(0);
                }
                continue;
            }
            
            currentBlock.append(line).append("\n");

            // Extract values based on layer prefixes.
            // Note: The order in the log might vary, so we capture whatever appears within the block.
            if (trimmed.startsWith("FRAME")) {
                hasData = true;
                frameNo = parseLong(trimmed, "FrameNo=");
                timestamp = parseVal(trimmed, "Timestamp=");
                len = parseVal(trimmed, "Len=");
            } else if (trimmed.startsWith("NETWORK")) {
                hasData = true;
                srcByIp = parseVal(trimmed, "SrcIP=");
                dstByIp = parseVal(trimmed, "DstIP=");
                String p = parseVal(trimmed, "ProtoName=");
                if (p != null && (proto.equals("N/A") || proto.isEmpty())) proto = p;
            } else if (trimmed.startsWith("TRANSPORT")) {
                hasData = true;
                String p = parseVal(trimmed, "ProtoName=");
                if (p != null) proto = p;
            } else if (trimmed.startsWith("APP")) {
                 hasData = true;
                 String appProto = parseVal(trimmed, "AppProto=");
                 if (appProto != null && !appProto.isEmpty()) {
                     proto = appProto;
                     String fl = parseVal(trimmed, "FirstLine=");
                     String sn = parseVal(trimmed, "SNI=");
                     String q = parseVal(trimmed, "Query=");
                     String inf = parseVal(trimmed, "Info=");
                     
                     if (fl != null) info = fl;
                     else if (sn != null && !sn.isEmpty()) info = "Client Hello (SNI=" + sn + ")";
                     else if (q != null) info = "DNS Query " + q;
                     else if (inf != null) info = inf;
                 }
            } else if (trimmed.startsWith("DELAY_SUMMARY")) {
                hasData = true;
                String dValue = parseVal(trimmed, "TotalNodalDelay=");
                if (dValue != null && !dValue.startsWith("0.000000")) {
                    delay = dValue;
                }
            }
        }
        
        // Final fallback for the very last block if there's no trailing "----"
        if (hasData) {
            addRecord(records, frameNo, timestamp, srcByIp, dstByIp, proto, len, info, delay, currentBlock.toString());
        }
        return records;
    }

    private void addRecord(List<PacketRecord> records, long frameNo, String timestamp, String srcByIp, String dstByIp, 
                           String proto, String len, String info, String delay, String rawContent) {
        
        // Final fallback if frameNo is still 0 (should not happen with new log order)
        long finalFrameNo = frameNo;
        if (finalFrameNo <= 0 && !records.isEmpty()) {
            finalFrameNo = records.get(records.size() - 1).frameNo() + 1;
        }

        // wording: 'X Packet Delay'
        String finalDelay = (delay == null || delay.isEmpty() || delay.equals("0.0 ms") || delay.startsWith("0.000000") || delay.contains("0.000000")) 
                ? (finalFrameNo + " Packet Delay") : delay;
                
        String finalInfo = (info == null || info.isEmpty()) ? (proto + " Packet") : info;
        
        records.add(new PacketRecord(
            finalFrameNo, 
            (timestamp != null && !timestamp.isEmpty()) ? timestamp : "N/A", 
            (srcByIp != null && !srcByIp.isEmpty()) ? srcByIp : "N/A", 
            (dstByIp != null && !dstByIp.isEmpty()) ? dstByIp : "N/A", 
            proto, 
            len, 
            finalInfo, 
            finalDelay, 
            rawContent
        ));
    }
    
    private String parseVal(String line, String key) {
        int idx = line.indexOf(key);
        if (idx == -1) return null;
        int valStart = idx + key.length();
        // The value ends at the next tab character or end of line
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
