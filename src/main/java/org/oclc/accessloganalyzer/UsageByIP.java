/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.accessloganalyzer;

import ORG.oclc.os.JSAP.SimplerJSAP;
import com.martiansoftware.jsap.JSAPException;
import com.martiansoftware.jsap.JSAPResult;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author levan
 */
public class UsageByIP extends Analyzer {

    HashMap<String, Long> longAddrs=new HashMap<>();
    HashMap<String, Long> shortAddrs=new HashMap<>();
    private boolean debug;

    @Override
    public void analyze(String line) {
        String ipAddr = line.substring(0, line.indexOf(' '));
        if(ipAddr.contains(",")) // host and proxy.  Just use host
            ipAddr=ipAddr.substring(0, ipAddr.indexOf(','));
        if(!ipAddr.contains("."))
            return;  // no IP address
        
        Long val = longAddrs.get(ipAddr);
        if(val==null)
            val=0L;
        longAddrs.put(ipAddr, val+1);
        // drop last digit
        String shortAddr = getShortAddress(ipAddr);
        val=shortAddrs.get(shortAddr);
        if(val==null)
            val=0L;
        shortAddrs.put(shortAddr, val+1);
    }

    @Override
    public void init(String[] args) {
        SimplerJSAP jsap;
        try {
            jsap = new SimplerJSAP("[--debug]");
        } catch (JSAPException ex) {
            throw new IllegalArgumentException(ex);
        }
        JSAPResult config = jsap.parse(args);
        debug=config.getBoolean("debug", false);
    }

    @Override
    public void load(String content, Date date) {
        merge(content, 0);
    }

    @Override
    public void merge(String content, int dayNumber) {
        Pattern p = Pattern.compile("<"+this.getClass().getSimpleName()+">(.*?)</"+this.getClass().getSimpleName()+">", Pattern.DOTALL);
        Matcher m=p.matcher(content);
        if(!m.find()) { // probably a new report
            return;
        }
        String usageData = m.group(1);
//    private static final int HTML=0, MARC21=1, RDF=2, SIMPLE_URI=3, XML=4, JUSTLINKS=5, RSS=6, UNIMARC=7, OTHER=8;
        p=Pattern.compile("<ip addr='([^']*)'>(\\d+)</ip>");
        m=p.matcher(usageData);
        long val;
        Long oldVal;
        while(m.find()) {
            String ipAddr=m.group(1);
            val=Long.parseLong(m.group(2));
            oldVal=longAddrs.get(ipAddr);
            if(oldVal==null)
                oldVal=0L;
            longAddrs.put(ipAddr, oldVal+val);
            // drop last digit
            String shortAddr = getShortAddress(ipAddr);
            oldVal=shortAddrs.get(shortAddr);
            if(oldVal==null)
                oldVal=0L;
            shortAddrs.put(shortAddr, oldVal+val);
        }
    }

    @Override
    public Object report() {
        if(debug)System.out.println("in UsageByIP.report()");
        ArrayList<AbstractMap.SimpleEntry<String,Long>> list=new ArrayList<>();
        ValueComparator bvc=new ValueComparator(shortAddrs);
        TreeMap<String, Long> sortedAddrs=new TreeMap<>(Collections.reverseOrder(bvc));
        if(debug)System.out.println("in UsageByIP.report(): about to sort");
        sortedAddrs.putAll(shortAddrs);
        Long val;
        String longAddr, name;
        if(debug)System.out.println("in UsageByIP.report(): adding "+sortedAddrs.keySet().size()+" entries");
        for(String addr:sortedAddrs.keySet()) {
            longAddr=null;
            for(String s:longAddrs.keySet())
                if(s.startsWith(addr)) {
                    longAddr=s;
                    break;
                }
            if(longAddr==null)
                longAddr=addr;
            name=getByAddress(longAddr);
            val=sortedAddrs.get(addr);
            list.add(new AbstractMap.SimpleEntry<>(name, val));
        }
        
        if(debug)System.out.println("in UsageByIP.report(): done");
        return list;
    }

    @Override
    public String unload() {
        ValueComparator bvc=new ValueComparator(longAddrs);
        TreeMap<String, Long> sortedAddrs=new TreeMap<>(Collections.reverseOrder(bvc));
        sortedAddrs.putAll(longAddrs);
        StringBuilder sb=new StringBuilder("<"+this.getClass().getSimpleName()+">\n");
        for(String addr:sortedAddrs.keySet()) {
            sb.append("<ip addr='").append(addr).append("'>").append(sortedAddrs.get(addr)).append("</ip>\n");
        }
        sb.append("</").append(this.getClass().getSimpleName()).append(">");
        return sb.toString();
    }

    class ValueComparator implements Comparator<String> {

        private final Map<String, Long> map;

        public ValueComparator(Map<String, Long> map) {
            this.map=map;
        }
        
        @Override
        public int compare(String a, String b) {
            if(map.get(a).equals(map.get(b)))
                return a.compareTo(b);
            return (int)(map.get(a)-map.get(b));
        }
    }
    
}
