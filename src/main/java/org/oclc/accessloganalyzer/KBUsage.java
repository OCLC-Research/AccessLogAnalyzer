/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.accessloganalyzer;

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
public class KBUsage extends Analyzer {
    public static Pattern getRequestPattern=Pattern.compile("\"GET\\s+/webservices/kb/([^\\s]+)[^\"]+\"\\s+(\\d{3})");

    HashMap<String, Integer> longAddrs=new HashMap<>();
    HashMap<String, Integer> shortAddrs=new HashMap<>();
    HashMap<String, Integer> wskeys=new HashMap<>();

    @Override
    public void analyze(String line) {
        Matcher m = getRequestPattern.matcher(line);
        if(!m.find())
            return;
        String request=m.group(1);
        int i;
        if((i=request.indexOf("wskey="))>0) {
            String key=request.substring(i+6);
            if((i=key.indexOf('&'))>0)
                key=key.substring(0, i);
            if(key.length()!=80) {
                System.out.println("bogus wskey: "+key);
                return;
            }
            Integer count=wskeys.get(key);
            if(count==null)
                count=0;
            wskeys.put(key, count+1);
        }
        else {
            String ipAddr= line.substring(0, line.indexOf(' '));
            if(ipAddr.contains(",")) // host and proxy.  Just use host
                ipAddr=ipAddr.substring(0, ipAddr.indexOf(','));
            if(!ipAddr.contains("."))
                return;  // no IP address
            Integer count = longAddrs.get(ipAddr);
            if(count==null)
                count=0;
            longAddrs.put(ipAddr, count+1);
            String shortAddr = getShortAddress(ipAddr);
            count=shortAddrs.get(shortAddr);
            if(count==null)
                count=0;
            shortAddrs.put(shortAddr, count+1);
        }
    }

    @Override
    public void init(String[] args) {
    }

    @Override
    public void load(String content, Date date) {
        merge(content, 0);
    }

    @Override
    public void merge(String content, int dayNumber) {
        Pattern p = Pattern.compile("<KBUsage>(.*?)</KBUsage>", Pattern.DOTALL);
        Matcher m=p.matcher(content);
        if(!m.find()) // probably a new report
            return;
        String usageData = m.group(1);
        p=Pattern.compile("<wskey value='([^']*)'>([^<]*)</wskey>");
        m=p.matcher(usageData);
        Integer prev;
        while(m.find()) {
            String wskey=m.group(1);
            int count=Integer.parseInt(m.group(2));
            prev=wskeys.get(wskey);
            if(prev==null)
                prev=0;
            wskeys.put(wskey, count+prev);
        }

        p=Pattern.compile("<ip addr='([^']*)'>([^<]*)</ip>");
        m=p.matcher(usageData);
        while(m.find()) {
            String longAddr=m.group(1);
            int count=Integer.parseInt(m.group(2));
            prev = longAddrs.get(longAddr);
            if(prev==null)
                prev=0;
            longAddrs.put(longAddr, prev+count);
            String shortAddr = getShortAddress(longAddr);
            prev=shortAddrs.get(shortAddr);
            if(prev==null)
                prev=0;
            shortAddrs.put(shortAddr, prev+count);
        }
    }

    @Override
    public Object report() {
        HashMap<String, ArrayList<AbstractMap.SimpleEntry<String,Long>>> map=new HashMap<>();
        ArrayList<AbstractMap.SimpleEntry<String,Long>> list=new ArrayList<>();
        ValueComparator bvc=new ValueComparator(wskeys);
        TreeMap<String, Integer> sortedWskeys=new TreeMap<>(Collections.reverseOrder(bvc));
        sortedWskeys.putAll(wskeys);
        long count;
        for(String wskey:sortedWskeys.keySet()) {
            count=sortedWskeys.get(wskey);
            list.add(new AbstractMap.SimpleEntry<>(wskey, count));
        }
        map.put("CountByWskey", list);
        
        list=new ArrayList<>();
        bvc=new ValueComparator(shortAddrs);
        TreeMap<String, Integer> sortedAddrs=new TreeMap<>(Collections.reverseOrder(bvc));
        sortedAddrs.putAll(shortAddrs);
        String longAddr, name;
        for(String addr:sortedAddrs.keySet()) {
            count=sortedAddrs.get(addr);
            longAddr=null;
            for(String s:longAddrs.keySet())
                if(s.startsWith(addr)) {
                    longAddr=s;
                    break;
                }
            if(longAddr==null)
                longAddr=addr;
            name=getByAddress(longAddr);
            list.add(new AbstractMap.SimpleEntry<>(name, count));
        }
        map.put("CountByIP", list);
        return map;
    }

    @Override
    public String unload() {
        ValueComparator bvc=new ValueComparator(wskeys);
        TreeMap<String, Integer> sortedAddrs=new TreeMap<>(Collections.reverseOrder(bvc));
        sortedAddrs.putAll(wskeys);
        StringBuilder sb=new StringBuilder("<KBUsage>\n");
        for(String addr:sortedAddrs.keySet()) {
            int count=sortedAddrs.get(addr);
            sb.append("<wskey value='").append(addr)
              .append("'>")
              .append(count)
              .append("</wskey>\n");
        }

        bvc=new ValueComparator(longAddrs);
        sortedAddrs=new TreeMap<>(Collections.reverseOrder(bvc));
        sortedAddrs.putAll(longAddrs);
        for(String addr:sortedAddrs.keySet()) {
            int count=sortedAddrs.get(addr);
            sb.append("<ip addr='").append(addr)
              .append("'>")
              .append(count)
              .append("</ip>\n");
        }
        sb.append("</KBUsage>");
        return sb.toString();
    }

    class ValueComparator implements Comparator<String> {
        private final Map<String, Integer> map;

        public ValueComparator(Map<String, Integer> map) {
            this.map=map;
        }
        
        @Override
        public int compare(String a, String b) {
            if(map.get(a).equals(map.get(b)))
                return a.compareTo(b);
            return map.get(a)-map.get(b);
        }
    }
}