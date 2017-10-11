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
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author levan
 */
public abstract class CountOfThingsByIP extends Analyzer {

    HashMap<String, HashMap<String, Long>> longAddrs=new HashMap<>();
    HashMap<String, HashMap<String, Long>> shortAddrs=new HashMap<>();
    TreeSet<String> listOfThings= new TreeSet<>();
    boolean debug;

    public abstract String getThing(String line);
    
    @Override
    public void analyze(String line) {
        String ipAddr = line.substring(0, line.indexOf(' '));
        if(ipAddr.contains(",")) // host and proxy.  Just use host
            ipAddr=ipAddr.substring(0, ipAddr.indexOf(','));
        if(!ipAddr.contains("."))
            return;  // no IP address
        HashMap<String, Long> h = longAddrs.get(ipAddr);
        if(h==null)
            h=new HashMap<>();
        String thing=getThing(line);
        if(thing==null)
            return;
        listOfThings.add(thing);
        Long val;
        val=h.get(thing);
        if(val==null)
            val=0L;
        h.put(thing, val+1);
        val=h.get("__total");
        if(val==null)
            val=0L;
        h.put("__total", val+1);
        longAddrs.put(ipAddr, h);
        // drop last digit
        String shortAddr = getShortAddress(ipAddr);
        h=shortAddrs.get(shortAddr);
        if(h==null)
            h=new HashMap<>();
        val=h.get(thing);
        if(val==null)
            val=0L;
        h.put(thing, val+1);
        val=h.get("__total");
        if(val==null)
            val=0L;
        h.put("__total", val+1);
        shortAddrs.put(shortAddr, h);
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
        longAddrs.clear();
        shortAddrs.clear();
        merge(content, 0);
    }

    @Override
    public void merge(String content, int dayNumber) {
        Pattern p = Pattern.compile("<"+this.getClass().getSimpleName()+">(.*?)</"+this.getClass().getSimpleName()+">", Pattern.DOTALL);
        Matcher m=p.matcher(content), thingsMatcher;
        if(!m.find()) { // probably a new report
            return;
        }
        String usageData = m.group(1);
        p=Pattern.compile("<ip addr='([^']*)' ([^/]*)/>");
        m=p.matcher(usageData);
        Pattern thingsPattern=Pattern.compile("(\\w*)='([^']*)'");
        HashMap<String, Long> longMap, shortMap;
        Long val;
        long newVal;
        String thing, things;
        while(m.find()) {
            String ipAddr=m.group(1);
            longMap=longAddrs.get(ipAddr);
            if(longMap==null)
                longMap=new HashMap<>();
            // drop last digit
            String shortAddr = getShortAddress(ipAddr);
            shortMap=shortAddrs.get(shortAddr);
            if(shortMap==null)
                shortMap=new HashMap<>();

            // loop through cached values and add them to the hashmaps
            things=m.group(2);
            thingsMatcher=thingsPattern.matcher(things);
            while(thingsMatcher.find()) {
                thing=thingsMatcher.group(1);
                listOfThings.add(thing);
                newVal=Long.parseLong(thingsMatcher.group(2));
                val=longMap.get(thing);
                if(val==null)
                    val=0L;
                longMap.put(thing, val+newVal);
                val=shortMap.get(thing);
                if(val==null)
                    val=0L;
                shortMap.put(thing, val+newVal);
            }
            
            longAddrs.put(ipAddr, longMap);
            shortAddrs.put(shortAddr, shortMap);
        }
    }

    @Override
    public Object report() {
        HashMap<String, Object> map=new HashMap<>();
        ArrayList<AbstractMap.SimpleEntry<String,long[]>> list=new ArrayList<>();
        ValueComparator bvc=new ValueComparator(shortAddrs);
        TreeMap<String, HashMap<String, Long>> sortedAddrs=new TreeMap<>(Collections.reverseOrder(bvc));
        sortedAddrs.putAll(shortAddrs);
        HashMap<String, Long> h;
        long vals[];
        Long val;
        String longAddr, name;
        int i;
        for(String addr:sortedAddrs.keySet()) {
            // convert shortAddr to longAddr
            longAddr=null;
            for(String s:longAddrs.keySet())
                if(s.startsWith(addr)) {
                    longAddr=s;
                    break;
                }
//            System.out.println("short="+addr+", long="+longAddr);
            if(longAddr==null)
                longAddr=addr;
            name=getByAddress(longAddr);
            h=sortedAddrs.get(addr);
            i=0;
            vals=new long[listOfThings.size()];
            for(String thing:listOfThings) {
                val=h.get(thing);
                if(val==null)
                    val=0L;
                vals[i++]=val;
            }
            list.add(new AbstractMap.SimpleEntry<>(name, vals));
        }
        
        map.put("listOfThings", listOfThings);
        map.put("ipData", list);
        return map;
    }

    @Override
    public String unload() {
        ValueComparator bvc=new ValueComparator(longAddrs);
        TreeMap<String, HashMap<String, Long>> sortedAddrs=new TreeMap<>(Collections.reverseOrder(bvc));
        sortedAddrs.putAll(longAddrs);
        long val;
        StringBuilder sb=new StringBuilder("<"+this.getClass().getSimpleName()+">\n");
        HashMap<String, Long> h;
        for(String addr:sortedAddrs.keySet()) {
            h=sortedAddrs.get(addr);
            sb.append("<ip addr='").append(addr).append("'");
            for(String thing:h.keySet()) {
                val=h.get(thing);
                if(val>0)
                    sb.append(" ").append(thing).append("='").append(val).append("'");
            }
            sb.append("'/>\n");
        }
        sb.append("</").append(this.getClass().getSimpleName()).append(">\n");
        return sb.toString();
    }

    private class ValueComparator implements Comparator<String> {

        private final Map<String, HashMap<String, Long>> map;

        public ValueComparator(Map<String, HashMap<String, Long>> map) {
            this.map=map;
        }
        
        @Override
        public int compare(String a, String b) {
            if(map.get(a).get("__total").equals(map.get(b).get("__total")))
                return a.compareTo(b);
            return (int)(map.get(a).get("__total")-map.get(b).get("__total"));
        }
    }
    
}
