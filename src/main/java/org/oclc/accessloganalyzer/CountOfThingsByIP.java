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
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import static org.oclc.accessloganalyzer.CountOfThings.cleanThing;

/**
 *
 * @author levan
 */
public abstract class CountOfThingsByIP extends Analyzer {

    Counter<String> longCounts=new Counter<>();
    Counter<String> notBlacklistedLongCounts=new Counter<>();
    Counter<String> shortCounts=new Counter<>();
    Counter<String> notBlacklistedShortCounts=new Counter<>();
    HashMap<String, Counter<String>> longAddrs=new HashMap<>();
    HashMap<String, Counter<String>> shortAddrs=new HashMap<>();
    HashMap<String, Counter<String>> notBlacklistedLongAddrs=new HashMap<>();
    HashMap<String, Counter<String>> notBlacklistedShortAddrs=new HashMap<>();
    Counter<String> listOfThings= new Counter<>();
    boolean debug;
    int maxThings=20;
    long otherCount;
    private boolean debugGetIPData;

    public abstract List<String> getThings(String line);
    
    @Override
    public void analyze(String line) {
        for(String thing:getThings(line)) {
            thing=cleanThing(thing); // let's make sure this is legal junk
            listOfThings.increment(thing);
            String ipAddr = line.substring(0, line.indexOf(' '));
            if(ipAddr.contains(",")) // host and proxy.  Just use host
                ipAddr=ipAddr.substring(0, ipAddr.indexOf(','));
            if(!ipAddr.contains("."))
                return;  // no IP address
            ipAddr=getIdenticalIP(ipAddr);
            Counter<String> counter = longAddrs.get(ipAddr);
            if(counter==null)
                counter=new Counter<>();
            counter.increment(thing);
            counter.increment("__total");
            longAddrs.put(ipAddr, counter);
            longCounts.increment(ipAddr);
            if(!isBlacklisted()) {
                counter = notBlacklistedLongAddrs.get(ipAddr);
                if(counter==null)
                    counter=new Counter<>();
                counter.increment(thing);
                counter.increment("__total");
                notBlacklistedLongAddrs.put(ipAddr, counter);
                notBlacklistedLongCounts.increment(ipAddr);
            }
            // drop last digit
            String shortAddr = getShortAddress(ipAddr);
            counter=shortAddrs.get(shortAddr);
            if(counter==null)
                counter=new Counter<>();
            counter.increment(thing);
            counter.increment("__total");
            shortAddrs.put(shortAddr, counter);
            shortCounts.increment(shortAddr);
            if(!isBlacklisted()) {
                counter = notBlacklistedShortAddrs.get(shortAddr);
                if(counter==null)
                    counter=new Counter<>();
                counter.increment(thing);
                counter.increment("__total");
                notBlacklistedShortAddrs.put(shortAddr, counter);
                notBlacklistedShortCounts.increment(shortAddr);
            }
        }
    }

    private ArrayList<AbstractMap.SimpleEntry<String, long[]>> getIPData(
            List<Map.Entry<String, Long>> mostCommonThingsList, 
            List<Map.Entry<String, Long>> sortedAddrs, 
            HashMap<String, Counter<String>> addrs) {
        TreeMap<String, Long> mostCommonThingsMap;
        boolean tooManyThings=false;
        Counter<String> thingsForThisAddr;
        long vals[];
        Long val;
        String name;

        if(debugGetIPData) {
            System.out.println("in "+this.getClass().getSimpleName());
            System.out.println("mostCommonThingsList="+mostCommonThingsList);
            System.out.println("sortedAddrs="+sortedAddrs);
        }
        otherCount=0;
        if(mostCommonThingsList.size()<listOfThings.size()) {
            tooManyThings=true;
            mostCommonThingsMap=new TreeMap<>();
            for(Map.Entry<String, Long> entry:mostCommonThingsList)
                mostCommonThingsMap.put(entry.getKey(), entry.getValue());
            List<Map.Entry<String, Long>> l = listOfThings.most_common();
            for(int i=maxThings; i<l.size(); i++)
                otherCount=+l.get(i).getValue();
        }
        else
            mostCommonThingsMap=listOfThings;

        ArrayList<AbstractMap.SimpleEntry<String,long[]>> list=new ArrayList<>();
        String addr;
        for(Map.Entry<String, Long> entry:sortedAddrs) {
            addr=entry.getKey();
            name=getByAddress(addr+".0");
            if(name==null) {
                System.out.println("**** null returned for longAddr "+addr+".0");
                continue;
            }
            thingsForThisAddr=addrs.get(addr);
            if(thingsForThisAddr==null) {
                System.out.println("in "+this.getClass().getSimpleName()+": no things for addr="+addr);
                continue;
            }
            if(debugGetIPData) {
                System.out.println("in getIPData: addr="+addr+", count="+entry.getValue()+", name="+name+", thingsForThisAddr="+thingsForThisAddr);
            }
            int i=0;
            long other=0;
            if(tooManyThings) {
                vals=new long[mostCommonThingsList.size()+1];
                for(String thing: thingsForThisAddr.keySet()) {
                    if(mostCommonThingsMap.get(thing)==null)
                        other+=thingsForThisAddr.get(thing);
                }
            }
            else
                vals=new long[mostCommonThingsList.size()];
            // create array of counts in mostCommonThings order
            for(Map.Entry<String, Long> thing:mostCommonThingsList) {
                val=thingsForThisAddr.get(thing.getKey());
                if(val==null)
                    val=0L;
                vals[i++]=val;
            }
            if(tooManyThings)
                vals[i]=other;
            list.add(new AbstractMap.SimpleEntry<>(name, vals));
        }
        return list;
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
        if(debug)
            System.out.println(this.getClass().getSimpleName()+": debug=true");
    }

    @Override
    public void load(String content, Date date) {
        longAddrs.clear();
        notBlacklistedLongAddrs.clear();
        shortAddrs.clear();
        notBlacklistedShortAddrs.clear();
        listOfThings.clear();
        shortCounts.clear();
        longCounts.clear();
        notBlacklistedShortCounts.clear();
        notBlacklistedLongCounts.clear();
        merge(content, 0);
    }

    @Override
    public void merge(String content, int dayNumber) {
        Pattern p = Pattern.compile("<"+this.getClass().getSimpleName()+">(.*?)</"+this.getClass().getSimpleName()+">", Pattern.DOTALL);
        Matcher m=p.matcher(content), thingsMatcher;
        if(!m.find()) { // probably a new report
            if(debug)
                System.out.println("no content for "+this.getClass().getSimpleName());
            return;
        }
        String usageData = m.group(1);
        p=Pattern.compile("<ip addr='([^']*)' ([^>]*)/>");
        m=p.matcher(usageData);
        Pattern thingsPattern=Pattern.compile("\\s*([^=]*)='([^/]*)/([^']*)'");
        Counter<String> longMap, notBlacklistedLongMap, notBlacklistedShortMap, shortMap;
        long nbVal, newVal;
        String thing, things;
        while(m.find()) {
            String ipAddr=m.group(1);
            longMap=longAddrs.get(ipAddr);
            if(longMap==null)
                longMap=new Counter<>();
            notBlacklistedLongMap=notBlacklistedLongAddrs.get(ipAddr);
            if(notBlacklistedLongMap==null)
                notBlacklistedLongMap=new Counter<>();
            // drop last digit
            String shortAddr = getShortAddress(ipAddr);
            shortMap=shortAddrs.get(shortAddr);
            if(shortMap==null)
                shortMap=new Counter<>();
            notBlacklistedShortMap=notBlacklistedShortAddrs.get(shortAddr);
            if(notBlacklistedShortMap==null)
                notBlacklistedShortMap=new Counter<>();

            // loop through cached values and add them to the hashmaps
            things=m.group(2);
            thingsMatcher=thingsPattern.matcher(things);
            while(thingsMatcher.find()) {
                thing=thingsMatcher.group(1);
                newVal=Long.parseLong(thingsMatcher.group(2));
                if(thing.equals("__total")) {
                    shortCounts.increment(shortAddr, newVal);
                    longCounts.increment(ipAddr, newVal);
                }
                else
                    listOfThings.increment(thing, newVal);
                longMap.increment(thing, newVal);
                shortMap.increment(thing, newVal);
                
                nbVal=Long.parseLong(thingsMatcher.group(3));
                if(nbVal>0) {
                    notBlacklistedLongMap.increment(thing, nbVal);
                    notBlacklistedShortMap.increment(thing, nbVal);
                    if(thing.equals("__total")) {
                        notBlacklistedShortCounts.increment(shortAddr, nbVal);
                        notBlacklistedLongCounts.increment(ipAddr, nbVal);
                    }
                }
            }
            
            longAddrs.put(ipAddr, longMap);
            if(!notBlacklistedLongMap.isEmpty())
                notBlacklistedLongAddrs.put(ipAddr, notBlacklistedLongMap);
            shortAddrs.put(shortAddr, shortMap);
            if(!notBlacklistedShortMap.isEmpty())
                notBlacklistedShortAddrs.put(shortAddr, notBlacklistedShortMap);
        }
        if(debug)
            System.out.println(this.getClass().getSimpleName()+": #longAddrs="+longAddrs.size()+", #notBlacklistedLongAddrs="+notBlacklistedLongAddrs.size());
    }

    @Override
    public Object report() {
        HashMap<String, Object> map=new HashMap<>();
        List<Map.Entry<String, Long>> mostCommonThingsList = listOfThings.most_common(maxThings);
        if(mostCommonThingsList.size()<listOfThings.size()) {
            ArrayList<Map.Entry<String, Long>> temp = new ArrayList<>();
            temp.addAll(mostCommonThingsList);
            temp.add(new AbstractMap.SimpleEntry<>("other", otherCount));
            map.put("listOfThings", temp);
        } else {
            map.put("listOfThings", mostCommonThingsList);
        }
        map.put("ipData", getIPData(mostCommonThingsList, shortCounts.most_common(), shortAddrs));
        debugGetIPData=false;
        map.put("notBlacklistedIpData", getIPData(mostCommonThingsList, notBlacklistedShortCounts.most_common(), notBlacklistedShortAddrs));
        debugGetIPData=false;
        return map;
    }

    @Override
    public String unload() {
        long val;
        Long zero=0L;
        String addr;
        StringBuilder sb=new StringBuilder("<"+this.getClass().getSimpleName()+">\n");
        Counter<String> h, h2;
        List<Map.Entry<String, Long>> mostCommon = longCounts.most_common();
        for(Map.Entry<String, Long> entry:mostCommon) {
            addr=entry.getKey();
            h=longAddrs.get(addr);
            h2=notBlacklistedLongAddrs.get(addr);
            if(h2==null)
                h2=new Counter();
            sb.append("<ip addr='").append(addr).append("'");
            for(String thing:h.keySet()) {
                val=h.get(thing);
                if(val>0) {
                    sb.append(" ").append(escapeEntityName(thing)).append("='").append(val).append('/').append(h2.getOrDefault(thing, zero)).append("'");
                }
            }
            sb.append("/>\n");
        }
        sb.append("</").append(this.getClass().getSimpleName()).append(">\n");
        return sb.toString();
    }
}
