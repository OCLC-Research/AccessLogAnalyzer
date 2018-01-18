/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.accessloganalyzer;

import ORG.oclc.os.JSAP.SimplerJSAP;
import com.martiansoftware.jsap.JSAPException;
import com.martiansoftware.jsap.JSAPResult;
import static java.net.HttpURLConnection.HTTP_OK;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import static org.oclc.accessloganalyzer.Analyzer.logEntryPattern;
import static org.oclc.accessloganalyzer.CountOfThings.cleanThing;

/**
 *
 * @author levan
 */
public abstract class CountOfThingsByReferer extends Analyzer {

    Counter<String> refererCounts=new Counter<>();
    Counter<String> notBlacklistedRefererCounts=new Counter<>();
    HashMap<String, Counter<String>> referers=new HashMap<>();
    HashMap<String, Counter<String>> notBlacklistedReferers=new HashMap<>();
    Counter<String> listOfThings= new Counter<>();
    boolean debug;
    int maxThings=20;
    long otherCount;

    public abstract List<String> getThings(String line);
    
    @Override
    public void analyze(String line) {
        Matcher m = logEntryPattern.matcher(line);
        if(!m.find())
            return;
        if(Integer.parseInt(m.group("StatusCode"))!=HTTP_OK)
            return;
        String referer=m.group("Referer");
        if(referer==null || referer.isEmpty() || referer.equals("-"))
            return;
        for(String thing:getThings(line)) {
            thing=cleanThing(thing); // let's make sure this is legal junk
            listOfThings.increment(thing);
            Counter<String> counter = referers.get(referer);
            if(counter==null)
                counter=new Counter<>();
            counter.increment(thing);
            counter.increment("__total");
            referers.put(referer, counter);
            refererCounts.increment(referer);
            if(!isBlacklisted()) {
                counter = notBlacklistedReferers.get(referer);
                if(counter==null)
                    counter=new Counter<>();
                counter.increment(thing);
                counter.increment("__total");
                notBlacklistedReferers.put(referer, counter);
                notBlacklistedRefererCounts.increment(referer);
            }
        }
    }

    private ArrayList<AbstractMap.SimpleEntry<String, long[]>> getRefererData(
            List<Map.Entry<String, Long>> mostCommonThingsList, 
            List<Map.Entry<String, Long>> sortedReferers, 
            HashMap<String, Counter<String>> referers) {
        TreeMap<String, Long> mostCommonThingsMap=new TreeMap<>();
        for(Map.Entry<String, Long> entry:mostCommonThingsList) {
            mostCommonThingsMap.put(entry.getKey(), entry.getValue());
        }
        boolean tooManyThings=false;
        Counter<String> thingsForThisReferer;
        long vals[];
        Long val;

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
        String referer;
        lookupCount=0;
        for(Map.Entry<String, Long> entry:sortedReferers) {
            referer=entry.getKey();
            thingsForThisReferer=referers.get(referer);
            if(thingsForThisReferer==null) {
                System.out.println("in "+this.getClass().getSimpleName()+": no things for referer="+referer);
                continue;
            }
            int i=0;
            long other=0;
            if(tooManyThings) {
                vals=new long[mostCommonThingsList.size()+1];
                for(String thing: thingsForThisReferer.keySet()) {
                    if(mostCommonThingsMap.get(thing)==null)
                        other+=thingsForThisReferer.get(thing);
                }
            }
            else
                vals=new long[mostCommonThingsList.size()];
            // create array of counts in mostCommonThings order
            for(Map.Entry<String, Long> thing:mostCommonThingsList) {
                val=thingsForThisReferer.get(thing.getKey());
                if(val==null)
                    val=0L;
                vals[i++]=val;
            }
            if(tooManyThings)
                vals[i]=other;
            list.add(new AbstractMap.SimpleEntry<>(referer, vals));
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
        referers.clear();
        notBlacklistedReferers.clear();
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
        String refererData = m.group(1);
        p=Pattern.compile("<referer name='([^']*)' ([^>]*)/>");
        m=p.matcher(refererData);
        Pattern thingsPattern=Pattern.compile("\\s*([^=]*)='([^/]*)/([^']*)'");
        Counter<String> refererMap, notBlacklistedRefererMap;
        long newVal;
        String thing, things;
        while(m.find()) {
            String referer=m.group(1);
            refererMap=referers.get(referer);
            if(refererMap==null)
                refererMap=new Counter<>();
            notBlacklistedRefererMap=notBlacklistedReferers.get(referer);
            if(notBlacklistedRefererMap==null)
                notBlacklistedRefererMap=new Counter<>();

            // loop through cached values and add them to the hashmaps
            things=m.group(2);
            thingsMatcher=thingsPattern.matcher(things);
            while(thingsMatcher.find()) {
                thing=thingsMatcher.group(1);
                if(!thing.equals("__total"))
                    listOfThings.increment(thing);
                newVal=Long.parseLong(thingsMatcher.group(2));
                refererMap.increment(thing, newVal);
                refererCounts.increment(referer, newVal);
                
                newVal=Long.parseLong(thingsMatcher.group(3));
                if(newVal>0) {
                    notBlacklistedRefererMap.increment(thing, newVal);
                    notBlacklistedRefererCounts.increment(referer, newVal);
                }
            }
            
            referers.put(referer, refererMap);
            if(!notBlacklistedRefererMap.isEmpty())
                notBlacklistedReferers.put(referer, notBlacklistedRefererMap);
        }
        if(debug)
            System.out.println(this.getClass().getSimpleName()+": #referers="+referers.size()+", #notBlacklistedReferers="+notBlacklistedReferers.size());
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
        map.put("refererData", getRefererData(mostCommonThingsList, refererCounts.most_common(), referers));
        map.put("notBlacklistedIpData", getRefererData(mostCommonThingsList, notBlacklistedRefererCounts.most_common(), notBlacklistedReferers));
        return map;
    }

    @Override
    public String unload() {
        int notBlacklistedCount=0;
        long val;
        Long zero=0L;
        String referer;
        StringBuilder sb=new StringBuilder("<"+this.getClass().getSimpleName()+">\n");
        Counter<String> h, h2;
        for(Map.Entry<String, Long> entry:refererCounts.most_common()) {
            referer=entry.getKey();
            h=referers.get(referer);
            h2=notBlacklistedReferers.get(referer);
            if(h2==null)
                h2=new Counter();
            else
                if(notBlacklistedCount++==100)
                    break;
            sb.append("<referer name='").append(referer).append("'");
            for(String thing:h.keySet()) {
                val=h.get(thing);
                if(val>0)
                    sb.append(" ").append(escapeEntityName(thing)).append("='").append(val).append('/').append(h2.getOrDefault(thing, zero)).append("'");
            }
            sb.append("/>\n");
        }
        sb.append("</").append(this.getClass().getSimpleName()).append(">\n");
        return sb.toString();
    }
}
