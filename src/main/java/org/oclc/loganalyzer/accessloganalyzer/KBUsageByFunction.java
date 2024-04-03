/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.loganalyzer.accessloganalyzer;

import org.oclc.loganalyzer.accessloganalyzer.AccessLogAnalyzer;
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
public class KBUsageByFunction extends AccessLogAnalyzer {
    public static Pattern getRequestPattern=Pattern.compile("\"GET\\s+/webservices/kb/([^\\s]+)[^\"]+\"\\s+(\\d{3})");

    HashMap<String, CountByFunction> longAddrs=new HashMap<>();
    HashMap<String, CountByFunction> shortAddrs=new HashMap<>();
    HashMap<String, CountByFunction> wskeys=new HashMap<>();
    int collectionsID=0, collectionsSearch=1, entriesID=2, entriesSearch=3, providersID=4, providersSearch=5, settings=6, openurlResolve=7, openurlMResolve=8, otherURL=9;

    @Override
    public void analyze(String line) {
        CountByFunction cbf;
        int i;
        String ipAddr=null, wskey=null;
        if((i=line.indexOf("wskey="))>0) {
            wskey=line.substring(i+6);
            if((i=wskey.indexOf('&'))>0)
                wskey=wskey.substring(0, i);
            if((i=wskey.indexOf(' '))>0)
                wskey=wskey.substring(0, i);
            cbf=wskeys.get(wskey);
        }
        else {
            ipAddr= line.substring(0, line.indexOf(' '));
            if(ipAddr.contains(",")) // host and proxy.  Just use host
                ipAddr=ipAddr.substring(0, ipAddr.indexOf(','));
            if(!ipAddr.contains("."))
                return;  // no IP address
            cbf = longAddrs.get(ipAddr);
        }
        
        if(cbf==null)
            cbf=new CountByFunction();
        int type=getType(line);
        if(type<0) // ignore
            return;
        cbf.increment(type);
        if(wskey!=null)
            wskeys.put(wskey, cbf);
        else {
            longAddrs.put(ipAddr, cbf);
            // drop last digit
            String shortAddr = getShortAddress(ipAddr);
            cbf=shortAddrs.get(shortAddr);
            if(cbf==null)
                cbf=new CountByFunction();
            cbf.increment(type);
            shortAddrs.put(shortAddr, cbf);
        }
    }

    private int getType(String line) {
        Matcher m = getRequestPattern.matcher(line);
        if(m.find()) {
            String request=m.group(1);
            int code=Integer.parseInt(m.group(2));
            if(code!=200) // don't count errors or redirects
                return -1;
            if(request.startsWith("rest/collections"))
                if(request.startsWith("rest/collections/search"))
                    return collectionsSearch;
                else
                    return collectionsID;
            if(request.startsWith("rest/entries"))
                if(request.startsWith("rest/entries/search"))
                    return entriesSearch;
                else
                    return entriesID;
            if(request.startsWith("rest/providers"))
                if(request.startsWith("rest/providers/search"))
                    return providersSearch;
                else
                    return providersID;
            if(request.startsWith("rest/settings"))
                return settings;
//            System.out.println("other format: '"+request+"'");
            if(request.startsWith("openurl/resolve"))
                return openurlResolve;
            if(request.startsWith("openurl/mresolve"))
                return openurlMResolve;
            System.out.println(request);
            return otherURL;
        }
        return -1;
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
        Pattern p = Pattern.compile("<KBUsageByFunction>(.*?)</KBUsageByFunction>", Pattern.DOTALL);
        Matcher m=p.matcher(content);
        if(!m.find()) { // probably a new report
            return;
        }
        String usageData = m.group(1);
//    int collectionsID=0, collectionsSearch=1, entriesID=2, entriesSearch=3, providersID=4, providersSearch=5, settings=6, openurlResolve=7, openurlMResolve=8, otherURL=9;

        p=Pattern.compile("<ip addr='([^']*)' collectionsID='([^']*)' collectionsSearch='([^']*)' entriesID='([^']*)' entriesSearch='([^']*)' providersID='([^']*)' providersSearch='([^']*)' settings='([^']*)' openurlResolve='([^']*)' openurlMResolve='([^']*)' otherURL='([^']*)'");
        m=p.matcher(usageData);
        CountByFunction cbf, longCBF, shortCBF;
        while(m.find()) {
            String ipAddr=m.group(1);
            cbf=new CountByFunction(m.group(2), m.group(3), m.group(4), m.group(5), m.group(6), m.group(7), m.group(8), m.group(9), m.group(10), m.group(11));
            longCBF=longAddrs.get(ipAddr);
            if(longCBF==null)
                longCBF=new CountByFunction();
            longCBF.increment(cbf);
            longAddrs.put(ipAddr, longCBF);
            // drop last digit
            String shortAddr = getShortAddress(ipAddr);
            shortCBF=shortAddrs.get(shortAddr);
            if(shortCBF==null)
                shortCBF=new CountByFunction();
            shortCBF.increment(longCBF);
            shortAddrs.put(shortAddr, shortCBF);
        }

        p=Pattern.compile("<wskey value='([^']*)' collectionsID='([^']*)' collectionsSearch='([^']*)' entriesID='([^']*)' entriesSearch='([^']*)' providersID='([^']*)' providersSearch='([^']*)' settings='([^']*)' openurlResolve='([^']*)' openurlMResolve='([^']*)' otherURL='([^']*)'");
        m=p.matcher(usageData);
        CountByFunction aggregatedCbf;
        while(m.find()) {
            String wskey=m.group(1);
            cbf=new CountByFunction(m.group(2), m.group(3), m.group(4), m.group(5), m.group(6), m.group(7), m.group(8), m.group(9), m.group(10), m.group(11));
            aggregatedCbf=wskeys.get(wskey);
            if(aggregatedCbf==null)
                aggregatedCbf=new CountByFunction();
            aggregatedCbf.increment(cbf);
            wskeys.put(wskey, aggregatedCbf);
        }
    }

    @Override
    public Object report() {
        HashMap<String, ArrayList<AbstractMap.SimpleEntry<String,long[]>>> map=new HashMap<>();
        ArrayList<AbstractMap.SimpleEntry<String,long[]>> list=new ArrayList<>();
        ValueComparator bvc=new ValueComparator(shortAddrs);
        TreeMap<String, CountByFunction> sortedAddrs=new TreeMap<>(Collections.reverseOrder(bvc));
        sortedAddrs.putAll(shortAddrs);
        CountByFunction cbf;
        String longAddr, name;
        int i=0;
        for(String addr:sortedAddrs.keySet()) {
            // convert shortAddr to longAddr
            longAddr=null;
            for(String s:longAddrs.keySet())
                if(s.startsWith(addr)) {
                    longAddr=s;
                    break;
                }
            if(longAddr==null)
                longAddr=addr;
            name=getByAddress(longAddr);
            cbf=sortedAddrs.get(addr);
            if(cbf!=null) // I messed up a content file and caused this to happen once
                list.add(new AbstractMap.SimpleEntry<>(name, cbf.counts));
        }
        map.put("UsageByIP", list);
        
        list=new ArrayList<>();
        bvc=new ValueComparator(wskeys);
        TreeMap<String, CountByFunction> sortedWskeys=new TreeMap<>(Collections.reverseOrder(bvc));
        sortedWskeys.putAll(wskeys);
        i=0;
        for(String wskey:sortedWskeys.keySet()) {
            cbf=sortedWskeys.get(wskey);
            list.add(new AbstractMap.SimpleEntry<>(wskey, cbf.counts));
        }
        map.put("UsageByWskey", list);
        return map;
    }

    @Override
    public String unload() {
        ValueComparator bvc=new ValueComparator(longAddrs);
        TreeMap<String, CountByFunction> sortedAddrs=new TreeMap<>(Collections.reverseOrder(bvc));
        sortedAddrs.putAll(longAddrs);
        StringBuilder sb=new StringBuilder("<KBUsageByFunction>\n");
        CountByFunction cbf;
//    int collectionsID=0, collectionsSearch=1, entriesID=2, entriesSearch=3, providersID=4,
//        providersSearch=5, settings=6, openurlResolve=7, openurlMResolve=8, otherURL=9;
        for(String addr:sortedAddrs.keySet()) {
            cbf=sortedAddrs.get(addr);
            sb.append("<ip addr='").append(addr)
              .append("' collectionsID='").append(cbf.counts[collectionsID])
              .append("' collectionsSearch='").append(cbf.counts[collectionsSearch])
              .append("' entriesID='").append(cbf.counts[entriesID])
              .append("' entriesSearch='").append(cbf.counts[entriesSearch])
              .append("' providersID='").append(cbf.counts[providersID])
              .append("' providersSearch='").append(cbf.counts[providersSearch])
              .append("' settings='").append(cbf.counts[settings])
              .append("' openurlResolve='").append(cbf.counts[openurlResolve])
              .append("' openurlMResolve='").append(cbf.counts[openurlMResolve])
              .append("' otherURL='").append(cbf.counts[otherURL])
              .append("'/>\n");
        }

        bvc=new ValueComparator(wskeys);
        TreeMap<String, CountByFunction> sortedWskeys=new TreeMap<>(Collections.reverseOrder(bvc));
        sortedWskeys.putAll(wskeys);
//    int collectionsID=0, collectionsSearch=1, entriesID=2, entriesSearch=3, providersID=4,
//        providersSearch=5, settings=6, openurlResolve=7, openurlMResolve=8, otherURL=9;
        for(String wskey:sortedWskeys.keySet()) {
            cbf=sortedWskeys.get(wskey);
            sb.append("<wskey value='").append(wskey)
              .append("' collectionsID='").append(cbf.counts[collectionsID])
              .append("' collectionsSearch='").append(cbf.counts[collectionsSearch])
              .append("' entriesID='").append(cbf.counts[entriesID])
              .append("' entriesSearch='").append(cbf.counts[entriesSearch])
              .append("' providersID='").append(cbf.counts[providersID])
              .append("' providersSearch='").append(cbf.counts[providersSearch])
              .append("' settings='").append(cbf.counts[settings])
              .append("' openurlResolve='").append(cbf.counts[openurlResolve])
              .append("' openurlMResolve='").append(cbf.counts[openurlMResolve])
              .append("' otherURL='").append(cbf.counts[otherURL])
              .append("'/>\n");
        }

        sb.append("</KBUsageByFunction>");
        return sb.toString();
    }

    private class CountByFunction {

        long counts[], total;

        public CountByFunction() {
            counts=new long[10];
            total=0;
        }

//    int collectionsID=0, collectionsSearch=1, entriesID=2, entriesSearch=3, providersID=4,
//        providersSearch=5, settings=6, openurlResolve=7, openurlMResolve=8, otherURL=9;
        private CountByFunction(String collectionsIDStr, String collectionsSearchStr, String entriesIDStr, String entriesSearchStr,
                String providersIDStr, String providersSearchStr, String settingsStr, String openurlResolveStr,
                String openurlMResolveStr, String otherURLStr) {
            counts=new long[10];
            counts[collectionsID]=Long.parseLong(collectionsIDStr);
            counts[collectionsSearch]=Long.parseLong(collectionsSearchStr);
            counts[entriesID]=Long.parseLong(entriesIDStr);
            counts[entriesSearch]=Long.parseLong(entriesSearchStr);
            counts[providersID]=Long.parseLong(providersIDStr);
            counts[providersSearch]=Long.parseLong(providersSearchStr);
            counts[settings]=Long.parseLong(settingsStr);
            counts[openurlResolve]=Long.parseLong(openurlResolveStr);
            counts[openurlMResolve]=Long.parseLong(openurlMResolveStr);
            counts[otherURL]=Long.parseLong(otherURLStr);
            total=0;
            for(int i=0; i<counts.length; i++)
                total+=counts[i];
        }

        private void increment(int type) {
            counts[type]=counts[type]+1;
            total++;
        }

//    int collectionsID=0, collectionsSearch=1, entriesID=2, entriesSearch=3, providersID=4,
//        providersSearch=5, settings=6, openurlResolve=7, openurlMResolve=8, otherURL=9;
        private void increment(CountByFunction cat) {
            total=0;
            for(int i=0; i<counts.length; i++) {
                counts[i]+=cat.counts[i];
                total+=counts[i];
            }
        }
    }

    class ValueComparator implements Comparator<String> {

        private final Map<String, CountByFunction> map;

        public ValueComparator(Map<String, CountByFunction> map) {
            this.map=map;
        }
        
        @Override
        public int compare(String a, String b) {
            if(map.get(a).total==map.get(b).total)
                return a.compareTo(b);
            return (int)(map.get(a).total-map.get(b).total);
        }
    }
    
}
