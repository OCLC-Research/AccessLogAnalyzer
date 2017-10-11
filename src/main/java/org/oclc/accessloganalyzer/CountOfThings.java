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
public abstract class CountOfThings extends Analyzer {

    HashMap<String, Long> things=new HashMap<>();
    boolean debug;

    public abstract String getThing(String line);

    @Override
    public void analyze(String line) {
        String thing=getThing(line);
        if(thing!=null) {
            Long val=things.get(thing);
            if(val==null)
                val=0L;
            things.put(thing, val+1);
        }
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
        p=Pattern.compile("<thing name='([^']*)'>(\\d+)</thing>");
        m=p.matcher(usageData);
        long val;
        Long oldVal;
        while(m.find()) {
            String thing=m.group(1);
            val=Long.parseLong(m.group(2));
            oldVal=things.get(thing);
            if(oldVal==null)
                oldVal=0L;
            things.put(thing, oldVal+val);
        }
    }

    @Override
    public Object report() {
        ArrayList<AbstractMap.SimpleEntry<String,Long>> list=new ArrayList<>();
        ValueComparator bvc=new ValueComparator(things);
        TreeMap<String, Long> sortedThings=new TreeMap<>(Collections.reverseOrder(bvc));
        sortedThings.putAll(things);
        for(String thing:sortedThings.keySet())
            list.add(new AbstractMap.SimpleEntry<>(thing, sortedThings.get(thing)));
        
        return list;
    }

    @Override
    public String unload() {
        ValueComparator bvc=new ValueComparator(things);
        TreeMap<String, Long> sortedThings=new TreeMap<>(Collections.reverseOrder(bvc));
        sortedThings.putAll(things);
        StringBuilder sb=new StringBuilder("<"+this.getClass().getSimpleName()+">\n");
        for(String thing:sortedThings.keySet()) {
            sb.append("<thing name='").append(thing).append("'>").append(sortedThings.get(thing)).append("</thing>\n");
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
