/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.loganalyzer.accessloganalyzer;

import ORG.oclc.os.JSAP.SimplerJSAP;
import com.martiansoftware.jsap.JSAPException;
import com.martiansoftware.jsap.JSAPResult;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.oclc.loganalyzer.Counter;

/**
 *
 * @author levan
 */
public abstract class CountOfAccessLogThings extends AccessLogAnalyzer {

    Counter<String> things=new Counter<>();
    Counter<String> notBlacklistedThings=new Counter<>();
    boolean debug;

    public abstract List<String> getThings(String line);

    @Override
    public void analyze(String line) {
        for(String thing:getThings(line)) {
            thing=cleanThing(thing);
            things.increment(thing);
            if(!isBlacklisted())
                notBlacklistedThings.increment(thing);
        }
    }

    static public String cleanThing(String thing) {
        // escape quotes and backslashes.
        // throw away control characters
        return thing.replaceAll(" ", "+");
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
            System.out.println("debug enabled for CountOfAccessLogThings");
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
        p=Pattern.compile("<thing name='([^']*)'>(\\d+)/(\\d+)</thing>");
        m=p.matcher(usageData);
        long val;
        while(m.find()) {
            String thing=m.group(1);
            val=Long.parseLong(m.group(2));
            things.increment(thing, val);
            val=Long.parseLong(m.group(3));
            if(val>0)
                notBlacklistedThings.increment(thing, val);
        }
    }

    @Override
    public Object report() {
        HashMap<String, Object> map=new HashMap<>();
        map.put("things", things.most_common());
        map.put("notBlacklistedThings", notBlacklistedThings.most_common());
        return map;
    }

    @Override
    public String unload() {
        int notBlacklistedCount=0;
        List<Map.Entry<String, Long>> most_common = things.most_common();
        Long notBlacklistedValue;
        StringBuilder sb=new StringBuilder("<"+this.getClass().getSimpleName()+">\n");
        for(Map.Entry<String, Long> entry:most_common) {
            notBlacklistedValue=notBlacklistedThings.get(entry.getKey());
            if(notBlacklistedValue==null)
                notBlacklistedValue=0L;
            else
                if(notBlacklistedCount++==100)
                    break;
            sb.append("<thing name='").append(entry.getKey()).append("'>").append(entry.getValue()).append('/').append(notBlacklistedValue).append("</thing>\n");
        }
        sb.append("</").append(this.getClass().getSimpleName()).append(">");
        return sb.toString();
    }
}
