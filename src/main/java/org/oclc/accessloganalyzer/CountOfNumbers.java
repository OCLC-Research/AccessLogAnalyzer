/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.accessloganalyzer;

import ORG.oclc.os.JSAP.SimplerJSAP;
import com.martiansoftware.jsap.JSAPException;
import com.martiansoftware.jsap.JSAPResult;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author levan
 */
public abstract class CountOfNumbers extends Analyzer {

    Counter<Long> numbers=new Counter<>();
    Counter<Long> notBlacklistedNumbers=new Counter<>();
    boolean debug;

    public abstract List<Long> getNumbers(String line);

    @Override
    public void analyze(String line) {
        for(Long number:getNumbers(line)) {
            numbers.increment(number);
            if(!isBlacklisted())
                notBlacklistedNumbers.increment(number);
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
        p=Pattern.compile("<number value='([^']*)'>(\\d+)/(\\d+)</number>");
        m=p.matcher(usageData);
        long val;
        while(m.find()) {
            Long number=Long.parseLong(m.group(1));
            val=Long.parseLong(m.group(2));
            numbers.increment(number, val);
            val=Long.parseLong(m.group(3));
            if(val>0)
                notBlacklistedNumbers.increment(number, val);
        }
    }

    @Override
    public Object report() {
        HashMap<String, Object> map=new HashMap<>();
        map.put("numbers", numbers.most_common());
        map.put("notBlacklistedNumbers", notBlacklistedNumbers.most_common());
        return map;
    }

    @Override
    public String unload() {
        int notBlacklistedCount=0;
        List<Map.Entry<Long, Long>> most_common = numbers.most_common();
        Long notBlacklistedValue;
        StringBuilder sb=new StringBuilder("<"+this.getClass().getSimpleName()+">\n");
        for(Map.Entry<Long, Long> entry:most_common) {
            notBlacklistedValue=notBlacklistedNumbers.get(entry.getKey());
            if(notBlacklistedValue==null)
                notBlacklistedValue=0L;
            else
                if(notBlacklistedCount++==100)
                    break;
            sb.append("<number value='").append(entry.getKey()).append("'>").append(entry.getValue()).append('/').append(notBlacklistedValue).append("</number>\n");
        }
        sb.append("</").append(this.getClass().getSimpleName()).append(">");
        return sb.toString();
    }
}
