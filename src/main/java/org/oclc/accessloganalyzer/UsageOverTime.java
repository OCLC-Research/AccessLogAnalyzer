/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.accessloganalyzer;

import ORG.oclc.os.JSAP.SimplerJSAP;
import com.martiansoftware.jsap.JSAPException;
import com.martiansoftware.jsap.JSAPResult;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author levan
 */
public class UsageOverTime extends Analyzer {

    protected int intervalSize;
    protected long total;
    protected long[] notBlacklistedUsage, usage;
    private Pattern timePattern;
    private Date date;
    private boolean weekly;
    private boolean monthly;
    private boolean annual;
    private String start;
    private String end;
    private int daysInMonth;
    private int daysInYear;
    private long startMillis;
    private long endMillis;
    private boolean daily;
    private boolean debug;

    @Override
    public void analyze(String line) {
        Matcher m = timePattern.matcher(line);
        if(m.find()) {
            int hour=Integer.parseInt(m.group(1));
            int minute=Integer.parseInt(m.group(2));
            int time=hour*60+minute;
            usage[time/intervalSize]=usage[time/intervalSize]+1;
            if(!isBlacklisted())
                notBlacklistedUsage[time/intervalSize]=notBlacklistedUsage[time/intervalSize]+1;
            total++;
        }
    }

    @Override
    public void init(String[] args) {
        SimplerJSAP jsap;
        try {
            jsap = new SimplerJSAP(
                    "[--usageInterval<int>] [--daily] [--weekly] [--week] [--monthly] [--month] [--annual] [--year] [--date<>] [--debug]");
        } catch (JSAPException ex) {
            throw new IllegalArgumentException(ex);
        }
        JSAPResult config = jsap.parse(args);
        debug=config.getBoolean("debug", false);
        intervalSize=config.getInt("usageInterval", 6);
        timePattern=Pattern.compile("\\[[^:]+:(\\d{2}):(\\d{2})[\\w:/]+\\s[+\\-]\\d{4}\\]");
        daily=config.getBoolean("daily", false);
        weekly=config.getBoolean("weekly", false)||config.getBoolean("week", false);
        monthly=config.getBoolean("monthly", false)||config.getBoolean("month", false);
        annual=config.getBoolean("annual", false)||config.getBoolean("year", false);
        date=new Date();
        
        String dateStr = config.getString("date", null);
        if(dateStr!=null) {
            try {
                date=new Date(new SimpleDateFormat("yyyyMMdd").parse(dateStr).getTime());
            } catch (ParseException ex) {
                Logger.getLogger(UsageOverTime.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        int calendarUnit=Calendar.DAY_OF_YEAR;
        Calendar cal=Calendar.getInstance();
        cal.setTime(date);
        cal.set(Calendar.HOUR_OF_DAY, 0);
        cal.set(Calendar.MINUTE, 0);
        cal.set(Calendar.SECOND, 0);
        if(weekly) {
            cal.set(Calendar.DAY_OF_WEEK, cal.getFirstDayOfWeek());
            calendarUnit=Calendar.WEEK_OF_YEAR;
        }
        if(monthly) {
            cal.set(Calendar.DAY_OF_MONTH, 1);
            calendarUnit=Calendar.MONTH;
            daysInMonth=cal.getMaximum(Calendar.DAY_OF_MONTH);
        }
        if(annual) {
            cal.set(Calendar.DAY_OF_YEAR, 1);
            calendarUnit=Calendar.YEAR;
            daysInYear=cal.getMaximum(Calendar.DAY_OF_YEAR);
        }
        startMillis=cal.getTime().getTime();
        start=new SimpleDateFormat("yyyyMMdd").format(cal.getTime());
        cal.add(calendarUnit, 1); // end of week, month, year
        endMillis=cal.getTime().getTime();
        end=new SimpleDateFormat("yyyyMMdd").format(cal.getTime());
        if(debug)
            System.out.println("in UsageOverTime.init: date="+date+", start="+start+", end="+end);
    }

    @Override
    public void load(String content, Date date) {
        this.date=date;
        Pattern p = Pattern.compile("<usageOverTime>(.*?)</usageOverTime>", Pattern.DOTALL);
        Matcher m=p.matcher(content);
        if(!m.find()) { // probably a new report
            int numIntervals = (24*60)/intervalSize;
            usage=new long[numIntervals];
            notBlacklistedUsage=new long[numIntervals];
            return;
        }

        String usageData = m.group(1);
        p=Pattern.compile("<usageInterval>(\\d*)</usageInterval>");
        m=p.matcher(usageData);
        if(m.find()) {
            intervalSize=Integer.parseInt(m.group(1));
        }
        int numIntervals = (24*60)/intervalSize;
        usage=new long[numIntervals];
        notBlacklistedUsage=new long[numIntervals];
        p=Pattern.compile("<interval minute='(\\d*)'>(\\d*)/(\\d*)</interval>");
        m=p.matcher(usageData);
        long count;
        int minute;
        while(m.find()) {
            minute=Integer.parseInt(m.group(1));
            count=Long.parseLong(m.group(2));
            usage[minute/intervalSize]=count;
            total+=count;
            count=Long.parseLong(m.group(3));
            notBlacklistedUsage[minute/intervalSize]=count;
        }
    }

    @Override
    public void merge(String content, int dayNumber) {
        Pattern p = Pattern.compile("<usageOverTime>(.*?)</usageOverTime>", Pattern.DOTALL);
        Matcher m=p.matcher(content);
        if(!m.find()) { // probably a new report
            return;
        }

        String usageData = m.group(1);
        int dailyIncrement=24*60, numIntervals=0;
        if(daily) {
            intervalSize=6;
            numIntervals= (24*60)/intervalSize;
        }
        if(weekly) {
            intervalSize=30;
            numIntervals= (7*24*60)/intervalSize;
        }
        if(monthly) {
            intervalSize=180;
            numIntervals= (daysInMonth*24*60)/intervalSize;
        }
        if(annual) {
            intervalSize=24*60;
            numIntervals= daysInYear;
        }
        if(usage==null) {
            usage=new long[numIntervals];
            notBlacklistedUsage=new long[numIntervals];
        }
        p=Pattern.compile("<interval minute='(\\d*)'>(\\d*)(?:/(\\d*))?</interval>");
        m=p.matcher(usageData);
        long count;
        int minute;
        while(m.find()) {
            minute=Integer.parseInt(m.group(1))+(dailyIncrement*dayNumber);
            total-=usage[minute/intervalSize]; // we'll add it back in on the next line
            count=Long.parseLong(m.group(2))+usage[minute/intervalSize];
            usage[minute/intervalSize]=count;
            total+=count;
            if(m.group(3)!=null) {
                count=Long.parseLong(m.group(3))+notBlacklistedUsage[minute/intervalSize];
                notBlacklistedUsage[minute/intervalSize]=count;
            }
        }
    }

    @Override
    public Object report() {
        HashMap<String, Object> map=new HashMap<>();
        if(debug)System.out.println("in UsageOverTime.report()");
        map.put("usage", usage);
        map.put("notBlacklistedUsage", notBlacklistedUsage);
        map.put("startMillis", startMillis);
        map.put("endMillis", endMillis);
        map.put("intervalSize", intervalSize);
        map.put("total", total);
        if(debug)System.out.println("in UsageOverTime.report(): done");
        return map;
    }

    @Override
    public String unload() {
        StringBuilder sb=new StringBuilder("<usageOverTime>\n");
        sb.append("<usageInterval>").append(intervalSize).append("</usageInterval>\n");
        for(int i=0; i<usage.length; i++) {
            if(usage[i]>0)
                sb.append("<interval minute='").append(i*intervalSize).append("'>").append(usage[i]).append('/').append(notBlacklistedUsage[i]).append("</interval>\n");
        }
        sb.append("</usageOverTime>");
        return sb.toString();
    }
}
