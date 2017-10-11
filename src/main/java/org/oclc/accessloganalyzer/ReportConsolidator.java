/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.accessloganalyzer;

import ORG.oclc.os.JSAP.SimplerJSAP;
import com.martiansoftware.jsap.JSAPResult;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import static org.oclc.accessloganalyzer.AccessLogAnalyzer.resetDate;

/**
 *
 * @author levan
 */
public class ReportConsolidator {
//    ArrayList<LongPair> times=new ArrayList<>();
//    ArrayList<TimedQuery> longQueries=new ArrayList<>();
    HashMap<Long, HashMap<String, Integer>> ipMap=new HashMap<>();
    SimpleDateFormat sdf=new SimpleDateFormat("dd/MMM/yyyy:HH:mm:ss", Locale.US);
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        new ReportConsolidator().run(args);
    }
    private String contentNameTemplate;
    private String reportNameTemplate;
    private boolean daily;
    private boolean weekly;
    private boolean monthly;
    private boolean annual;
    private String[] analyzerNames;

    public void run(String[] args) throws Exception {
        SimplerJSAP jsap = new SimplerJSAP(
          "--reportNameTemplate<> --contentNameTemplate<> [--freemarkerTemplateDirectory<File>] [--freemarkerTemplateName<>] [--analyzers<>] [--date<>] [--daily] [--weekly] [--week] [--monthly] [--month] [--annual] [--year] [--debug]");
        JSAPResult config = jsap.parse(args);
        Date today=new Date();
        String date = config.getString("date", null);
        if(date!=null) {
            if(date.equals("yesterday")) {
                today=new Date(System.currentTimeMillis()-86400000);
                Calendar cal=Calendar.getInstance();
                cal.setTime(today);
                args=resetDate(cal, args);
            }
            else
                today=new Date(new SimpleDateFormat("yyyyMMdd").parse(date).getTime());
        }

        String analyzerList=config.getString("analyzers", "");
        if(!analyzerList.isEmpty())
            analyzerList=analyzerList+",";
        analyzerList=analyzerList+"UsageOverTime";
        analyzerNames = analyzerList.split(",");
        contentNameTemplate=config.getString("contentNameTemplate");
        String freemarkerTemplateName = config.getString("freemarkerTemplateName", "AccessLogAnalyzerTemplate.html");
        String freemarkerTemplateDirectory=".";
        int i=freemarkerTemplateName.lastIndexOf('/');
        if(i>=0) {
            freemarkerTemplateDirectory=freemarkerTemplateName.substring(0, i);
            freemarkerTemplateName=freemarkerTemplateName.substring(i+1);
        }

        int calendarUnit=-1, numDays=0;
        Calendar cal=Calendar.getInstance();
        cal.setTime(today);
        cal.set(Calendar.HOUR_OF_DAY, 0);
        cal.set(Calendar.MINUTE, 0);
        cal.set(Calendar.SECOND, 0);
        if(config.getBoolean("daily", false)) {
            daily=true;
            calendarUnit=Calendar.DAY_OF_YEAR;
            numDays=1;
        }
        if(config.getBoolean("weekly", false)||config.getBoolean("week", false)) {
            weekly=true;
            cal.set(Calendar.DAY_OF_WEEK, cal.getFirstDayOfWeek());
            calendarUnit=Calendar.WEEK_OF_YEAR;
            numDays=7;
        }
        if(config.getBoolean("monthly", false)||config.getBoolean("month", false)) {
            monthly=true;
            cal.set(Calendar.DAY_OF_MONTH, 1);
            calendarUnit=Calendar.MONTH;
            numDays=cal.getActualMaximum(Calendar.DAY_OF_MONTH);
        }
        if(config.getBoolean("annual", false)||config.getBoolean("year", false)) {
            annual=true;
            cal.set(Calendar.DAY_OF_YEAR, 1);
            calendarUnit=Calendar.YEAR;
            numDays=cal.getActualMaximum(Calendar.DAY_OF_YEAR);
        }
        if(calendarUnit==-1)
            throw new IllegalArgumentException("Missing a calendar flag: --weekly, --monthly or --annual");

        reportNameTemplate=config.getString("reportNameTemplate");
        Configuration cfg = new Configuration(Configuration.VERSION_2_3_25);
        cfg.setDirectoryForTemplateLoading(new File(freemarkerTemplateDirectory));
        cfg.setDefaultEncoding("UTF-8");
        cfg.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
        cfg.setLogTemplateExceptions(false);
        doReport(cal, today, daily, weekly, monthly, annual, numDays, cfg.getTemplate(freemarkerTemplateName), args);
    }

    void doReport(Calendar cal, Date end, boolean daily, boolean weekly, boolean monthly, boolean annual, int numDays, Template t, String[] args) throws IOException, TemplateException {
        String reportName=new SimpleDateFormat(reportNameTemplate).format(cal.getTime());
        HashMap<String, Object> freeMarkerMap=new HashMap<>();
        Date start=cal.getTime();
        freeMarkerMap.put("today", start);

        Analyzer[] analyzers = new Analyzer[analyzerNames.length];
        for(int i=0; i<analyzerNames.length; i++) {
            Analyzer analyzer = getAnalyzer(analyzerNames[i]);
            analyzer.doInit(args);
            analyzers[i]=analyzer;
        }

        int dayNumber=0;
        boolean didSomething=false;
        for(Date d=cal.getTime(); dayNumber<numDays; cal.add(Calendar.DAY_OF_YEAR, 1),d=cal.getTime(),dayNumber++) {
            System.out.println("content for "+d);
            String contentFileName=new SimpleDateFormat(contentNameTemplate).format(d);

            File f=new File(contentFileName);
            if(!f.exists()) {
                System.out.println("Nothing to report for "+d);
                continue;
            }

            // read the content from the report to be added to the consolidation
            String content = loadContent(new File(contentFileName));
            // and merge it into the old data
            for(Analyzer analyzer:analyzers) {
                analyzer.merge(content, dayNumber);
            }
            didSomething=true;
        }
        if(!didSomething)
            return;

        if(daily)
            freeMarkerMap.put("daily", true);
        if(weekly)
            freeMarkerMap.put("weekly", true);
        if(monthly)
            freeMarkerMap.put("monthly", true);
        if(annual)
            freeMarkerMap.put("annual", true);
        for(Analyzer analyzer:analyzers) {
            freeMarkerMap.put(analyzer.getClass().getSimpleName(), analyzer.report());
        }

        File f=new File(reportName);
        System.out.println("producing "+reportName);
        boolean firstTime=false;
        if(!f.exists()) // first time for this report
            firstTime=true;
        try (FileWriter fw = new FileWriter(f)) {
            t.process(freeMarkerMap, fw);
        }
        freeMarkerMap.clear();
        
        if(firstTime) { // if this was the first time for this period,
            // then we probably need to finish off the previous period
            cal=Calendar.getInstance();
            cal.setTime(start);
            cal.set(Calendar.HOUR_OF_DAY, 0);
            cal.set(Calendar.MINUTE, 0);
            cal.set(Calendar.SECOND, 0);
            if(daily) {
                cal.set(Calendar.DAY_OF_YEAR, cal.get(Calendar.DAY_OF_YEAR)-1);
            }
            if(weekly) {
                cal.set(Calendar.DAY_OF_YEAR, cal.get(Calendar.DAY_OF_YEAR)-7);
            }
            if(monthly) {
                cal.set(Calendar.MONTH, cal.get(Calendar.MONTH)-1);
                numDays=cal.getActualMaximum(Calendar.DAY_OF_MONTH);
            }
            if(annual) {
                cal.set(Calendar.YEAR, cal.get(Calendar.YEAR)-1);
                numDays=cal.getActualMaximum(Calendar.DAY_OF_YEAR);
            }
            args=AccessLogAnalyzer.resetDate(cal, args);
            doReport(cal, start, daily, weekly, monthly, annual, numDays, t, args);
        }
    }

    public Analyzer getAnalyzer(String analyzerName) {
        Class<? extends Analyzer> c;
        Analyzer analyzer;
        String        name=getAnalyzerClassName(analyzerName);

        try {
            c=Class.forName(name).asSubclass(Analyzer.class);
        }
        catch(ClassNotFoundException e) {
            throw new IllegalArgumentException(name);
        }

        try {
            analyzer=c.newInstance();
        }
        catch(InstantiationException | IllegalAccessException e) {
            throw new IllegalArgumentException(name);
        }

        return analyzer;
    }

    private static String getAnalyzerClassName(String name) {
        if (name.indexOf('.')<0)
            return "org.oclc.accessloganalyzer."+name;

        return name;
    }

    private int getSkipCount(String content, int defaultValue) {
        Pattern p = Pattern.compile("<skipLineCount>(.*?)</skipLineCount>");
        Matcher m=p.matcher(content);
        if(m.find())
            return Integer.parseInt(m.group(1));
        return defaultValue;
    }

    private String loadContent(File f) throws IOException {
        boolean justReadContent;
        BufferedReader br=new BufferedReader(new FileReader(f));
        String line;
        StringBuilder sb=new StringBuilder();
        while((line=br.readLine())!=null) {
            justReadContent=false;
            if(line.contains("<script type='xmlContent'")) {
                justReadContent=true;
                // grab this and remaining line to send of script
                sb.append(line).append('\n');
                while((line=br.readLine())!=null) {
                    sb.append(line).append('\n');
                    if(line.contains("</script>"))
                        break;
                }
            }
            if(justReadContent)
                if(line.contains("</script>"))
                    break;
                else
                    throw new IOException("didn't find end of script!");
        }
        return sb.toString();
    }
}
