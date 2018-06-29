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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import org.anarres.lzo.LzopInputStream;

/**
 *
 * @author levan
 */
public class AccessLogAnalyzer {
    HashMap<Long, HashMap<String, Integer>> ipMap=new HashMap<>();
    /**
     * @param args the command line arguments
     * @throws java.lang.Exception
     */
    public static void main(String[] args) throws Exception {
        new AccessLogAnalyzer().run(args);
    }
    private String logNameTemplate;
    private String reportNameTemplate;
    private String hostname;
    private String contentNameTemplate;
    private String remoteLogNameTemplate;
    private String todaysRemoteLogNameTemplate;
    private int maxDaysToProcess;
    private boolean debug;

    public void run(String[] args) throws Exception {
        Date today=new Date();
        SimplerJSAP jsap = new SimplerJSAP(
          "[--logNameTemplate<>] [--remoteLogNameTemplate<>] [--todaysRemoteLogNameTemplate<>] [--freemarkerTemplateName<>] [--reportNameTemplate<>] --contentNameTemplate<> [--date<>] [--hostname<>] [--analyzers<>] [--maxDaysToProcess<int>] [--maxRecordsPerDay<int>] [--debug]");
        JSAPResult config = jsap.parse(args);
        debug=config.getBoolean("debug", false);
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
        maxDaysToProcess=config.getInt("maxDaysToProcess", Integer.MAX_VALUE);
        int maxRecordsPerDay=config.getInt("maxRecordsPerDay", Integer.MAX_VALUE);

        String analyzerList=config.getString("analyzers", "");
        if(!analyzerList.isEmpty())
            analyzerList=analyzerList+",";
        analyzerList=analyzerList+"UsageOverTime";
        String[] analyzerNames = analyzerList.split(",");
        
        logNameTemplate=config.getString("logNameTemplate", null);
        remoteLogNameTemplate=config.getString("remoteLogNameTemplate", null);
        todaysRemoteLogNameTemplate=config.getString("todaysRemoteLogNameTemplate", null);
        String freemarkerTemplateName = config.getString("freemarkerTemplateName", "AccessLogAnalyzerTemplate.html");
        String freemarkerTemplateDirectory=".";
        int i=freemarkerTemplateName.lastIndexOf('/');
        if(i>=0) {
            freemarkerTemplateDirectory=freemarkerTemplateName.substring(0, i);
            freemarkerTemplateName=freemarkerTemplateName.substring(i+1);
        }
        reportNameTemplate=config.getString("reportNameTemplate", null);
        contentNameTemplate=config.getString("contentNameTemplate");
        hostname=config.getString("hostname", null);

        Configuration cfg = new Configuration(Configuration.VERSION_2_3_25);
        cfg.setDirectoryForTemplateLoading(new File(freemarkerTemplateDirectory));
        cfg.setDefaultEncoding("UTF-8");
        cfg.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
        cfg.setLogTemplateExceptions(false);
        Template t=cfg.getTemplate(freemarkerTemplateName);

        doReport(today, t, analyzerNames, args, 0, maxRecordsPerDay);
    }
    
    private void doReport(Date date, Template template, String[] analyzerNames, String[] args, int recursionDepth, int maxCount) throws IOException, TemplateException {
        System.out.println("report for "+date);
        if(recursionDepth>=maxDaysToProcess)
            return;
        String content="";
        String todaysContent=new SimpleDateFormat(contentNameTemplate).format(date);
        String todaysLog=null;

        if(logNameTemplate!=null) {
            todaysLog=new SimpleDateFormat(logNameTemplate).format(date);
            File f=new File(todaysLog);
            if(!f.exists()) {
                f=new File(todaysLog+".gz");
                if(!f.exists()) {
                    f=new File(todaysLog+".lzo");
                    if(!f.exists()) {
                        if(remoteLogNameTemplate!=null) {
                            SimpleDateFormat sdf=new SimpleDateFormat("yyyyMMdd");
                            if(todaysRemoteLogNameTemplate!=null && sdf.format(new Date()).equals(sdf.format(date))) {
                                String todaysRemoteLogName=new SimpleDateFormat(todaysRemoteLogNameTemplate).format(date);
                                if(!getLog(todaysRemoteLogName, todaysLog, date)) {
                                    System.out.println("Nothing to report");
                                    return;
                                }
                            }
                            else {
                                String remoteLogName=new SimpleDateFormat(remoteLogNameTemplate).format(date);
                                if(!getLog(remoteLogName, todaysLog, date)) { // try gzipped
                                    if(!getLog(remoteLogName+".gz", todaysLog, date)) {
                                        if(!getLog(remoteLogName+".lzo", todaysLog, date)) {
                                            System.out.println("Nothing to report");
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                        else {
                            System.out.println("Nothing to report");
                            return;
                        }
                    }
                }
            }
        }
        Analyzer[] analyzers = new Analyzer[analyzerNames.length];
        for(int i=0; i<analyzerNames.length; i++) {
            Analyzer analyzer = getAnalyzer(analyzerNames[i]);
            analyzer.doInit(args);
            analyzers[i]=analyzer;
        }
        File f=new File(todaysContent);
        StringBuilder skipCountBuilder=new StringBuilder();
        if(f.exists()) {
            // load old content from report
            boolean justReadContent;
            BufferedReader br=new BufferedReader(new FileReader(f));
            String line;
            StringBuilder contentBuilder=new StringBuilder();
            while((line=br.readLine())!=null) {
                justReadContent=false;
                if(line.contains("<script type='xmlContent'")) {
                    justReadContent=true;
                    // grab this and remaining line to send of script
                    contentBuilder.append(line).append('\n');
                    while((line=br.readLine())!=null) {
                        contentBuilder.append(line).append('\n');
                        if(line.contains("</script>"))
                            break;
                    }
                }
                if(line.contains("<script type='skipCounts'")) {
                    // grab this and remaining line to send of script
                    skipCountBuilder.append(line).append('\n');
                    while((line=br.readLine())!=null) {
                        skipCountBuilder.append(line).append('\n');
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
            content=contentBuilder.toString();
        }
        else if(todaysLog==null) { // no old content and no log to analyze??
            System.out.println("Nothing to process for "+date);
            return;
        }
        int startingSkipCount, skipCount=getSkipCount(skipCountBuilder, todaysLog);
        startingSkipCount=skipCount;
        
        // load the analyzers with their old content
        for(Analyzer analyzer:analyzers) {
            analyzer.load(content, date);
        }

        if(todaysLog!=null) {
            System.out.println("skipping "+skipCount+" lines from file "+todaysLog);
            BufferedReader br=openReader(todaysLog);
            String line;
            for(int i=0; i<skipCount; i++)
                br.readLine();
            if(debug)System.out.println("reading remainder of log");
            int readCount=0;
            while((line=br.readLine())!=null) { // read the log and call the analyzer
                skipCount++;
                readCount++;
                if(readCount>maxCount)
                    break;
                Analyzer.setBlacklisted(line);
                for(Analyzer analyzer:analyzers) {
                    analyzer.analyze(line);
                }
            }
            if(readCount>0) {
                if(debug)System.out.println("serializing content");
                try (FileWriter fw = new FileWriter(todaysContent)) {
                    fw.write("<content>\n");
                    fw.write("<script type='skipCounts'>\n");
                    fw.write(skipCountBuilder.toString());
                    fw.write(String.format("<skipLineCount hostname='%s'>%d</skipLineCount>\n", hostname==null?todaysLog:hostname, skipCount));
                    fw.write("</script>\n");

                    // get the analyzers to unload their new content
                    StringBuilder sb=new StringBuilder();
                    for(Analyzer analyzer:analyzers) {
                        sb.append(analyzer.unload()).append('\n');
                    }
                    fw.write("<script type='xmlContent'>\n");
                    fw.write(sb.toString());
                    fw.write("</script>\n");
                    fw.write("</content>\n");
                }
            }
        }

        if(debug)System.out.println("getting content from "+analyzers.length+" analyzers");
        HashMap<String, Object> freeMarkerMap=new HashMap<>();
        freeMarkerMap.put("daily", true);
        freeMarkerMap.put("today", date);
        for(Analyzer analyzer:analyzers) {
            freeMarkerMap.put(analyzer.getClass().getSimpleName(), analyzer.report());
            analyzer.close();
        }

        if(debug)System.out.println("reportNameTemplate="+reportNameTemplate);
        if(reportNameTemplate!=null) {
            String todaysReport=new SimpleDateFormat(reportNameTemplate).format(date);
            if(debug)System.out.println("todaysReport="+todaysReport);
            boolean doYesterdayToo=false;
            f=new File(todaysReport);
            if(!f.exists() || startingSkipCount==0) // haven't started today, so let's be sure to finish yesterday
                doYesterdayToo=true;
            try (FileWriter fw = new FileWriter(f)) {
                template.process(freeMarkerMap, fw);
            }
            if(debug)System.out.println("doYesterdayToo="+doYesterdayToo);
            if(doYesterdayToo) {
                freeMarkerMap.clear();
                Calendar cal=Calendar.getInstance();
                cal.setTime(date);
                cal.add(Calendar.DATE, -1);
                args=resetDate(cal, args);
                try {
                    doReport(cal.getTime(), template, analyzerNames, args, recursionDepth+1, maxCount);
                } catch (FileNotFoundException ex) {
                    System.out.println("Nothing to finish: "+ex.getMessage());
                }
            }
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

    private boolean getLog(String remoteLogName, String logName, Date date) throws MalformedURLException, FileNotFoundException, IOException {
        System.out.println("trying for "+remoteLogName);
        URL website = new URL(remoteLogName);
        InputStream stream;
        try {
            stream = website.openStream();
        } catch (IOException ex) {
            System.out.println("couldn't find "+remoteLogName);
            return false;
        }
        ReadableByteChannel rbc = Channels.newChannel(stream);
        if(remoteLogName.endsWith(".gz") && !logName.endsWith(".gz"))
            logName=logName+".gz";
        System.out.println("writing to "+logName);
        
        FileOutputStream fos = new FileOutputStream(logName);
        fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
        
        return true;
    }

    private int getSkipCount(StringBuilder skipCountBuilder, String todaysLog) {
        int returnVal=0;
        Pattern p = Pattern.compile("<skipLineCount hostname='([^']+)'>(.*?)</skipLineCount>");
        Matcher m=p.matcher(skipCountBuilder.toString());
        StringBuilder sb=new StringBuilder();
        while(m.find()) {
            if(hostname!=null && hostname.equals(m.group(1)))
                returnVal=Integer.parseInt(m.group(2));
            else if(todaysLog.equals(m.group(1)))
                returnVal=Integer.parseInt(m.group(2));
            else
                sb.append(String.format("<skipLineCount hostname='%s'>%s</skipLineCount>\n", m.group(1), m.group(2)));
        }
        skipCountBuilder.replace(0, skipCountBuilder.length(), sb.toString()); // remove the current host from the list
        return returnVal;
    }
    
    static public BufferedReader openReader(String filename) throws FileNotFoundException, IOException {
//        System.out.println("looking for file: "+filename);
        File f=new File(filename);
        if(f.exists())
            return new BufferedReader(new FileReader(f));
//        System.out.println("looking for file: "+filename+".gz");
        f=new File(filename+".gz");
        if(f.exists())
            return new BufferedReader(new InputStreamReader(new GZIPInputStream(new FileInputStream(f))));
//        System.out.println("looking for file: "+filename+".lzo");
        f=new File(filename+".lzo");
        if(f.exists())
            return new BufferedReader(new InputStreamReader(new LzopInputStream(new FileInputStream(f))));
//        System.out.println("file not found: "+filename);
        throw new FileNotFoundException(filename);
    }

    static public String[] resetDate(Calendar cal, String[] args) {
        ArrayList<String> newArgs=new ArrayList<>();
        for(int i=0; i<args.length; i++)
            if(args[i].startsWith("--date")) {
                i++;
            } else {
                newArgs.add(args[i]);
            }
        newArgs.add("--date");
        newArgs.add(new SimpleDateFormat("yyyyMMdd").format(cal.getTime()));
        return newArgs.toArray(new String[0]);
    }
}
