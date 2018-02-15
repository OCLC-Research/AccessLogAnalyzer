/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.accessloganalyzer;

import ORG.oclc.os.JSAP.SimplerJSAP;
import com.martiansoftware.jsap.JSAPException;
import com.martiansoftware.jsap.JSAPResult;
import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Reader;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import sun.net.spi.nameservice.NameService;

/**
 *
 * @author levan
 */
public abstract class Analyzer implements Closeable {

    static final HashMap<String, String> EQUIVALENT_ADDRESSES=new HashMap<>();
    static final HashMap<String, String> IDENTICAL_ADDRESSES=new HashMap<>();
    static HashSet<String> spiders=new HashSet<>();
    static HashSet<String> blacklistedIPs=new HashSet<>();
    static public Properties hostNames;
    static public File propertiesFile;
    static public boolean closed=false;
    static public Pattern logEntryPattern = Pattern.compile("^(?<RemoteHost>[\\d.]+) (?<Identity>\\S+) (?<UserName>\\S+) \\[(?<Time>[\\w:/]+\\s[+\\-]\\d{4})\\] \"(?<Method>\\S+) (?<Request>.+?) HTTP/\\d\\.\\d\" (?<StatusCode>\\d{3}) (?<Size>[\\d-]+) \"(?<Referer>[^\"]+)\" \"(?<UserAgent>[^\"]+)\"");
    int lookupCount=0, maxLookups=20;
    static boolean blacklisted;
    static private String cacheRequest, cacheResponse;
    static final ArrayList<String> NOTHING=new ArrayList<>();
    private static final int[] LIST256;

    public abstract void analyze(String line);
    public abstract void init(String[] args);
    public abstract void load(String content, Date date);
    public abstract void merge(String content, int dayNumber);
    public abstract Object report();
    public abstract String unload();

    static {
        LIST256=new int[256];
        for(int i=0; i<256; i++)
            LIST256[i]=i;
    }

    static private void addAddresses(String line, HashMap<String, String> map) {
        String[] parts=line.split("=");
        String address = parts[0].substring(0, parts[0].indexOf('-'));
        parts=parts[1].split(","); // array of patterns
        for(String pattern:parts) {
            String[] numbers=pattern.split("\\.");
            for(int number1:makeNumbers(numbers[0]))
                for(int number2:makeNumbers(numbers[1]))
                    for(int number3:makeNumbers(numbers[2])) {
                        map.put(number1+"."+number2+"."+number3, address);
                    }
        }
    }

    @Override
    public void close() throws IOException {
        if(!closed && propertiesFile!=null) {
            try (FileWriter fw = new FileWriter(propertiesFile)) {
                System.out.println("hostNames.size()="+hostNames.size());
                hostNames.store(fw, null);
            }
        }
        closed=true;
    }

    public void doInit(String[] args) throws FileNotFoundException, IOException {
        SimplerJSAP jsap;
        try {
            jsap = new SimplerJSAP(
                    "[--equivalentAddresses<File>] [--spidersList<File>] [--hostNameProperties<File>] [--maxLookups<int>] [--debug]");
        } catch (JSAPException ex) {
            throw new IllegalArgumentException(ex);
        }
        JSAPResult config = jsap.parse(args);
        if(hostNames==null) {
            propertiesFile=config.getFile("hostNameProperties", (File)null);
            hostNames=new Properties();
            if(propertiesFile!=null) {
                try {
                    hostNames.load(new FileReader(propertiesFile));
                }
                catch(FileNotFoundException ex) {
                    System.out.println("warning: "+propertiesFile+" not found, but will be created");
                }
            }
        }
        maxLookups=config.getInt("maxLookups", 20);
        if(spiders.isEmpty()) {
            File file=config.getFile("spidersList", (File)null);
            if(file!=null) {
                loadSpiders(new FileReader(file));
            }
        }
        if(EQUIVALENT_ADDRESSES.isEmpty()) {
            File file=config.getFile("equivalentAddresses", (File)null);
            if(file!=null) {
                loadEquivalentAddresses(new FileReader(file));
            }
        }
        init(args);
    }

    static String escapeEntityName(String s) {
//        char         c;
//        StringBuilder sb=null;
//        for(int i=0; i<s.length(); i++) {
//            c=s.charAt(i);
//            if(c=='_' || (!Character.isDigit(c) && !Character.isLetter(c))) {
//                if(sb==null) {
//                    if(i>0)
//                        sb=new StringBuilder(s.substring(0, i));
//                    else
//                        sb=new StringBuilder();
//                }
//                sb.append("_").append(Integer.toHexString(c)).append('_');
//            }
//            else
//                if(sb!=null)
//                    sb.append(c);
//        }
//        if(sb!=null)
//            return sb.toString();
        return s;
    }

    public static Analyzer getAnalyzer(String analyzerName) {
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

    String getByAddress(String ipAddress) {
//        if(ipAddress.equals(cacheRequest))
//            return cacheResponse;
        cacheRequest=ipAddress;
        if(!hostNames.isEmpty()) {
            String name=hostNames.getProperty(ipAddress);
            if(name==null) {
                // maybe the short name is available?
                String shortAddr = ipAddress.substring(0, ipAddress.lastIndexOf('.'));
                name=hostNames.getProperty(shortAddr);
                if(name==null) {
                    if(lookupCount>maxLookups) // nope, no more lookups
                        return cacheResponse=ipAddress;
                    // got to do this the hard way
                    lookupCount++;
                    String[] parts = ipAddress.split("\\.");
                    if(parts.length==4) {
                        try {
                            InetAddress inetAddr = InetAddress.getByAddress(new byte[]{(byte)Integer.parseInt(parts[0]), (byte)Integer.parseInt(parts[1]), (byte)Integer.parseInt(parts[2]), (byte)Integer.parseInt(parts[3])});
                            name=getHostName(inetAddr);
                            if(!name.equals(ipAddress)) {
                                hostNames.setProperty(ipAddress, name);
                                hostNames.setProperty(shortAddr, name);
                            }
                        } catch (UnknownHostException | NumberFormatException ex) {
                            System.out.println("error looking up \""+ipAddress+"\": "+ex.getMessage());
                            name=ipAddress;
                        }
                    }
                }
            }
            return cacheResponse=name;
        }
        return cacheResponse=ipAddress;
    }

    @SuppressWarnings("unchecked")
    public static String getHostName(InetAddress addr) {
        String host = null;
        List<NameService> nameServicesImpl = new ArrayList<>();
        try {
            // do naughty things...
            Field nameServices = InetAddress.class.getDeclaredField("nameServices");
            nameServices.setAccessible(true);
            nameServicesImpl = (List<NameService>) nameServices.get(null);
        } catch (Throwable t) {
            throw new RuntimeException("Got caught doing naughty things.", t);
        }
        for (NameService nameService : nameServicesImpl) {
            try {
                // lookup the hostname...
                host = nameService.getHostByAddr(addr.getAddress());
            } catch (Throwable t) {
                // NOOP: problem getting hostname from this name service, continue looping...
            }
        }
        return host != null ? host : addr.getHostAddress();
    }

    String getIdenticalIP(String ipAddr) {
        String shortAddr=getShortAddress(ipAddr);
        String identicalIP=IDENTICAL_ADDRESSES.get(shortAddr);
        if(identicalIP!=null)
            return identicalIP;
        return ipAddr;
    }
    
    static String getShortAddress(String ipAddress) {
        String shortAddr=ipAddress.substring(0, ipAddress.lastIndexOf('.'));
        String t=EQUIVALENT_ADDRESSES.get(shortAddr);
        if(t!=null)
            shortAddr=t;
        return shortAddr;
    }
    
    boolean isBlacklisted() {
        return blacklisted;
    }
    
    static private int[] makeNumbers(String number) {
        // either a star or a range
        if(number.equals("*"))
            return LIST256;
        String[] parts=number.split("-");
        if(parts.length==1) {
            int[] numbers=new int[1];
            numbers[0]=Integer.parseInt(number);
            return numbers;
        }
        int begin=Integer.parseInt(parts[0]);
        int end=Integer.parseInt(parts[1]);
        int num=end-begin+1;
        int[] numbers=new int[num];
        for(int i=begin; i<=end; i++)
            numbers[i-begin]=i;
        return numbers;
    }

    static void setBlacklisted(String line) {
        if(!spiders.isEmpty()) {
            Matcher m = logEntryPattern.matcher(line);
            if(m.find()) {
                String agent=m.group("UserAgent");
                for(String spider:spiders) {
                    if(agent.contains(spider)) {
                        blacklisted=true;
                        return;
                    }
                }
            }
        }
        if(!blacklistedIPs.isEmpty()) {
            String ipAddress=line.substring(0, line.indexOf(' '));
            for(String blackListedIP:blacklistedIPs) {
//                if(line.startsWith("132.174")) System.out.println("if("+ipAddress+".startsWith("+blackListedIP);
                if(ipAddress.startsWith(blackListedIP)) {
//                    if(line.startsWith("132.174")) System.out.println("blacklisting: "+ipAddress);
                    blacklisted=true;
                    return;
                }
            }
        }
        blacklisted=false;
    }

    public static void loadEquivalentAddresses(Reader file) throws FileNotFoundException, IOException {
        BufferedReader br=new BufferedReader(file);
        String line;
        while((line=br.readLine())!=null) {
            if(line.isEmpty() || line.startsWith("//"))
                continue;
            if(line.contains("-equivalent"))
                addAddresses(line, EQUIVALENT_ADDRESSES);
            else if(line.contains("-identical"))
                addAddresses(line, IDENTICAL_ADDRESSES);
            else if(line.contains("-blacklisted"))
                blacklistedIPs.add(line.substring(0, line.indexOf('-')));
            else {
                String[] parts=line.split("=");
                hostNames.put(parts[0], parts[1]);
            }
        }
    }

    static public void loadSpiders(FileReader reader) throws IOException {
        BufferedReader br=new BufferedReader(reader);
        String line;
        while((line=br.readLine())!=null) {
            spiders.add(line);
        }
    }
}
