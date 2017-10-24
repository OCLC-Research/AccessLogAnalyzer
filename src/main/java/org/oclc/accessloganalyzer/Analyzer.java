/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.accessloganalyzer;

import ORG.oclc.os.JSAP.SimplerJSAP;
import com.martiansoftware.jsap.JSAPException;
import com.martiansoftware.jsap.JSAPResult;
import java.io.Closeable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Date;
import java.util.HashMap;
import java.util.Properties;
import java.util.regex.Pattern;

/**
 *
 * @author levan
 */
public abstract class Analyzer implements Closeable {

    private static final HashMap<String, String> EQUIVALENTS=new HashMap<>();
    static Properties hostNames;
    static private File propertiesFile;
    private boolean closed=false;
    public Pattern logEntryPattern = Pattern.compile("^(?<RemoteHost>[\\d.]+) (?<Identity>\\S+) (?<UserName>\\S+) \\[(?<Time>[\\w:/]+\\s[+\\-]\\d{4})\\] \"(?<Request>.+?)\" (?<StatusCode>\\d{3}) (?<Size>\\d+) \"(?<Referer>[^\"]+)\" \"(?<UserAgent>[^\"]+)\"");
    private int lookupCount=0, maxLookups=20;

    public abstract void analyze(String line);
    public abstract void init(String[] args);
    public abstract void load(String content, Date date);
    public abstract void merge(String content, int dayNumber);
    public abstract Object report();
    public abstract String unload();

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
        if(hostNames==null) {
            SimplerJSAP jsap;
            try {
                jsap = new SimplerJSAP(
                        "[--hostNameProperties<File>] [--maxLookups<int>] [--debug]");
            } catch (JSAPException ex) {
                throw new IllegalArgumentException(ex);
            }
            JSAPResult config = jsap.parse(args);
            propertiesFile=config.getFile("hostNameProperties", (File)null);
            hostNames=new Properties();
            if(propertiesFile!=null) {
                try {
                    hostNames.load(new FileReader(propertiesFile));
                    String newShortName, shortNames[], value;
                    for(String name:hostNames.stringPropertyNames()) {
                        if(name.startsWith("equivalent-")) {
                            newShortName=name.substring(11);
                            value=hostNames.getProperty(name);
                            shortNames=value.split(",");
                            for(String shortName:shortNames)
                                EQUIVALENTS.put(shortName, newShortName);
                        }
                        else if(name.endsWith("-equivalent")) {
                            newShortName=name.substring(11);
                            value=hostNames.getProperty(name);
                            shortNames=value.split(",");
                            for(String shortName:shortNames)
                                EQUIVALENTS.put(shortName, newShortName);
                        }
                    }
                }
                catch(FileNotFoundException ex) {
                    System.out.println("warning: "+propertiesFile+" not found, but will be created");
                }
            }
            maxLookups=config.getInt("maxLookups", 20);
        }
        init(args);
    }

    String getByAddress(String ipAddress) {
        if(propertiesFile!=null && lookupCount<maxLookups) {
            String name=hostNames.getProperty(ipAddress);
            if(name==null) {
                // maybe the short name is available?
                String shortAddr = ipAddress.substring(0, ipAddress.lastIndexOf('.'));
                name=hostNames.getProperty(shortAddr);
                if(name==null) {
                    // got to do this the hard way
                    lookupCount++;
                    String[] parts = ipAddress.split("\\.");
                    if(parts.length==4) {
                        try {
                            name=InetAddress.getByAddress(new byte[]{(byte)Integer.parseInt(parts[0]), (byte)Integer.parseInt(parts[1]), (byte)Integer.parseInt(parts[2]), (byte)Integer.parseInt(parts[3])}).getHostName();
                            hostNames.setProperty(ipAddress, name);
                            hostNames.setProperty(shortAddr, name);
                        } catch (UnknownHostException | NumberFormatException ex) {
                            System.out.println("error looking up \""+ipAddress+"\": "+ex.getMessage());
                            name=ipAddress;
                        }
                    }
                }
                else {
                    // cache the new long name
                    hostNames.setProperty(ipAddress, name);
                }
            }
            return name;
        }
        return ipAddress;
    }
    
    String getShortAddress(String ipAddress) {
        String shortAddr=ipAddress.substring(0, ipAddress.lastIndexOf('.'));
        String t=EQUIVALENTS.get(shortAddr);
        if(t!=null)
            shortAddr=t;
        return shortAddr;
    }
}
