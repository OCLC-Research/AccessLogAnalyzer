/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.loganalyzer;

import java.io.Closeable;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;

/**
 *
 * @author levan
 */
public abstract class Analyzer implements Closeable {

    public HashMap<String, String> extraAbstractions=new HashMap<>();

    public abstract void analyze(String line);
    public abstract void init(String[] args) throws Exception;
    public abstract void load(String content, Date date);
    public abstract void merge(String content, int dayNumber);
    public abstract Object report();
    public abstract String unload() throws Exception;

    @Override
    public void close() throws IOException {
    }

    public void doInit(String[] args) throws Exception {
        init(args);
    }

    public static Analyzer getAnalyzer(String analyzerName) {
        Class<? extends Analyzer> c;
        Analyzer analyzer;
        String        name=getAnalyzerClassName(analyzerName);

        try {
            c=Class.forName(name).asSubclass(Analyzer.class);
        }
        catch(ClassNotFoundException e) {
            throw new IllegalArgumentException(name, e);
        }

        try {
            analyzer=c.newInstance();
        }
        catch(InstantiationException | IllegalAccessException e) {
            throw new IllegalArgumentException(name, e);
        }

        return analyzer;
    }

    private static String getAnalyzerClassName(String name) {
        if (name.indexOf('.')<0)
            return "org.oclc.accessloganalyzer."+name;

        return name;
    }
}
