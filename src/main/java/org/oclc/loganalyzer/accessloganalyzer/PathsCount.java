/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.loganalyzer.accessloganalyzer;

import org.oclc.loganalyzer.accessloganalyzer.CountOfAccessLogThings;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;

/**
 *
 * @author levan
 */
public class PathsCount extends CountOfAccessLogThings {

    @Override
    public List<String> getThings(String line) {
        Matcher m = logEntryPattern.matcher(line);
        if(!m.find())
            return NOTHING;
        String request=m.group(5);
//        System.out.println("request: "+request);
        int firstSpace=request.indexOf(' ');
        request=request.substring(firstSpace+1);
        int lastSlash=request.lastIndexOf('/');
        lastSlash=request.lastIndexOf('/', lastSlash-1);
        if(lastSlash>0) {
//            System.out.println("firstSpace="+firstSpace+", lastSlash="+lastSlash+", returning: "+request.substring(firstSpace+1, lastSlash));
            return Arrays.asList(request.substring(0, lastSlash));
        }
        return NOTHING;
    }
}
