/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.accessloganalyzer;

import java.util.regex.Matcher;

/**
 *
 * @author levan
 */
public class PathsCount extends CountOfThings {

    @Override
    public String getThing(String line) {
        Matcher m = logEntryPattern.matcher(line);
        if(!m.find())
            return null;
        String request=m.group(5);
//        System.out.println("request: "+request);
        int firstSpace=request.indexOf(' ');
        request=request.substring(firstSpace+1);
        int lastSlash=request.lastIndexOf('/');
        lastSlash=request.lastIndexOf('/', lastSlash-1);
        if(lastSlash>0) {
//            System.out.println("firstSpace="+firstSpace+", lastSlash="+lastSlash+", returning: "+request.substring(firstSpace+1, lastSlash));
            return request.substring(0, lastSlash);
        }
        return null;
    }
    
}
