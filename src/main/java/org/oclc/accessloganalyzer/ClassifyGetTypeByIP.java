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
public class ClassifyGetTypeByIP extends CountOfThingsByIP {

    static final String MANDATORY_START="GET /classify2/Classify";

    @Override
    public String getThing(String line) {
        Matcher m = logEntryPattern.matcher(line);
        if(!m.find())
            return null;
        String statusCode=m.group(6);
        if(!"200".equals(statusCode))
            return null;
        String request=m.group(5);
        if(!request.startsWith(MANDATORY_START))
            return null;
        request=request.substring(MANDATORY_START.length());
        if(request.contains("ident="))
            return "ident";
        if(request.contains("oclc="))
            return "oclc";
        if(request.contains("owi="))
            return "owi";
        if(request.contains("wi="))
            return "wi";
        if(request.contains("swid="))
            return "swid";
        if(request.startsWith("Demo")) {
            if(request.contains("search-title-txt"))
                return "title";
            if(request.contains("search-author-txt"))
                return "author";
            if(request.contains("search-standnum-txt"))
                return "stdnbr";
            if(request.contains("search-subhead-txt"))
                return "heading";
            return "otherDemo";
        }
        if(request.contains("title="))
            return "title";
        if(request.contains("author="))
            return "author";
        if(request.contains("stdnbr="))
            return "stdnbr";
        if(request.contains("heading="))
            return "heading";
        if(request.contains("isbn="))
            return "isbn";
        if(request.contains("issn="))
            return "issn";
        if(request.contains("upc="))
            return "upc";
        if(request.contains("lccn="))
            return "lccn";
        return "other";
    }
    
}
