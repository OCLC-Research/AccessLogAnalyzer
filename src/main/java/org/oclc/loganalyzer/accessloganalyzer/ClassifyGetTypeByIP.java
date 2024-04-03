/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.loganalyzer.accessloganalyzer;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;

/**
 *
 * @author levan
 */
public class ClassifyGetTypeByIP extends CountOfThingsByIP {

    static final String MANDATORY_START="GET /classify2/Classify";

    @Override
    public List<String> getThings(String line) {
        Matcher m = logEntryPattern.matcher(line);
        if(!m.find())
            return NOTHING;
        String statusCode=m.group(6);
        if(!"200".equals(statusCode))
            return NOTHING;
        String request=m.group(5);
        if(!request.startsWith(MANDATORY_START))
            return NOTHING;
        request=request.substring(MANDATORY_START.length());
        if(request.contains("ident="))
            return Arrays.asList("ident");
        if(request.contains("oclc="))
            return Arrays.asList("oclc");
        if(request.contains("owi="))
            return Arrays.asList("owi");
        if(request.contains("wi="))
            return Arrays.asList("wi");
        if(request.contains("swid="))
            return Arrays.asList("swid");
        if(request.startsWith("Demo")) {
            if(request.contains("search-title-txt"))
                return Arrays.asList("title");
            if(request.contains("search-author-txt"))
                return Arrays.asList("author");
            if(request.contains("search-standnum-txt"))
                return Arrays.asList("stdnbr");
            if(request.contains("search-subhead-txt"))
                return Arrays.asList("heading");
            return Arrays.asList("otherDemo");
        }
        if(request.contains("title="))
            return Arrays.asList("title");
        if(request.contains("author="))
            return Arrays.asList("author");
        if(request.contains("stdnbr="))
            return Arrays.asList("stdnbr");
        if(request.contains("heading="))
            return Arrays.asList("heading");
        if(request.contains("isbn="))
            return Arrays.asList("isbn");
        if(request.contains("issn="))
            return Arrays.asList("issn");
        if(request.contains("upc="))
            return Arrays.asList("upc");
        if(request.contains("lccn="))
            return Arrays.asList("lccn");
        return Arrays.asList("other");
    }
}
