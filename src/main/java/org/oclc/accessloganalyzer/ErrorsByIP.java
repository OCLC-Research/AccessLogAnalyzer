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
public class ErrorsByIP extends UsageByIP {
    @Override
    public void analyze(String line) {
        Matcher m = logEntryPattern.matcher(line);
        if(!m.find())
            return;
        int code=Integer.parseInt(m.group(6));
        if(code<400 || code>499)
            return;
        super.analyze(line);
    }
}
