/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.accessloganalyzer;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;

/**
 *
 * @author levan
 */
public class UserAgentByIP extends CountOfThingsByIP {

    @Override
    public List<String> getThings(String line) {
        Matcher m = logEntryPattern.matcher(line);
        if(!m.find())
            return NOTHING;
        String agent = m.group("UserAgent");
        if(agent.isEmpty())
            return Arrays.asList("No UserAgent");
        return Arrays.asList(agent);
    }
}
