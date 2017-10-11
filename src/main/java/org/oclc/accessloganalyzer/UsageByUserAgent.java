package org.oclc.accessloganalyzer;

import java.util.regex.Matcher;

/**
 *
 * @author levan
 */
public class UsageByUserAgent extends CountOfThings {

    @Override
    public String getThing(String line) {
        Matcher m = logEntryPattern.matcher(line);
        if(!m.find())
            return null;
        return m.group(8); // agent
    }
}
