package org.oclc.accessloganalyzer;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;

/**
 *
 * @author levan
 */
public class UsageByUserAgent extends CountOfThings {

    @Override
    public List<String> getThings(String line) {
        Matcher m = logEntryPattern.matcher(line);
        if(!m.find())
            return NOTHING;
        return Arrays.asList(m.group(8)); // agent
    }
}
