package org.oclc.loganalyzer.accessloganalyzer;

import org.oclc.loganalyzer.accessloganalyzer.CountOfAccessLogThings;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;

/**
 *
 * @author levan
 */
public class UsageByUserAgent extends CountOfAccessLogThings {

    @Override
    public List<String> getThings(String line) {
        Matcher m = logEntryPattern.matcher(line);
        if(!m.find())
            return NOTHING;
        return Arrays.asList(m.group(8)); // agent
    }
}
