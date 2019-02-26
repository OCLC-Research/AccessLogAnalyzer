/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.accessloganalyzer;

import java.util.regex.Pattern;

/**
 *
 * @author levan
 */
public class KBUsageOverTime extends UsageOverTime {

    @Override
    public void init(String[] args) {
        super.init(args);
        // timestamps normally have brackets around them, but someone has taken them off for the kb
        timePattern=Pattern.compile("[^\\s]+- - [^:]+:(\\d{2}):(\\d{2})[\\w:/]+\\s[+\\-]\\d{4}");
    }
}
