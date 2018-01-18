/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.accessloganalyzer;

import java.util.Arrays;
import java.util.List;

/**
 *
 * @author levan
 */
public class UsageByIP extends CountOfThingsByIP {

    List<String> thing=Arrays.asList("Transactions");

    @Override
    public List<String> getThings(String line) {
        return thing;  // we'll end up counting the number of transactions
    }
}
