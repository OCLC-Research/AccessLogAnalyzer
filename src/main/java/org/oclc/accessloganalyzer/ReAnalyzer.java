/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.accessloganalyzer;

import java.util.Date;

/**
 *
 * @author levan
 */
public abstract class ReAnalyzer extends Analyzer {

    @Override
    public void analyze(String string) {
        // reanalyzers don't analyze logs
    }

    @Override
    public void load(String string, Date date) {
        // reanalyzers don't do that either
    }

    @Override
    public String unload() {
        return null; // reanalyzers don't save anything either
    }
}
