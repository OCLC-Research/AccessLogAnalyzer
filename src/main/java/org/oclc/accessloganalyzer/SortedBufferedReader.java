/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.accessloganalyzer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.Comparator;
import java.util.PriorityQueue;

/**
 *
 * @author levan
 */
public class SortedBufferedReader extends BufferedReader {

    private final PriorityQueue<String> buffer;
    private boolean eof=false;

    public SortedBufferedReader(Reader reader, int numLinesToBuffer, Comparator<String> comparator) throws IOException {
        super(reader);
        if(comparator!=null)
            buffer=new PriorityQueue<>(numLinesToBuffer, comparator);
        else
            buffer=new PriorityQueue<>(numLinesToBuffer);
        String line;
        while(--numLinesToBuffer>0) {
            line=super.readLine();
            if(line==null)
                break;
            buffer.add(line);
        }
    }
    
    @Override
    public String readLine() throws IOException {
        String line=null;
        if(!eof)
            line=super.readLine();
        if(line==null)
            eof=true;
        else
            buffer.add(line);
        if(buffer.isEmpty())
            return null;
        return buffer.remove();
    }
    
}
