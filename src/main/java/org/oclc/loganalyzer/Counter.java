/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.loganalyzer;

import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.apache.commons.text.StringEscapeUtils;

/**
 *
 * @author levan
 * @param <T>
 */
public class Counter<T extends Comparable<T>> extends TreeMap<T, Long> {

    private static final long serialVersionUID = 1L;

    public Long get(T key, long defaultValue) {
        Long value=get(key);
        if(value!=null)
            return value;
        return defaultValue;
    }

    public Long increment(T key) {
        return increment(key, 1L);
    }

    public Long increment(T key, long incrementAmount) {
        long value=getOrDefault(key, 0L);
        return put(key, value+incrementAmount);
    }
    
    public List<Map.Entry<T, Long>> most_common() {
        ValueComparator bvc=new ValueComparator(this);
        TreeMap<T, Long> sortedThings=new TreeMap<>(bvc);
        sortedThings.putAll(this);
        LinkedList<Map.Entry<T, Long>> bob=new LinkedList<>(sortedThings.entrySet());
        return bob;
    }
    
//    public List<Map.Entry<T, Long>> most_common() {
//        List<Map.Entry<T, Long>> list =
//            new LinkedList<>( this.entrySet() );
//        Collections.sort(list, (Map.Entry<T, Long> o1, Map.Entry<T, Long> o2) -> {
//            int retval = (o2.getValue()).compareTo( o1.getValue() ); // reverse the order of the values
//            if(retval==0)
//                retval=o1.getKey().compareTo(o2.getKey());
//            return retval;
//        });
//
//        return list;
//    }
    
    public List<Map.Entry<T, Long>> most_common(int numEntriesReturned) {
        List<Map.Entry<T, Long>> list = most_common();
        if(list.size()<=numEntriesReturned)
            return list;
        return list.subList(0, numEntriesReturned);
    }

    public String toXML() {
        StringBuilder sb=new StringBuilder();
        for(Map.Entry<T, Long> entry:most_common()) {
            sb.append("<").append(StringEscapeUtils.escapeXml10(entry.getKey().toString())).append(">").append(entry.getValue()).append("</").append(entry.getKey().toString()).append(">");
        }
        return sb.toString();
    }

    public void update(Counter<T> counter) {
        counter.keySet().forEach((key) -> {
            increment(key, counter.get(key));
        });
    }
    
    class ValueComparator implements Comparator<T> {

        private final TreeMap<T, Long> map;

        public ValueComparator(TreeMap<T, Long> map) {
            this.map=map;
        }
        
        @Override
        public int compare(T a, T b) {
            long retval=map.get(b)-map.get(a); // reverse the order of number comparisons
            if(retval==0)
                retval=a.compareTo(b);
            if(retval<0)
                return -1;
            if(retval>0)
                return 1;
            return 0;
        }
    }
}