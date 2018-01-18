/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.oclc.accessloganalyzer;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Properties;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import static org.oclc.accessloganalyzer.ReportConsolidator.callAnalyzers;

/**
 *
 * @author levan
 */
public class ReportConsolidatorServlet extends HttpServlet {

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            boolean daily=false, weekly=false, monthly=false, annual=false;
            boolean debug=getBoolean(request, "debug", false);
            String date = request.getParameter("date");
            Date today = new Date(new SimpleDateFormat("yyyyMMdd").parse(date).getTime());
            int calendarUnit=-1, numDays=0;
            Calendar cal=Calendar.getInstance();
            cal.setTime(today);
            cal.set(Calendar.HOUR_OF_DAY, 0);
            cal.set(Calendar.MINUTE, 0);
            cal.set(Calendar.SECOND, 0);
            if(getBoolean(request, "daily", false)) {
                daily=true;
                calendarUnit=Calendar.DAY_OF_YEAR;
                numDays=1;
            }
            if(getBoolean(request, "weekly", false)||getBoolean(request, "week", false)) {
                weekly=true;
                cal.set(Calendar.DAY_OF_WEEK, cal.getFirstDayOfWeek());
                calendarUnit=Calendar.WEEK_OF_YEAR;
                numDays=7;
            }
            if(getBoolean(request, "monthly", false)||getBoolean(request, "month", false)) {
                monthly=true;
                cal.set(Calendar.DAY_OF_MONTH, 1);
                calendarUnit=Calendar.MONTH;
                numDays=cal.getActualMaximum(Calendar.DAY_OF_MONTH);
            }
            if(getBoolean(request, "annual", false)||getBoolean(request, "year", false)) {
                annual=true;
                cal.set(Calendar.DAY_OF_YEAR, 1);
                calendarUnit=Calendar.YEAR;
                numDays=cal.getActualMaximum(Calendar.DAY_OF_YEAR);
            }
            if(calendarUnit==-1)
                throw new ServletException("Missing a calendar flag: --weekly, --monthly or --annual");

            Configuration cfg = new Configuration(Configuration.VERSION_2_3_25);
            String freemarkerTemplateDirectoryName=request.getParameter("freemarkerTemplateDirectory");
            if(freemarkerTemplateDirectoryName==null)
                throw new ServletException("Missing freemarkerTemplateDirectory parameter");
            String freemarkerTemplateDirectory = getServletContext().getRealPath(freemarkerTemplateDirectoryName);
            cfg.setDirectoryForTemplateLoading(new File(freemarkerTemplateDirectory));
            cfg.setDefaultEncoding("UTF-8");
            cfg.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
            cfg.setLogTemplateExceptions(false);
            String freemarkerTemplateName=request.getParameter("freemarkerTemplateName");
            if(freemarkerTemplateName==null)
                throw new ServletException("Missing freemarkerTemplateName parameter");
            Template t = cfg.getTemplate(freemarkerTemplateName);
            String contentDirectoryName=request.getParameter("contentDirectory");
            if(contentDirectoryName==null)
                throw new ServletException("Missing contentDirectory parameter");
            File contentDirectory=new File(getServletContext().getRealPath(contentDirectoryName));
            String contentNameTemplate=request.getParameter("contentNameTemplate");
            if(contentNameTemplate==null)
                throw new ServletException("Missing contentNameTemplate parameter");
            String analyzers=request.getParameter("analyzers");
            if(analyzers==null)
                throw new ServletException("Missing analyzers parameter");
            String hostNames=request.getParameter("hostNames");
            if(hostNames!=null) {
                Analyzer.hostNames=new Properties();
                Analyzer.hostNames.load(new FileReader(getServletContext().getRealPath(hostNames)));
            }
            String equivalents=request.getParameter("ipEquivalents");
            if(equivalents!=null)
                Analyzer.loadEquivalentAddresses(new FileReader(getServletContext().getRealPath(equivalents)));
            String spiders=request.getParameter("spiders");
            if(spiders!=null)
                Analyzer.loadSpiders(new FileReader(getServletContext().getRealPath(spiders)));
            String args=request.getParameter("args");
            if(args==null)
                args="";
            System.out.println("args="+args);
            System.out.println("args[]="+Arrays.toString(args.split(",")));
            callAnalyzers(cal, daily, weekly, monthly, annual, numDays, t,
              contentDirectory, contentNameTemplate, analyzers.split(","), args.split(","),
              response.getWriter(), debug);
        } catch (ParseException | TemplateException ex) {
            throw new ServletException(ex);
        }
    }

    @Override
    public void init() throws ServletException {
    }

    private boolean getBoolean(HttpServletRequest request, String parameter, boolean defaultValue) {
        String value=request.getParameter(parameter);
        if(value==null)
            return defaultValue;
        return Boolean.parseBoolean(value);
    }
}
