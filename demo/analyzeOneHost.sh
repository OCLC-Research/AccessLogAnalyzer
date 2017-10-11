hostname=$1

java -cp "java/lib/*" org.oclc.accessloganalyzer.AccessLogAnalyzer --logNameTemplate "'logs/${hostname}/catalina_access_log.'yyyy-MM-dd'.log'" --remoteLogNameTemplate "'http://${hostname}.prod.oclc.org:8007/logs/catalina_access_log.'yyyy-MM-dd'.log'" --reportNameTemplate "'reports/day-'yyyyMMdd'.html'" --contentNameTemplate "'abstractedAccessLogs/content-'yyyyMMdd" --analyzers "UsageByIP" --freemarkerTemplateName "Template Example 3.1.html" --date yesterday --maxDaysToProcess 2
