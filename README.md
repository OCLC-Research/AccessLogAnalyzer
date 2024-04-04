The _LogAnalyzer_ was written to produce a consolidated report from access logs for a service running on multiple servers. Originally named the
_AccessLogAnalyzer_, it was later observed that the program works well on any line-oriented files and access-log-specific parts of the program were
refactored out into the _AccessLogAnalyzer_ package. At OCLC, the _LogAnalyzer_ was used to produce reports from text debug logs containing embedded JSON.

The program runs in two phases.

In the first phase, the _LogAnalyzer_ reads through a single log, one line at a time, and passes that line to each of the _Analyzers_
it has been configured for. Each analyzer decides if the line has information for it and extracts and holds that information. At the end
of the phase, the _Analyzer_ produces an XML serialization of its extracted data and the _LogAnalyzer_ aggregates those serializations into a single
XML document that it writes.

In the _LogAnalyzer's_ initialization phase, it can read that previously written XML file and pass the stored data
from the _Analyzers_ back to them, allowing the _Analyzers_ to aggregate their data over time.

For the original project, the access logs were available via HTTP. This means that the _LogAnalyzer_ can read either local or remote logs. The
original logs lived in a directory with dates embedded in their filenames (a common practice.) The _LogAnalyzer_ can be provided with a template for
recreating those filenames from the date it is looking for.

In the second phase, a report is produced. Each _Analyzer_ is asked to provide a _HashMap_ of its data. The _LogAnalyzer_ combines them into a
single _HashMap_ and it is used by _FreeMarker_ (https://freemarker.sourceforge.io/features.html) to produce the report.

It is possible to run the _LogAnalyzer_ over the same
log periodically, producing near-real-time reports from the logs.
