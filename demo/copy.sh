cp abstractedAccessLogs/content-$1 /viafdata/stats/prod/stats/
rm -f /viafdata/stats/prod/stats/day-$1.html
cp reports/day-$1.html /viafdata/stats/prod/stats/
cp reports/week-201701* /viafdata/stats/prod/stats/
cp reports/month-201701.html /viafdata/stats/prod/stats/
cp reports/year-2017.html /viafdata/stats/prod/stats/

