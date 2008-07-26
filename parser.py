#!/usr/bin/env python
from __future__ import with_statement
from time import strftime, strptime
import re
import sys


#   tissynbe.py
#   Copyright (C) 2008  Marcin Wielgoszewski (tssci-security.com)
#
#   Thanks to the following people for their contributions:
#   Romain Gaucher (rgaucher.info)
#   
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

__author__  = [ 'Marcin Wielgoszewski',
		'Christopher Keller'
	    ]
__version__ = '1.9'

DB_HOST   = ''
DB_UNAME  = ''
DB_PASSWD = ''


nbe = 'testdata';

result = re.compile(r'(?P<descriptor>\w+\|)'
    r'(?P<subnet>\d*\.{0,1}\d*\.{0,1}\d*\|)'
    r'(?P<host>\d{0,3}\.{0,1}\d{0,3}\.{0,1}\d{0,3}\.{0,1}\d{0,3}\|)'
    r'(?P<service>(\W|\w)+\/)'						
    r'(?P<protocol>\w{0,4}\){0,1}\|)'
    r'(?P<pluginid>\d*\|)'
    r'(?P<note>.*\|)'
    r'(?P<description>.*$)'
    )
shortresult = re.compile(r'(?P<descriptor>\w+\|)'
    r'(?P<subnet>\d*\.{0,1}\d*\.{0,1}\d*\|)'
    r'(?P<host>\d{0,3}\.{0,1}\d{0,3}\.{0,1}\d{0,3}\.{0,1}\d{0,3}\|)'
    r'(?P<service>(\W|\w)+\/)'					
    r'(?P<protocol>\w{0,4}\)*)'
    )
    
timestamp = re.compile(r'(?P<descriptor>\w+\|)'
    r'(?P<blank>\|)'
    r'(?P<host>\d{0,3}\.{0,1}\d{0,3}\.{0,1}\d{0,3}\.{0,1}\d{0,3}\|)'
    r'(?P<status>.{0,15}\|)'						# scan start/end 
    r'(?P<datetime>\w{3}\s\w{3}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2}\s\d{4}\|$)'
    )

cve = re.compile(r'(?P<cve>CVE-\d{4}-\d{4})')

def parseResults(line,result,resultsList):
    """Parse a data line of a Nessus NBE file."""

    tempList = []
    
    m = result.search(line)
    if m:
	tempList.append(m.group('subnet').rstrip('|'))
	tempList.append(m.group('host').rstrip('|'))
	tempList.append(m.group('service').rstrip('1234567890(/'))
	tempList.append(m.group('protocol').rstrip('|)'))
	tempList.append(m.group('pluginid').rstrip('|'))
	tempList.append(m.group('note').replace('\\n', '').replace(':','').rstrip('|'))
	tempList.append(m.group('description').replace('\\n', ''))

	m = cve.search(tempList[len(tempList)-1])
	
	if m:
	    tempList.append(m.group('cve'))
	else:
	    tempList.append('None')
    else:
        print "ERROR %d: %s" % (numFields,line)
   
    resultsList.append(tempList)
    return resultsList

def parseTimestamps(line,timestamp,timestampsList):
    """Parse a timestamp line of a Nessus NBE file."""

    tempList = []

    m = timestamp.search(line)

    if m:
	tempList.append(m.group('host').rstrip('|'))
	tempList.append(m.group('status').rstrip('|'))
	tempList.append(m.group('datetime').rstrip('|'))
	tempList[2] = strftime("%Y-%m-%d %H:%M:%S", strptime(tempList[2]))

    else:
	print "ERROR %d: %s" % (numFields,line)

    timestampsList.append(tempList)
    return timestampsList

def parseshortResults(line,shortresult,shortresultsList):
    """Parse a short data line of a Nessus NBE file.
    Note that this line is most likely garbage.
    """

    m = shortresult.search(line)
    if m:
	shortresultsList.append(m.group('descriptor').rstrip('|'))
	shortresultsList.append(m.group('subnet').rstrip('|'))
	shortresultsList.append(m.group('host').rstrip('|'))
	shortresultsList.append(m.group('service').rstrip('1234567890(/'))
	shortresultsList.append(m.group('protocol').rstrip('|)'))
    else:
	print "ERROR %d: %s" % (numFields,line)

    return shortresultsList

def insert_nbe(results,timestamps,database):
    """Insert parsed Nessus data into MySQL database.

    This block of code will insert our processed Nessus data into the MySQL
    database specified with the -d option on the command line.  Before doing 
    so, ensure you have the proper database schema.  After doing our SQL 
    INSERTs, the number of rows inserted into each table is printed for 
    reference. For database schema information see 
    http://www.tssci-security.com/upload/tissynbe_py/nessusdb.sql
    
    """
    import MySQLdb
    print """Executing SQL INSERT..."""

    try:
        db = MySQLdb.connect(DB_HOST,DB_UNAME,DB_PASSWD,database)
    except MySQLdb.Error, e:
        print """Error %d: %s""" % (e.args[0], e.args[1])
        sys.exit (1)

    c = db.cursor()
    results_rows = 0
    timestamps_rows = 0

    while results:
        small_results, results = results[:100], results[100:]  
        c.executemany("""INSERT INTO results 
	    (network, host, service, protocol, pluginid, summary, description, cve) 
	    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""", (small_results))
        results_rows += c.rowcount

    while timestamps:
        small_timestamps, timestamps = timestamps[:100], timestamps[100:]
        c.executemany("""INSERT INTO timestamps 
                      (host,progress,datetime) 
                      VALUES (%s, %s, %s)""", (small_timestamps))
        timestamps_rows += c.rowcount

    db.commit()
    print """Number of rows inserted: %d results""" % results_rows
    print """Number of rows inserted: %d timestamps""" % timestamps_rows

def select_nbe(database, risk, order, sort):
    """Perform SQL SELECT query.
    
    This section of code is used to perform a SQL SELECT query of Nessus data 
    already in a database specified using the -d option on the command line.

    """
    import MySQLdb
    print """Executing SQL SELECT..."""

    try:
        db = MySQLdb.connect(DB_HOST,DB_UNAME,DB_PASSWD,database)
    except MySQLdb.Error, e:
        print """Error %d: %s""" % (e.args[0], e.args[1])
        sys.exit (1)

    c = db.cursor()

    c.execute("""SELECT domain, host, service, scriptid, riskval, msg1, msg2 
              FROM results WHERE riskval >= %s 
              ORDER BY %s %s""", (risk, order, sort))

    results = c.fetchall()
    return results


def count_nbe(database, risk):
    """Perform SQL SELECT query displaying plugins by count.

    This function is similar to select_nbe(), except that it does not record
    domain or host information, instead performs a tally of plugins by count.  
    It is only called when --count is specified with a database on the command 
    line.
    
    """
    import MySQLdb
    print """Executing SQL SELECT with COUNT..."""

    try:
        db = MySQLdb.connect(DB_HOST,DB_UNAME,DB_PASSWD,database)
    except MySQLdb.Error, e:
        print """Error %d: %s""" % (e.args[0], e.args[1])
        sys.exit (1)

    c = db.cursor()

    c.execute("""SELECT riskval, COUNT(scriptid) AS count, 
              scriptid, msg1, msg2, service 
              FROM results GROUP BY scriptid HAVING riskval >= %s 
              ORDER BY riskval DESC, count DESC, scriptid DESC""", (risk))

    results = c.fetchall()
    return results


def write_csv(file,data):
    """Write to CSV file.

    Used with the -o option on the command line.
    
    """
    import csv
    if data:
        print """Writing""", file + """..."""
        writer = csv.writer(open(file,"wb"))
        writer.writerows(data)
    else:
        print """Error occurred while processing: no data to write!"""



def parse_nbe(nbe, resultsList, shortresultsList, timestampsList):
    """Open an nbe file, parse, then split into fields.
        
    This code opens our input file we specified gracefully.  It then begins to
    process our data by calling clean_nbe() and then finally splits each line 
    on the pipe-delimiter.  If a line has less fields than required, it will 
    print the line to stdout.  Copy stdout to a file and send to
    tissynbe _at_ tssci-security.com.  I'll update the script to account for 
    these errors in processing.

    """
    
    print """Processing""", nbe + """..."""

    with open(nbe, 'rU') as file:

        for line in file:
	    line = line.rstrip()
	    numFields = len(line.split('|'))
	    if numFields >= 7:
		resultsList = parseResults(line,result,resultsList)
	    elif numFields == 6:
		timestampsList = parseTimestamps(line,timestamp,timestampsList)
	    elif numFields == 4:
		shortresultsList = parseshortResults(line,shortresult,shortresultsList)
    
    return resultsList, shortresultsList, timestampsList

    
def main():
    results = []
    shortresults = []
    timestamps = []
    
    """The main() function that contains our use cases."""
    if opt.infile and opt.database and opt.outfile:
        results, shortresults, timestamps = parse_nbe(opt.infile, results, shortresults, timestamps)
        insert_nbe(results,timestamps,opt.database)
        write_csv(opt.outfile,results)
    elif opt.infile and opt.database:
        results, shortresults, timestamps = parse_nbe(opt.infile, results, shortresults, timestamps)
        insert_nbe(results,timestamps,opt.database)
    elif opt.database and opt.outfile:
        if opt.count:
            results = count_nbe(opt.database,opt.risk)
        else:
            results = select_nbe(opt.database,opt.risk,opt.order,opt.sort)
        write_csv(opt.outfile,results)
    elif opt.infile and opt.outfile:
        results, shortresults, timestamps = parse_nbe(opt.infile, results, shortresults, timestamps)
        write_csv(opt.outfile,results)
    else:
        print parser.error("You are missing arguments, see usage or help")


if __name__ == "__main__":
    from optparse import OptionParser, make_option
    option_list = [
        make_option("-d", "--database", dest="database", 
                    help="query results from specified MySQL database"),
        make_option("-f", "--file", dest="infile", 
                    help="input nbe file to parse"),
        make_option("-o", "--output-file", dest="outfile", 
                    help="output to CSV file"),
        make_option("-r", "--risk", type="choice", dest="risk", default="1", 
                    help="minimum risk criticality to query", 
                    choices=["1","2","3"]),
        make_option("--count", action="store_true", dest="count", 
                    help="output results by count"),
        make_option("--order", type="choice", dest="order", default="host", 
                    help="order database query by column", 
                    choices=["host","service","scriptid","riskval"]),
        make_option("--sort", type="choice", dest="sort", default="", 
                    help="sort results descending", choices=["","desc"])
    ]

    usage  = """usage: tissynbe.py [options] args
tissynbe.py -d database -f results.nbe
tissynbe.py -d database -o output.csv
tissynbe.py -d database -o output.csv --order scriptid --sort desc
tissynbe.py -d database -o output.csv --count
tissynbe.py -f results.nbe -o output.csv
tissynbe.py -f results.nbe -d database -o output.csv"""
    parser = OptionParser(usage,option_list=option_list)
    opt, args = parser.parse_args()
    main()
