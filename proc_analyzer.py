#!/usr/bin/env python
"""
	SQL stored procedure analysis
	by Romain Gaucher <r@rgaucher.info> - http://rgaucher.info

	Copyright (c) 2011-2012 Romain Gaucher <r@rgaucher.info>

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

	Last revision: 2011, Friday, March 18, 3:23 AM
"""
import os, sys
import unicodedata
import re
import json

try:
	import sqlparse
except:
	print "Missing package: 'sqlparse'"
	print "Please run the following command"
	print " $ sudo easy_install sqlparse"
	sys.exit()

import logging
import logging.config
logging.config.fileConfig("log.conf")
log = logging.getLogger("procanalyzer")

__isiterable = lambda obj: isinstance(obj, basestring) or getattr(obj, '__iter__', False)
__normalize_argmt = lambda x: ''.join(x.lower().split())
__normalize_path = lambda x: os.path.abspath(x)
__normalize_paths = lambda x: [os.path.abspath(of) for of in x]


CONCATENATION = {
	'tokens': [sqlparse.tokens.Operator],
	'values': ['+', '||'],
}

CONTEXTS = {
	0x01 : ['EXEC', 'EXECUTE'],
	0x02 : ['UPDATE', 'SELECT', 'INSERT', 'DELETE', 'ALTER']
}
OVERALL_CONTEXTS = CONTEXTS[0x01] + CONTEXTS[0x02]

def normalize_charset(rts):
	return unicodedata.normalize('NFKD', unicode(rts, errors='ignore')).encode('ascii', 'ignore')

"""
	From a list of tokens, extract bad behavior:
	  EXEC <str> + @input + <str>
	  EXEC @input
"""
def analyze_for_behavior(parsed, proc_parameters):
	p_tokens = []
	first, interesting, ctxt = True, False, None
	for item in parsed:		
		if item is None or item.ttype == sqlparse.tokens.Whitespace:
			continue
		if isinstance(item, sqlparse.sql.IdentifierList):
			for identifier in item.get_identifiers():
				if identifier is None:
					continue
				if isinstance(identifier, sqlparse.sql.Identifier):
					try:
						p_tokens.append((sqlparse.sql.Identifier, identifier.get_name()))
					except Exception, error:
						log.exception("analyze_for_behavior:: Exception in instance(... identifier.get_name()) -- Exception: %s" % error)
						continue
				else:
					if item.ttype == sqlparse.tokens.Whitespace:
						continue
					else:
						p_tokens.append((item.ttype, item.value))
		elif isinstance(item, sqlparse.sql.Identifier):
			try:
				p_tokens.append((sqlparse.sql.Identifier, item.get_name()))
			except Exception, error:
				log.exception("analyze_for_behavior:: Exception in instance(... item.get_name()) -- Exception: %s" % error)
				continue
		
		if first:
			if item.ttype in (sqlparse.tokens.Keyword, sqlparse.tokens.DML) and item.value.upper() in OVERALL_CONTEXTS:
				interesting = True
				first = False
				ctxt = item.value.upper()
		if interesting:	
			# print item.ttype, item.value
			if None == item.ttype:
				continue
			p_tokens.append((item.ttype, item.value))
	
	# No result!
	if not interesting:
		return (False, [])
	
	has_punctuation = 0 < len([k for k in p_tokens if k[0] == sqlparse.tokens.Punctuation and k[1] == ','])
	has_concat = 0 < len([k for k in p_tokens if k[0] in CONCATENATION['tokens'] and k[1] in CONCATENATION['values']])
	has_assign = ctxt in CONTEXTS[0x02] and 0 < len([k for k in p_tokens if k[0] == sqlparse.tokens.Comparison and k[1] == "="])
	
	log.debug("ctxt=%s, has_concat=%s, has_punctuation=%s, has_assign=%s" % (ctxt, has_concat, has_punctuation, has_assign))
	
	found = []
	return_value = False
	# Is there concatenation?
	if has_concat and (not has_punctuation or has_assign):
		for p_token in p_tokens:
			if p_token[0] == sqlparse.sql.Identifier and p_token[1] in proc_parameters:
				log.debug("has_concat, has_punctuation and parameter '%s' in the list" % p_token[1])
				return_value = True
				if p_token[1] not in found:
					found.append(p_token[1])
	# if not, only true if the value is coming from a parameter
	elif ctxt in CONTEXTS[0x01]:
		if 2 == len(p_tokens):
			p_token = p_tokens[1]
			if p_token[0] == sqlparse.sql.Identifier and p_token[1] in proc_parameters:
				return_value = True
				if p_token[1] not in found:
					found.append(p_token[1])
		elif has_concat:
			# totally noisy, we need to check that it's not an exec of a stored proc.
			# we do this by being sure that '@' is in the name... only works in TSQL
			p_token = p_tokens[1]
			if p_token[0] == sqlparse.sql.Identifier and '@' in p_token[1]:
				return_value = True
				if p_token[1] not in found:
					found.append(p_token[1])			

	return (return_value, found)


"""
	Remove comments 
"""
def remove_comments(rts, separator):
	rts = re.sub(re.compile("/\*.*?\*/", re.DOTALL), "", rts)
	rts = re.sub(re.compile("\-\-.*?%s" % separator, re.DOTALL), "%s" % separator, rts)
	return rts

"""
	Make sure to split the procedure into statements (sqlparse doesn't handle that well enough)
"""
def statement_split(rts):
	statements = []
	tokens_stream = []
	parsed = sqlparse.parse(rts)[0]
	for item in parsed.tokens:
		if item.ttype == sqlparse.tokens.Text.Whitespace.Newline:
			# push what we had
			if 1 < len(tokens_stream):
				statements.append(tokens_stream)
			tokens_stream = []
		else:
			tokens_stream.append(item)
	return statements

"""
	Analyze a SQL file passed in argument
"""
def analyze_sql(conf):
	# load the file
	sbuf = open(conf['sql'], 'r').read()
	# clean UTF and weird characters
	sbuf = normalize_charset(sbuf)
	
	separator = '\r\n'
	if separator not in sbuf:
		separator = '\r' if '\r' in sbuf else '\n'	
	
	# reformat to strip the comments out
	print "Cleaning SQL code...."
	sbuf = remove_comments(sbuf, separator)
	
	# extract the procedures and create files	
	reg_create_proc = re.compile(r'(CREATE\s+PROCEDURE)', re.I)
	reg_pname = re.compile('[\W+]PROCEDURE ([^%s]+)%s' % (separator, separator), re.M | re.I)
	reg_param_name = re.compile(r'(@[^\s]+)\s+N?VARCHAR', re.I)
	
	findings = {}
	procedures = sbuf.split('END%sGO' % separator)
	print "Procedure-level analysis"
	for proc in procedures:
		create_proc_needle = reg_create_proc.search(proc)
		if not create_proc_needle:
			log.exception("No procedure found!")
			continue
		else:
			create_proc_needle = create_proc_needle.groups()[0]
		
		proc = proc[proc.find(create_proc_needle):] + 'END' + separator + 'GO'
		
		#1- extract procedure name
		proc_name = None
		rgpname = reg_pname.search(proc)
		if rgpname:
			proc_name = rgpname.groups()[0]
			proc_name = ''.join(proc_name.split())
		else:
			log.exception("No procedure name found in %s..." % proc[:50])
			continue
		
		#2- extract parameters of the procedure
		end_str_find = 'AS%s' % (separator)
		end_stmt = proc.find(end_str_find)
		proc_header = proc[proc.find(proc_name)+len(proc_name):end_stmt]
		sql_body = proc[end_stmt + len(end_str_find):]
		
		proc_header_tmp = proc_header.replace(separator, ' ').replace('\r', ' ')
		proc_header_tmp = ' '.join(proc_header_tmp.split())
		proc_parameters = reg_param_name.findall(proc_header_tmp)
		
		# did not find any parameters (NVARCHAR)?
		if 0 == len(proc_parameters):
			continue
		
		# 3- parse the SQL statements
		log.debug("Analyze procedure: %s... (%d parameters found)" % (proc_name, len(proc_parameters)))
		log.debug("... %s" % repr(proc_parameters))
		sql_body = sqlparse.format(sql_body, reindent=False, keyword_case='upper', strip_comments=True, indent_tables=False)
		statements = statement_split(sql_body)
		for query in statements:
			parsed = query
			has_findings, list_parameters = analyze_for_behavior(parsed, proc_parameters)
			if has_findings:
				print "Procedure %s has issue with the %s parameter(s)" % (proc_name, list_parameters)
				if proc_name not in findings:
					findings[proc_name] = []
				for p in list_parameters:
					if p not in findings[proc_name]:
						findings[proc_name].append(p)
	
	if 0 == len(findings):
		print "No finding for %s..." % conf['sql']
	else:
		print "%d bad code constructs were detected in %s!" % (len(findings), conf['sql'])
		output_fname = conf['sql'][conf['sql'].rfind(os.sep)+1:conf['sql'].rfind('.')] + "-findings.json"
		if conf['output']:
			output_fname = conf['output']
	
		o = open(output_fname, 'w')
		o.write(json.dumps(findings))
		o.close()
		print "Results stored in '%s'" % output_fname


USAGE = """SQL 'procedures analyzer' by Romain Gaucher <rgaucher@cigital.com>

Note: This tool looks for bad code constructs in stored procedures for T-SQL.
Bad constructs are limited to DML/EXEC statements where an input parameter
is concatenated.

Example of what the tool is meant to find:
  EXEC <str> + @PROC_PARAMETER 
  SELECT @sql = 'select * from ' + @PROC_PARAMETER; EXEC @sql;

Usage:
 $ ./%s --sql input-file.sql --output findings.json""" % sys.argv[0]

def main(argc, argv):
	conf = {
		'sql' : None,
		'output' : None
	}

	for i in range(argc):
		s = argv[i]
		if s in ('--sql', '-s'):
			conf['sql'] = __normalize_path(argv[i+1])
		elif s in ('--output', '-o'):
			conf['output'] = argv[i+1]
	
	if conf['sql'] and os.path.isfile(conf['sql']):
		analyze_sql(conf)
	else:
		print USAGE

if __name__ == "__main__":
	main(len(sys.argv), sys.argv)


