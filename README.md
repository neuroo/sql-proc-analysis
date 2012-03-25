# SQL Procedure Static Analysis

Developed by Romain Gaucher, [@rgaucher](https://twitter.com/rgaucher)

## Description

This script analyses statically stored procedures, and report a defect when a
potentially unsafe concatenation is detected.

The type of analysis is totally unsound, and no inter-procedural analysis is performed.
Also, the intra-procedural analysis is a shame. However, this script was handy more
than once, to quickly pinpoint interesting locations in SQL stored procedures.

Example of what the tool is meant to find:

	EXEC <str> + @PROC_PARAMETER 
	SELECT @sql = 'select * from ' + @PROC_PARAMETER; EXEC @sql;

where @PROC_PARAMETER is an argument of the stored procedure.


## Usage
	$ proc_analyzer.py --sql input-file.sql --output findings.json