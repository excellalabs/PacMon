Script Arguments
================

Required
------------

-target <relpath> — defines the relative path to the folder you want to scan for vulnerable dependencies.

Optional
------------

-app "<title>" — overrides the default project title ("PacMon")

-java <path> — defines the full path to the Java executable — it is highly recommended that you use TeamCity's pre-defined environment variable: %env.JAVA_EXE%

-opts "<options>" — passes optional parameters to Java

-dc <relpath> — overrides the default relative path to the Dependency Check folder (.\dc)

-etc "<options>" — passes optional parameters to Dependency Check

-etc "-n" — Disables the automatic updating of the CPE data

-etc "-s <path>" — Additional path to scan (this option can be specified multiple times)

-s <filename.xml> — overrides the default suppression XML file (suppress.xml)

-h <filename.html> — overrides the default vulnerability artifact report filename (vulnerability.html)

-x <filename.xml> — overrides the default temporary XML file (output.xml)