Script Arguments
================

Required
------------

- **-target &lt;relpath&gt;** — defines the relative path to the folder you want to scan for vulnerable dependencies.

Optional
------------

- **-app "&lt;title&gt;"** — overrides the default project title ("PacMon")
- **-java &lt;path&gt;** — defines the full path to the Java executable — it is highly recommended that you use TeamCity's pre-defined environment variable: *%env.JAVA_EXE%*
- **-opts "&lt;options&gt;"** — passes optional parameters to Java
- **-dc &lt;relpath&gt;** — overrides the default relative path to the Dependency Check folder (.\dc)
- **-etc "&lt;options&gt;"** — passes optional parameters to Dependency Check
  - **-etc "-n"** — Disables the automatic updating of the CPE data
  - **-etc "-s &lt;path&gt;"** — Additional path to scan (this option can be specified multiple times)
- **-s &lt;filename.xml&gt;** — overrides the default suppression XML file (suppress.xml)
- **-h &lt;filename.html&gt;** — overrides the default vulnerability artifact report filename (vulnerability.html)
- **-x &lt;filename.xml&gt;** — overrides the default temporary XML file (output.xml)
