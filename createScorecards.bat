:: createScorecards.bat
:: uncomment a selected suite vars

::set SUITE=SARD-testsuite-103-PHP
::set EXPECTED=manifest-2016-09-12-09-54-03-ibdn6w.xml

::set SUITE=SARD-testsuite-87
::set EXPECTED=manifest-2016-09-12-09-43-15-OpcWjf.xml

set SUITE=SARD-testsuite-105-csharp
set EXPECTED=manifest-2016-09-13-16-48-29-76yO0L.xml

call mvn validate -Pbenchmarkscore -Dexec.args="%SUITE% suites/%SUITE% suites/%SUITE%/expected/%EXPECTED%"
