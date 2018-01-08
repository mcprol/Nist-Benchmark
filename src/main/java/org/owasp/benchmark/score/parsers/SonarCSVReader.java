/**
* CSV file was obteined exporting the sonar ddbb with:
*   SELECT i.rule_id, i.severity, r.name, r.plugin_name, i.tags, p.path, i.line
*   FROM sonar.issues i, sonar.rules r, sonar.projects p
*   where i.project_uuid='AWBf4SdeOLTip58mq-2G'
*   and i.rule_id=r.id
*   and i.component_uuid = p.uuid;
*/

package org.owasp.benchmark.score.parsers;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.Properties;

import org.owasp.benchmark.helpers.NistHelper;
import org.owasp.benchmark.score.BenchmarkScore;
import com.opencsv.CSVReader;

public class SonarCSVReader extends Reader {
	
	private static final String TOOLNAME = "sonar";

	private Properties cweMappings = null;

	public TestResults parse( File f ) throws Exception {
		trace("SonarReader. Parsing file: " + f.getAbsolutePath());
				
		TestResults tr = new TestResults(TOOLNAME, true, TestResults.ToolType.SAST);
		tr.setToolVersion("6.7.4267");
		
		CSVReader reader = new CSVReader(new InputStreamReader(new FileInputStream(f), Charset.forName("UTF-8")), ',');
		
		String[] nextLine;
		
		// first line are the headers. Skip them.
		nextLine = reader.readNext();
		
		while ((nextLine = reader.readNext()) != null) {
			TestCaseResult tcr = parseSonarIssue( nextLine );
			if (null != tcr) {
				tr.put( tcr );
        	}
		}	
		
		return tr;
	}


	private TestCaseResult parseSonarIssue(String[] issue) {
		String cwe = issue[0];
		String rule = issue[2];
		String path = issue[5];
		
		TestCaseResult tcr = null;
		try {
			path = path.replaceAll("testcases/", "");

			tcr = new TestCaseResult();
	        tcr.setCWE(cweLookup(Integer.parseInt(cwe)));

	        tcr.setTestCaseName(NistHelper.getTestNameFromFilename(path));
			tcr.setNumber(NistHelper.getTestNumberFromFilename(path));

	        
	        tcr.setCategory(rule);
	        tcr.setEvidence(rule);			
	        
	        tcr.setReal(true);
	        
		} catch (Exception e) {
			e.printStackTrace();
		}

		return tcr;
	}
	
	
	private Integer cweLookup(int cwe) {
		loadMappingFile();
		
		String mappedCWE = cweMappings.getProperty(Integer.toString(cwe));
		
		if (null != mappedCWE) {
			cwe = Integer.parseInt(mappedCWE);
		}

		return cwe;
	}
	
	
	private void loadMappingFile() {
		if (null == cweMappings) {
			cweMappings = new Properties();
			
			String fileName = BenchmarkScore.suiteDirName + "/mappings/" + TOOLNAME + "2bench.properties";
	        try {
				File file = new File(fileName);
				
				if (file.exists()) {
					cweMappings.load(new FileInputStream(file)); 
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	private void trace(String msg) {
		//System.out.println(msg);
	}

}
