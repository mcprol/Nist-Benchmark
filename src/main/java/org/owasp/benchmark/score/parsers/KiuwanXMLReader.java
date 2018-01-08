/**
* OWASP Benchmark Project
*
* This file is part of the Open Web Application Security Project (OWASP)
* Benchmark Project For details, please see
* <a href="https://www.owasp.org/index.php/Benchmark">https://www.owasp.org/index.php/Benchmark</a>.
*
* The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
* of the GNU General Public License as published by the Free Software Foundation, version 2.
*
* The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
* even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details
*
* @author Dave Wichers <a href="https://www.aspectsecurity.com">Aspect Security</a>
* @created 2015
*/

package org.owasp.benchmark.score.parsers;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.List;
import java.util.Properties;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.owasp.benchmark.helpers.NistHelper;
import org.owasp.benchmark.score.BenchmarkScore;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class KiuwanXMLReader extends Reader {
	
	private static final String TOOLNAME = "kiuwan";

	private Properties cweMappings = null;

	public TestResults parse( File f ) throws Exception {
		trace("KiuwanReader. Parsing file: " + f.getAbsolutePath());
		
		DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
		// Prevent XXE
		docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
		DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
		InputSource is = new InputSource( new FileInputStream(f) );
		Document doc = docBuilder.parse(is);

		Node root = doc.getDocumentElement();
		NamedNodeMap rootAttrs = root.getAttributes();
		String version = rootAttrs.getNamedItem("version").getNodeValue();
		
		TestResults tr = new TestResults(TOOLNAME, true, TestResults.ToolType.SAST);
		tr.setToolVersion(version);
		
		// If the filename includes an elapsed time in seconds (e.g., TOOLNAME-seconds.xml), set the compute time on the scorecard.
		tr.setTime(f);


		Node issues = getChildNodeByName(root, "Issues");
		
		NodeList nl = issues.getChildNodes();
		for ( int i = 0; i < nl.getLength(); i++ ) {
			Node n = nl.item( i );
			if (n.getNodeName().equals("Issue")) {
			    TestCaseResult tcr = parseKiuwanIssue( n );
                if ( tcr != null ) {
                    tr.put( tcr );
                }
			}
		}
		
		//dump(tr);
		
		return tr;
	}
	
	private void dump(TestResults tr) {
		try {
            FileOutputStream outputStream = new FileOutputStream("c:/owasp/kiuwan-test-results.csv");
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(outputStream, "UTF-8");
            BufferedWriter writer = new BufferedWriter(outputStreamWriter);
			
			for (Integer testNumber: tr.keySet()) {
				List<TestCaseResult> results = tr.get(testNumber);
				for (TestCaseResult tcr: results) {
					writer.write(tcr.toString());
					writer.newLine();
				}			
			}
			writer.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private TestCaseResult parseKiuwanIssue(Node issue) {
		NamedNodeMap issueAttrs = issue.getAttributes();
		String id = issueAttrs.getNamedItem("id").getNodeValue();
		//trace("Parsing issue: " + id);

		String rule = issueAttrs.getNamedItem("check").getNodeValue();
		
        Node location = getChildNodeByName(issue, "Location");
        if (null != location) {
    		NamedNodeMap locationAttrs = location.getAttributes();
            String path = locationAttrs.getNamedItem("path").getNodeValue();
    		if (path != null) {
				Integer cwe = figureCWE(issue);
				if (null != cwe) {
					TestCaseResult tcr = new TestCaseResult();
	    	        
					tcr.setTestCaseName(NistHelper.getTestNameFromFilename(path));
					tcr.setNumber(NistHelper.getTestNumberFromFilename(path));

	    	        tcr.setCWE(cwe);
	                
	    	        tcr.setCategory(rule);
	    	        tcr.setEvidence(rule);
	    	        
	    	        tcr.setReal(true);
	    	        
	    	        trace(tcr.toString());
	    	        
	    	        return tcr;
				}
    		}
        	
        }
					
		return null;
	}
	
	private Node getChildNodeByName(Node parent, String childName) {
		NodeList nl = parent.getChildNodes();
		for ( int i = 0; i < nl.getLength(); i++ ) {
			Node n = nl.item( i );
			if (n.getNodeName().equals(childName)) {
				return n;
			}
		}
		
		return null;
	}

	
	private Integer figureCWE(Node issue) {
		Node cweNode = getChildNodeByName(issue, "CWE");
		if (null != cweNode) {
			String cwe = cweNode.getTextContent();
			return cweLookup(Integer.parseInt(cwe));
		}
		
		return null;
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
