package org.owasp.benchmark.helpers;

import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/* this class parse a NIST suite results file (manifest-2016-09-13-16-48-29-76yO0L.xml) to a csv expected by OWASP benchmark score */

public class NistExpectedResultsGenerator {
	static String srcFileName = "D:/_dev/csharp-SARD-testsuite-105-benchmark/manifest-2016-09-13-16-48-29-76yO0L.xml";
	static String tgtFileName = "D:/_dev/csharp-SARD-testsuite-105-benchmark/expectedresults-SARD-testsuite-105.csv";
	static BufferedWriter writer;

	public static void main(String[] args) throws ParserConfigurationException, SAXException, IOException {


		writer = Files.newBufferedWriter(Paths.get(tgtFileName), StandardCharsets.UTF_8, StandardOpenOption.CREATE);
		writeToOutputFile("# test name", "category", "real vulnerability", "cwe, Benchmark version: testsuite-105, 2016-09-13");
		
		DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
		InputSource is = new InputSource( new FileInputStream(srcFileName) );
		Document doc = docBuilder.parse(is);

		NodeList testcases = doc.getElementsByTagName("testcase");
		for ( int i = 0; i < testcases.getLength(); i++ ) {
			Node testcase = testcases.item( i );
		
			Node file = getChildNodeByName(testcase, "file");
			NamedNodeMap fileAttrs = file.getAttributes();
			String path = fileAttrs.getNamedItem("path").getNodeValue();
			
			String type = "CWE-000";
			String cwe = "000";
			Node flaw = getChildNodeByName(file, "flaw");
			if (null != flaw) {
				NamedNodeMap flawAttrs = flaw.getAttributes();
				String name = flawAttrs.getNamedItem("name").getNodeValue();
				type = name.substring(0,7);
				cwe = type.substring(4, 7);
			}
			
			writeToOutputFile(path, type, "true", cwe);
		}
		
		writer.close();
	}

	private static void writeToOutputFile(String path, String type, String real, String cwe) throws IOException {
	    writer.write(String.format("%s,%s,%s,%s%n", path, type, real, cwe));
	}

	private static Node getChildNodeByName(Node parent, String childName) {
		NodeList nl = parent.getChildNodes();
		for ( int i = 0; i < nl.getLength(); i++ ) {
			Node n = nl.item( i );
			if (n.getNodeName().equals(childName)) {
				return n;
			}
		}
		
		return null;
	}
}
