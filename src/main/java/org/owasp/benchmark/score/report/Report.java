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

package org.owasp.benchmark.score.report;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.DecimalFormat;
import java.util.HashMap;
import java.util.Map;

import org.owasp.benchmark.score.BenchmarkScore;
import org.owasp.benchmark.score.parsers.Counter;
import org.owasp.benchmark.score.parsers.OverallResult;
import org.owasp.benchmark.score.parsers.OverallResults;
import org.owasp.benchmark.score.parsers.TestResults;
import org.owasp.benchmark.score.parsers.TestResults.ToolType;
import org.jfree.data.category.DefaultCategoryDataset;

public class Report implements Comparable<Report> {

	private final boolean isCommercial;
	private ToolType toolType;
	private String toolName = "not specified";
	private final String toolNameAndVersion;
	private String toolVersion = "";
	private final String benchmarkVersion;
	private final Map<String, Counter> scores;
	private final OverallResults overallResults;
	private final String reportPath;
	private String totalProc = "";

	// The name of the file that contains this scorecard report
	private String filename = null;

	public Report(TestResults actualResults, Map<String, Counter> scores, OverallResults or, int totalResults,
			String actualResultsFileName, boolean isCommercial, ToolType toolType, DefaultCategoryDataset bardataset ) throws IOException, URISyntaxException {
		//bardataset.addValue(22, "Buu", "CWE-111");
		//bardataset.addValue(27, "Beu", "CWE-111");
		this.isCommercial = isCommercial;
		this.toolType = toolType;
		this.toolName = actualResults.getTool();
		this.toolVersion = actualResults.getToolVersion();
		this.toolNameAndVersion = actualResults.getToolNameAndVersion();
		this.toolType = actualResults.toolType;
		this.benchmarkVersion = actualResults.getBenchmarkVersion();

		String fullTitle = "NIST Benchmark Scorecard for: " + actualResults.getToolNameAndVersion();// + getToolName() + version;
		// If not in anonymous mode OR the tool is not commercial, add the type at the end of the name
		// It's not added to anonymous commercial tools, because it would be redundant.
		if (!BenchmarkScore.anonymousMode || !isCommercial) {
			fullTitle += " (" + actualResults.toolType+ ")";			
		}

		String shortTitle = "Benchmark v" + actualResults.getBenchmarkVersion() + " Scorecard for " + getToolName();
		this.filename = "Benchmark v" + actualResults.getBenchmarkVersion() + " Scorecard for " 
				+ actualResults.getToolNameAndVersion();
		this.filename = filename.replace(' ', '_');

		this.scores = scores;
		this.overallResults = or;

		this.reportPath = BenchmarkScore.scoreCardDirName + File.separator + filename + ".html";
		//File img_old = new File(BenchmarkScore.scoreCardDirName + File.separator + filename + "_old.png");
		File img = new File(BenchmarkScore.scoreCardDirName + File.separator + filename + ".png");
		ScatterTools graph = new ScatterTools(shortTitle, 800, or, bardataset, actualResults.getToolNameAndVersion());

		if (!(BenchmarkScore.showAveOnlyMode && this.isCommercial)) {
			graph.writeChartToFile(img, 800);
			//graph.writeBarChartToFile(img, 1000,800);
			String reportHtml = generateHtml(fullTitle, actualResults, scores, or, totalResults, img, actualResultsFileName);
			Files.write(Paths.get(reportPath), reportHtml.getBytes());
			System.out.println("Report written to: " + new File(reportPath).getAbsolutePath());
		}
	}

	/**
	 * Gets the name of the tool that produced the results for this scorecard.
	 * 
	 * @return Name of the tool.
	 */
	public String getToolName() {
		return this.toolName;
	}

	public String getToolVersion() {
		return this.toolVersion;
	}

	public String getToolNameAndVersion() {
		return this.toolNameAndVersion;
	}

	public boolean isCommercial() {
		return this.isCommercial;
	}

	public ToolType getToolType() {
		return toolType;
	}

	public String getBenchmarkVersion() {
		return this.benchmarkVersion;
	}

	public String getTotalProc() {
		return this.totalProc;
	}
	/**
	 * Gets the name of the file that contains this scorecard.
	 * 
	 * @return Name of the file (without any path information)
	 */
	public String getFilename() {
		return this.filename;
	}

	/**
	 * Gets the overall results used to calculate this scorecard.
	 * 
	 * @return the overall results for this scorecard.
	 */
	public OverallResults getOverallResults() {
		return this.overallResults;
	}

	private String generateHtml(String title, TestResults actualResults, Map<String, Counter> scores, OverallResults or,
			int totalResults, File img, String actualResultsFileName) throws IOException, URISyntaxException {
		String template = new String(
				Files.readAllBytes(Paths.get(BenchmarkScore.pathToScorecardResources + "template.html")));

		// String template = new String(Files.readAllBytes(
		// Paths.get(this.getClass().getClassLoader()
		// .getResource("template.html")
		// .toURI())));

		String html = template;
		html = html.replace("${title}", title);
		html = html.replace("${tests}", Integer.toString(totalResults));
		html = html.replace("${time}", or.getTime());
		html = html.replace("${score}", "" + new DecimalFormat("#0.00%").format(or.getScore()));
		html = html.replace("${tool}", actualResults.getTool());
		html = html.replace("${toolversion}", actualResults.getToolVersion());
		html = html.replace("${version}", actualResults.getBenchmarkVersion());
		html = html.replace("${actualResultsFile}", actualResultsFileName);
		String jsvarname = "Benchmark_v" + actualResults.getBenchmarkVersion() + "_Scorecard_for_" + actualResults.getTool() + "_v" + actualResults.getToolVersion();
		jsvarname = jsvarname.replace("-", "_").replace(".", "_");
		html = html.replace("${jsvarname}", jsvarname);

		String imgTag = "<img align=\"middle\" src=\"" + img.getName() + "\" />";
		html = html.replace("${image}", imgTag);

		String table = generateTable(actualResults, scores, or);
		html = html.replace("${totalproc}", this.totalProc);
		html = html.replace("${table}", table);

		return html;
	}

	/**
	 * The method generates a Detailed results table for whatever tool results are passed in.
	 */
	private String generateTable(TestResults actualResults, Map<String, Counter> scores, OverallResults or) {
		// Read table of CWE nr vs. name
		//HashMap <String, String> HmCWElist = getCWElist(new File(BenchmarkScore.pathToScorecardResources + File.separator + "CWE-nr-name.csv"));
		
		StringBuilder sb = new StringBuilder();
		sb.append("<table class=\"table\">\n");
		sb.append("<tr>");
		sb.append("<th>CWE</th>");
		sb.append("<th>CWE Name</th>");
		sb.append("<th>TP</th>");
		sb.append("<th>FN</th>");
		sb.append("<th>Total (P)</th>");
		sb.append("<th>Total (P+N)</th>");
		sb.append("<th>Score</th>");
		sb.append("</tr>\n");
		Counter totals = new Counter();
		double totalTPR = 0;
		int nrbadtests = 0;

		for (String category : scores.keySet()) {

			Counter c = scores.get(category);
			OverallResult r = or.getResults(category);

			if (!(c.tp == 0 && c.fn == 0)) {
				String style = "";
				nrbadtests ++;

				// 20171031 RME Mark CWE's that are not supported by Kiuwan
				String CWEnr = Integer.toString(BenchmarkScore.translateNameToCWE(category));
				if (ScatterTools.IgnCWEs.contains(CWEnr)) {
					style = "class=\"warning\"";
				} else if (Math.abs(r.truePositiveRate) < .1) {
					style = "class=\"danger\"";
				} else if (r.truePositiveRate > .7) {
					style = "class=\"success\"";
				}
				sb.append("<tr " + style + ">");
				if (ScatterTools.IgnCWEs.contains(CWEnr)) {
					sb.append("<td><A HREF=https://cwe.mitre.org/data/definitions/" + CWEnr + ".html>CWE:" + CWEnr + " (*)</A></td>");
				} else {
					sb.append("<td><A HREF=https://cwe.mitre.org/data/definitions/" + CWEnr + ".html>CWE:" + CWEnr + "</A></td>");
				}
				sb.append("<td><A HREF=https://cwe.mitre.org/data/definitions/" + CWEnr + ".html>" + BenchmarkScore.getCWEName(CWEnr) + "</A></td>");
				sb.append("<td>" + c.tp + "</td>");
				sb.append("<td>" + c.fn + "</td>");
				int totalbad = c.tp + c.fn;
				int totalall = totalbad + c.fp + c.tn;
				sb.append("<td>" + totalbad + "</td>");
				sb.append("<td>" + totalall + "</td>");
				sb.append("<td>" + new DecimalFormat("#0.00%").format(r.truePositiveRate) + "</td>");
				sb.append("</tr>\n");
				totals.tp += c.tp;
				totals.fn += c.fn;
				if (!Double.isNaN(r.truePositiveRate))
					totalTPR += r.truePositiveRate;
			}
		}
		sb.append("<th>Totals</th><th></th>");
		sb.append("<th>" + totals.tp + "</th>");
		sb.append("<th>" + totals.fn + "</th>");
		int total = totals.tp + totals.fn;
		this.totalProc = Integer.toString(total);
		sb.append("<th>" + total + "</th>");
		sb.append("<th>" + or.getTotal() + "</th>");
		double tpr = (totalTPR / nrbadtests);
		sb.append("<th>" + new DecimalFormat("#0.00%").format(tpr) + "</th>");
		sb.append("</tr>\n");
		sb.append("</table>");
		return sb.toString();
	}

	public int compareTo(Report r) {
		return this.getToolNameAndVersion().toLowerCase().compareTo(r.getToolNameAndVersion().toLowerCase());
	}

	public Map<String, Counter> getScores() {
		return 	this.scores;
	}

	/*
	private HashMap <String, String> getCWElist(File cwefile) {
		HashMap <String, String> HmCWElist = new HashMap <String, String>();
		if (!cwefile.exists()) {
			System.out.println("Can't find CWE names file to get lines from File: " + cwefile.getName());
			return null;
		}

		FileReader fr = null;
		BufferedReader br = null;
		try {
			fr = new FileReader(cwefile);
			br = new BufferedReader(fr);
			String line = "";
			while ((line = br.readLine()) != null) {
				String[] cwedata = line.split(";");
				HmCWElist.put(cwedata[0], cwedata[1]);
			}
		} catch (Exception e) {
			System.out.println("Error reading CWE names file: " + cwefile.getName());
		}		

		return HmCWElist;
	} */
	
	/*private String CWElink (String CWEnr) {
		return "<A HREF=https://cwe.mitre.org/data/definitions/" + CWEnr + ".html>CWE:" + CWEnr + "</A>";
	}*/
}
