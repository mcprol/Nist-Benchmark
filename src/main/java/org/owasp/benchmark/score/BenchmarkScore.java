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

package org.owasp.benchmark.score;

import java.awt.Color;
import java.awt.Font;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.io.FileUtils;
import org.owasp.benchmark.helpers.NistHelper;
import org.owasp.benchmark.score.parsers.Counter;
import org.owasp.benchmark.score.parsers.KiuwanXMLReader;
import org.owasp.benchmark.score.parsers.OverallResult;
import org.owasp.benchmark.score.parsers.OverallResults;
import org.owasp.benchmark.score.parsers.SonarCSVReader;
import org.owasp.benchmark.score.parsers.TestCaseResult;
import org.owasp.benchmark.score.parsers.TestResults;
import org.owasp.benchmark.score.report.HighChartsGenerator;
import org.owasp.benchmark.score.report.Report;
import org.owasp.benchmark.score.report.ScatterHome;
import org.owasp.benchmark.score.report.ScatterTools;
import org.owasp.benchmark.score.report.ScatterVulns;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartUtilities;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.StandardChartTheme;
import org.jfree.chart.axis.CategoryAxis;
import org.jfree.chart.axis.ValueAxis;
import org.jfree.chart.plot.CategoryPlot;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.category.DefaultCategoryDataset;
import org.json.JSONArray;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class BenchmarkScore {

	private static final String GUIDEFILENAME = "NIST_Benchmark_Guide.html";
	private static final String HOMEFILENAME = "NIST_Benchmark_Home.html";    
    public static final String pathToScorecardResources = "src/main/resources/scorecard/";

    public static String suiteDirName = "suite";
    public static String expectedResultFile = "expected";
    public static String resultsDirName = "result";
    public static String scoreCardDirName = "scorecard";

    public static String benchmarkVersion = null;
    
    // This is used to indicate that results from multiple versions of the Benchmark are included in these results.
	// Each set in their own directory with their associated expectedresults file.
    public static boolean mixedMode = false;
    // Indicates that the names of Commercial tools should be anonymized
    public static boolean anonymousMode = false;
    // Indicates that the results of Commercial tools should be suppressed. Only show their averages.
    public static boolean showAveOnlyMode = false;
    // The name of this file if generated
    private static String commercialAveScorecardFilename = null;
    // The name of the tool to 'focus' on, if any
    private static String focus = "none";
    private static DefaultCategoryDataset bardataset = new DefaultCategoryDataset();
    
    private static JFreeChart barchart = null;
    static StandardChartTheme bartheme = initializeBarTheme();
	/*
	 * A list of the reports produced for each tool.
	 */
	private static Set<Report> toolResults = new TreeSet<Report>();
	
	private static final String usageNotice = "Usage: BenchmarkScore suite_root_dir suite_expected_results\n"
		+ "  suite - suite name.\n"
		+ "  suite_root_dir - root directory for suite.\n"
		+ "  suite_expected_results - expected result file\n"
		+ "\nNotes:\n"
		+ "  suite_root_dir/results directory with result files from tools (.ozasmt, .fpr, .fvdl, .xml, etc...)\n"
		+ "  suite_root_dir/scorecard - target scorecard directory.\n";

	private static final HashMap <String, String> HmCWElist = getCWElist(new File(pathToScorecardResources + File.separator + "CWE-nr-name.csv"));
	
	public static void main(String[] args) {
		if (args.length != 3) {
			System.out.println( usageNotice );
			System.exit( -1 );				
		}
		
		benchmarkVersion = args[0];
		suiteDirName = args[1];
		expectedResultFile = args[2];
		resultsDirName = args[1] + "/results";
		scoreCardDirName = args[1] + "/scorecard";

		// Prepare the scorecard results directory for the newly generated scorecards
		// Step 1: Create the dir if it doesn't exist, or delete everything in it if it does
        File scoreCardDir = new File(scoreCardDirName);
        try {
            if (!scoreCardDir.exists()) {
                Files.createDirectories(Paths.get(scoreCardDirName));
            } else {
                System.out.println("Deleting previously generated scorecard files in: " + scoreCardDir.getAbsolutePath());
                FileUtils.cleanDirectory(scoreCardDir);
            }
            
            // Step 2: Now copy the entire /content directory, that either didn't exist, or was just deleted with everything else
            File dest1 = new File(scoreCardDirName + File.separator + "content");
            FileUtils.copyDirectory(new File(pathToScorecardResources + "content"), dest1);
            
        } catch (IOException e) {
            System.out.println("Error dealing with scorecard directory: '" + scoreCardDir.getAbsolutePath() + "' for some reason!");
            e.printStackTrace();
        }

	    // Step 3: Copy over the Homepage and Guide templates
        try {
            Files.copy(Paths.get(pathToScorecardResources + HOMEFILENAME),
                    Paths.get( scoreCardDirName + "/" + HOMEFILENAME),
                    StandardCopyOption.REPLACE_EXISTING );
        } catch( IOException e ) {
            System.out.println( "Problem copying home and guide files" );
            e.printStackTrace();
        }
        
        
		// #### Generate Bar plot for all CWE's in one
        barchart = ChartFactory.createBarChart("NISP Benchmark v" + BenchmarkScore.benchmarkVersion 
        		+ " Results Comparison", "Vulnerabilities", "Score (%)", bardataset, PlotOrientation.HORIZONTAL, true, true, false);
        bartheme.apply(barchart);
        CategoryPlot catplot = barchart.getCategoryPlot();
        initializeBarPlot( catplot );
        		
        // Step 4: Read the expected results so we know what each tool 'should do'
		try {				
	        // Step 4b: Read the expected results so we know what each tool 'should do'
			File expected = new File( expectedResultFile );
			TestResults expectedResults = readExpectedResults( expected );
			if (expectedResults == null) {
				System.out.println( "Couldn't read expected results file: " + expected);
				System.exit(-1);
			} else {
				System.out.println( "Read expected results from file: " + expected.getAbsolutePath());
				int totalResults = expectedResults.totalResults();
				if (totalResults != 0) {
					System.out.println( totalResults + " results found.");
		            //benchmarkVersion = expectedResults.getBenchmarkVersion();
				} else {
					System.out.println( "Error! - zero expected results found in results file.");
					System.exit(-1);
				}
			}
		
	        // Step 5b: Go through each result file and generate a scorecard for that tool.
			File f = new File( resultsDirName );
			if (!f.exists()) {
				System.out.println( "Error! - results file: '" + f.getAbsolutePath() + "' doesn't exist.");
				System.exit(-1);
			}

			// To handle anonymous mode, we are going to randomly grab files out of this directory
			// and process them. By doing it this way, multiple runs should randomly order the commercial
			// tools each time.
			List<File> files = new ArrayList();
			for ( File file : f.listFiles() ) {
				files.add(file);
			}
			
			SecureRandom generator = SecureRandom.getInstance("SHA1PRNG");
			while (files.size() > 0) {
				int randomNum = generator.nextInt();
				// FIXME: Get Absolute Value better
				if (randomNum < 0) randomNum *= -1;
				int fileToGet = randomNum % files.size();
				File actual = files.remove(fileToGet);
				// Don't confuse the expected results file as an actual results file if its in the same directory
				if (!actual.isDirectory() && !expected.getName().equals(actual.getName()))
					process( actual, expectedResults, toolResults);
			}

			System.out.println( "Tool scorecards computed." );
			
			
		} catch( Exception e ) {
			System.out.println( "Error during processing: " + e.getMessage() );
			e.printStackTrace();
		}


        // Step 6: Now generate scorecards for each type of vulnerability across all the tools

		// First, we have to figure out the list of vulnerabilities
        // A set is used here to eliminate duplicate categories across all the results
        Set<String> catSet = new TreeSet<String>();
        for ( Report toolReport : toolResults ) {
            catSet.addAll( toolReport.getOverallResults().getCategories() );
        }
		
		// Then we generate each vulnerability scorecard
        BenchmarkScore.generateVulnerabilityScorecards(toolResults, catSet );
		System.out.println( "Vulnerability scorecards computed." );
        		
        // Step 7: Update all the menus for all the generated pages to reflect the tools and vulnerability categories
		updateMenus(toolResults, catSet);
		
        // Step 8: Generate the overall comparison chart for all the tools in this test
		HighChartsGenerator.generateToolsChartData(scoreCardDirName, "NIST_Benchmark_Home", "NIST Benchmark '" + BenchmarkScore.benchmarkVersion + "' Tools Comparison", toolResults);
        //ScatterHome.generateComparisonChart(scoreCardDirName, toolResults, focus);

		HighChartsGenerator.generateCWEChartData(scoreCardDirName, "cwe_NIST_Benchmark_Home", "NIST Benchmark '" + BenchmarkScore.benchmarkVersion + "' CWE Comparison", toolResults);
        
		//js files per tool
		HighChartsGenerator.generateCWEperToolChartData(scoreCardDirName, BenchmarkScore.benchmarkVersion, toolResults);
		
        //### Generate all CWE barchart
        /*try {
        	writeBarChartToFile(new File(scoreCardDirName + "/cwe_comparison.png"), 1100, 2000);
        } catch (IOException e) {
    		System.out.println("Couldn't generate CWE comparison chart for some reason.");
    		e.printStackTrace();
    	}*/
        
        // Step 9: Generate the results table across all the tools in this test
		String table = generateOverallStatsTable(toolResults);
		
		File f = Paths.get( scoreCardDirName + "/" + HOMEFILENAME).toFile();
        try {
            String html = new String( Files.readAllBytes( f.toPath() ) );
    		html = html.replace("${table}", table);
            Files.write( f.toPath(), html.getBytes() );
        } catch ( IOException e ) {
            System.out.println ( "Error updating results table in: " + f.getName() );
            e.printStackTrace();
        }

		System.out.println( "Benchmark scorecards complete." );
       
		System.exit(0);
	}

	
	/**
	 * The method takes in a tool scan results file and determined how well that tool did against the benchmark.
	 * @param f - The results file to process. This is the native results file from the tool.
	 * @param expectedResults - This is the expected results csv file for this version of the Benchmark.
	 * @param toolResults - This list contains some information about the results for each tool. It is updated
	 * in this method so that the menus across all the scorecards can be generated and a summary scorecard can be
	 * computed. A new entry is added each time this method is called which adds the name of the tool, the filename of the
	 * scorecard, and the report that was created for that tool.
	 */
	private static void process(File f, TestResults expectedResults, Set<Report> toolreports) {
        try {
        	//bardataset.addValue(20.3, "Muuu", f.getName());
            //bardataset.addValue(20.2, "Baa", f.getName());
        	// Figure out the actual results for this tool from the raw results file for this tool            
            System.out.println( "\nAnalyzing results from " + f.getName() );
            TestResults actualResults = readActualResults( f );
            //System.out.println("Computed actual results for tool: " + actualResults.getTool());
        
            if ( expectedResults != null && actualResults != null ) {
                // note: side effect is that "pass/fail" value is set for each expected result so it
            	// can be used to produce scorecard for this tool
                analyze( expectedResults, actualResults );
            
                // Produce a .csv results file of the actual results, except if its a commercial tool,
                // and we are in showAveOnly mode.
                String actualResultsFileName = "notProduced";
                if (!(showAveOnlyMode && actualResults.isCommercial)) {
                	actualResultsFileName = produceResultsFile (expectedResults);
                }
                
                Map<String,Counter> scores = calculateScores( expectedResults );
            
                OverallResults results = calculateResults( scores );
                results.setTime( actualResults.getTime() );
                              
                // This has the side effect of also generating the report on disk.
                Report scoreCard = new Report( actualResults, scores, results, expectedResults.totalResults(), 
                		actualResultsFileName, actualResults.isCommercial(),actualResults.getToolType(), 
                		bardataset);
                
                // Add this report to the list of reports
                toolreports.add(scoreCard);
                
                // This is for debugging purposes. It indicates how may extra results were found in the
                // actual results vice the expected results.
                // printExtraCWE( expectedResults, actualResults );
            }
            else {
            	if ( expectedResults == null) {
                	System.out.println("Error!!: expected results were null.");
            	}
            	else System.out.println("Error!!: actual results were null for file: " + f);
            }
        }
        catch( Exception e ) {
            System.out.println( "Error processing " + f + ". Continuing." );
            e.printStackTrace();
        }
    }

	// Don't delete - for debug purposes
    private static void printExtraCWE(TestResults expectedResults, TestResults actualResults) {
        Set<Integer> expectedCWE = new HashSet<Integer>();
        for ( Integer i : expectedResults.keySet() ) {
            List<TestCaseResult> list = expectedResults.get( i );
            for ( TestCaseResult t : list ) {
                expectedCWE.add( t.getCWE() );
            }
        }
        
        Set<Integer> actualCWE = new HashSet<Integer>();
        for ( Integer i : actualResults.keySet() ) {
            List<TestCaseResult> list = actualResults.get( i );
            if ( list != null ) {
                for ( TestCaseResult t : list ) {
                    actualCWE.add( t.getCWE() );
                }
            }
        }
        
        Set<Integer> extras = difference( actualCWE, expectedCWE );
        for ( int cwe : extras ) {
            System.out.println( "Extra: "+cwe );
        }
    }

    public static <T> Set<T> difference(Set<T> setA, Set<T> setB) {
        Set<T> tmp = new HashSet<T>(setA);
        tmp.removeAll(setB);
        return tmp;
    }
    
    private static OverallResults calculateResults(Map<String, Counter> results) {
		OverallResults or = new OverallResults();
		double totalScore = 0;
		double totalFPRate = 0;
		double totalTPRate = 0;
		int total = 0;
		int countNonNaN = 0;
		int totalTP = 0;
		int totalFP = 0;
		int totalFN = 0;
		int totalTN = 0;
		for ( String category : results.keySet() ) {
			Counter c = results.get( category );			
			int rowTotal = c.tp + c.fn + c.tn + c.fp;
			double tpr = 0.0;
			double fpr = 0.0;
			// Compensate "no case": 0/0 calculated...
			//if (c.tp == 0 && c.fn == 0) {
			//	tpr = 1.0;
			//} else {
				tpr = (double) c.tp / (double) ( c.tp + c.fn );
			//}
			//if (c.fp == 0 &&c.tn == 0) {
			//	fpr = 0.0;
			//} else {
				fpr = (double) c.fp / (double) ( c.fp + c.tn );
			//}
//			double fdr = c.fp / ( c.tp + c.fp );

            // category score is distance from (fpr,tpr) to the guessing line
            //double side = tpr - fpr;
            //double hyp = side * Math.sqrt(2); // Pythagoras
            //double raw = hyp/2;
            //double score = raw * Math.sqrt(2); // adjust scores to 0-1
            
            double score = tpr;
            
            if ( !Double.isNaN(score)) {
                totalScore += score;
                countNonNaN ++;
            }
            totalFPRate += fpr;
            totalTPRate += tpr;
            total += rowTotal;
            totalTP += c.tp;
            totalFP += c.fp;
            totalFN += c.fn;
            totalTN += c.tn;
            
            or.add( category, tpr, fpr, rowTotal, score );
		}
		
		//int resultsSize = results.size();
		int resultsSize = countNonNaN;
		or.setScore( totalScore / resultsSize );
		or.setFalsePositiveRate( totalFPRate / resultsSize );
		or.setTruePositiveRate( totalTPRate / resultsSize );
		or.setTotal(total);
		or.setFindingCounts(totalTP, totalFP, totalFN, totalTN);
		
		return or;
	}

    /**
     * This method translates vulnerability categories, e.g., xss, to their long names for human consumption.
     * @param The category to translate.
     * @return The human readable value of that category.
     */
	public static String translateCategoryToName(String category) {
		switch( category ) {
		case "cmdi" : return "Command Injection";
		case "xss" : return "Cross-Site Scripting";
		case "ldapi" : return "LDAP Injection";
		case "headeri" : return "Header Injection";
		case "securecookie" : return "Insecure Cookie";
		case "pathtraver" : return "Path Traversal";
		case "crypto" : return "Weak Encryption Algorithm";
		case "hash" : return "Weak Hash Algorithm";
		case "weakrand" : return "Weak Random Number";
		case "sqli" : return "SQL Injection";
		case "trustbound" : return "Trust Boundary Violation";
		case "xpathi" : return "XPath Injection";
		default : return category;
		}
	}

    /**
     * This method translates vulnerability categories, e.g., xss, to their CWE number.
     * @param The category to translate.
     * @return The CWE # of that category.
     */
	public static int translateCategoryToCWE(String category) {
		switch( category ) {
		case "cmdi" : return 78;
		case "xss" : return 79;
		case "ldapi" : return 90;
		case "securecookie" : return 614;
		case "pathtraver" : return 22;
		case "crypto" : return 327;
		case "hash" : return 328;
		case "weakrand" : return 330;
		case "sqli" : return 89;
		case "trustbound" : return 501;
		case "xpathi" : return 643;
		
		default : 
			return category2cwe(category);
		}
	}

	private static int category2cwe(String category) {
		int cwe = 0;
		String scwe = category.substring(4);
		try {
			cwe = Integer.parseInt(scwe);
		} catch (Exception e) {
		}
		return cwe;
	}
	
    /**
     * This method translates vulnerability names, e.g., Cross-Site Scripting, to their CWE number.
     * @param The category to translate.
     * @return The CWE # of that category.
     */
	public static int translateNameToCWE(String category) {
		switch( category ) {
		case "Command Injection" : return 78;
		case "Cross-Site Scripting" : return 79;
		case "LDAP Injection" : return 90;
		case "Insecure Cookie" : return 614;
		case "Path Traversal" : return 22;
		case "Weak Encryption Algorithm" : return 327;
		case "Weak Hash Algorithm" : return 328;
		case "Weak Random Number" : return 330;
		case "SQL Injection" : return 89;
		case "Trust Boundary Violation" : return 501;
		case "XPath Injection" : return 643;
		default : 
			return category2cwe(category);
		}
	}
	
	/**
	 * Return map of category to array of results
	 * @param expectedResults
	 * @return
	 */
	private static Map<String,Counter> calculateScores(TestResults expectedResults) {
		Map<String,Counter> map = new TreeMap<String,Counter>();
		
		for ( Integer tn : expectedResults.keySet() ) {
			TestCaseResult tcr = expectedResults.get(tn).get(0); // only one
			String cat = translateCategoryToName( tcr.getCategory() );

			Counter c = map.get(cat);
			if ( c == null ) {
				c = new Counter();
				map.put(cat, c);
			}
			// real vulnerabilities
			if ( tcr.isReal() && tcr.isPassed() ) c.tp++; // tp
			else if ( tcr.isReal() && !tcr.isPassed() ) c.fn++; // fn
			
			// fake vulnerabilities
			else if (!tcr.isReal() && tcr.isPassed() ) c.tn++;  // tn
			else if (!tcr.isReal() && !tcr.isPassed() ) c.fp++; // fp
		}
		return map;
	}


	private static TestResults readActualResults(File fileToParse) throws Exception {
		String filename = fileToParse.getName();
		TestResults tr = null;
        
		if ( filename.endsWith( ".xml" ) ) {
            String line1 = getLine( fileToParse, 0 );
            String line2 = getLine( fileToParse, 1 );
            if ( line2.startsWith( "<Report")) {
                tr = new KiuwanXMLReader().parse( fileToParse );
            }
		} else if ( filename.endsWith( ".sonar_csv" ) ) {
            tr = new SonarCSVReader().parse( fileToParse );
		}
        
        // If the version # of the tool is specified in the results file name, extract it, and set it.
        // For example: Benchmark-1.1-Coverity-results-v1.3.2661-6720.json  (the version # is 1.3.2661 in this example). 
        // This code should also handle: Benchmark-1.1-Coverity-results-v1.3.2661.xml (where the compute time '-6720' isn't specified)
        int indexOfVersionMarker = filename.lastIndexOf("-v");
        if ( indexOfVersionMarker != -1) {
        	String restOfFileName = filename.substring(indexOfVersionMarker+2);
        	int endIndex = restOfFileName.lastIndexOf('-');
        	if (endIndex == -1) endIndex = restOfFileName.lastIndexOf('.');
        	String version = restOfFileName.substring(0, endIndex);
        	tr.setToolVersion(version);
        }
        
		return tr;
	}

	/**
	 * Read the 2nd line of the provided file. If its blank, skip all blank lines until a non-blank line
	 * is found and return that. Return "" if no none blank line is found from the second line on.
	 * @return The first non-blank line in the file starting with the 2nd line.
	 */
	private static String getLine(File actual, int line) {
		BufferedReader br = null;
		try {
    	    br = new BufferedReader( new FileReader( actual ) );
    	    for ( int i=0; i<line; i++ ) {
    	        br.readLine(); // Skip line 1
    	    }
    	    String line2 = "";
    	    while ( line2.equals( "" ) ) {
    	        line2 = br.readLine();
    	    }
    	    return line2;
	    } catch( Exception e ) {
	        return "";
	    } finally {
	    	try {
		    	if (br != null) br.close();	    		
	    	} catch (IOException e) {
	    		System.out.println("Can't close filereader for file: " + actual.getAbsolutePath() + 
	    			" for some reason.");
	    		e.toString();
	    	}
	    }
    }

	// Go through each expected result, and figure out if this tool actually passed or not.
	// This updates the expected results to reflect what passed/failed.
    private static void analyze( TestResults expected, TestResults actual ) {
    	
    	// Set the version of the Benchmark these actual results are being compared against
    	//actual.setBenchmarkVersion(expected.getBenchmarkVersion());
    	actual.setBenchmarkVersion(BenchmarkScore.benchmarkVersion);
    	
    		
    	// If in anonymous mode, anonymize the tool name if its a commercial tool before its used to compute anything.
	    // unless its the tool of 'focus'
		if (BenchmarkScore.anonymousMode && actual.isCommercial && !actual.getTool().replace(' ','_').equalsIgnoreCase(focus)) {
			actual.setAnonymous();
		}
		
		boolean pass = false;
		for ( Integer tc : expected.keySet() ) {
			TestCaseResult exp = expected.get( tc ).get(0); // always only one!
			List<TestCaseResult> act = actual.get( tc );  // could be lots of results for this test
				
			pass = compare( exp, act, actual.getTool() );

			// helpful in debugging
			//System.out.println( tc + ", " + exp.getCategory() + ", " + exp.isReal() + ", " + exp.getCWE() + ", " + pass + "\n");
			
			// fill the result into the "expected" results in case we need it later
			exp.setPassed( pass );
		}
		
		// Record the name and version of the tool whose pass/fail values were recorded in 'expected' results
		expected.setTool(actual.getTool());
		expected.setToolVersion(actual.getToolVersion());
	}
	
	/**
	 * Check all actual results. If a real vulnerability matches, then exit. Otherwise keep going.
	 * @param exp The expected results
	 * @param actList The list of actual results for this test case.
	 * @return true if the expected result is found in the actual result (i.e., If True Positive, 
	 * that results was found, If False Positive, that result was not found.)
	 */
	private static boolean compare( TestCaseResult exp, List<TestCaseResult> actList, String tool ) {
		// return true if there are no actual results and this was a fake test
		if ( actList == null || actList.isEmpty() ) {
			return !exp.isReal();
		}
		
		// otherwise check actual results
		for ( TestCaseResult act : actList ) {
			// Helpful in debugging
		    //System.out.println( "  Evidence: " + act.getCWE() + " " + act.getEvidence() + "[" + act.getConfidence() + "]");
			int expCWE = cweLookupExpected(exp.getCWE());
		    boolean match = act.getCWE() == expCWE;
			
			// special hack since IBM/Veracode don't distinguish different kinds of weak algorithm
			if ( tool.startsWith("AppScan") || tool.startsWith("Vera")) {
			    if ( exp.getCWE() == 328 && act.getCWE() == 327 ) {
			        match = true;
			    }
			}
					
			// return true if we find an exact match for a real test
			if ( match ) {
				return exp.isReal();
			}
		}
		// if we couldn't find a match, then return true if it's a fake test
		return !exp.isReal();
	}

	// Create a TestResults object that contains the expected results for this version
	// of the Benchmark.
private static final String BENCHMARK_VERSION_PREFIX = "Benchmark version: ";
	private static TestResults readExpectedResults(File f1) throws Exception {
		TestResults tr = new TestResults( "Expected", true, null);
		String benchmarkVersion = null;
		try {
			DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
			InputSource is = new InputSource( new FileInputStream(f1) );
			Document doc = docBuilder.parse(is);

			NodeList testcases = doc.getElementsByTagName("testcase");
			for ( int i = 0; i < testcases.getLength(); i++ ) {
				Node testcase = testcases.item( i );
				NamedNodeMap testcaseAttrs = testcase.getAttributes();
				String testsuiteid = testcaseAttrs.getNamedItem("testsuiteid").getNodeValue();
				
				if (null == benchmarkVersion && null != testsuiteid) {
					benchmarkVersion = testsuiteid;
				}
				
				// checks if this test is disabled.
				Node disabled = testcaseAttrs.getNamedItem("disabled");
				if (null != disabled) {
					String idDisabled = disabled.getNodeValue();
					if (null != idDisabled && idDisabled.equalsIgnoreCase("true")) {
						// skip this test.
						continue;
					}
				}
			
				List<Node> files = getChildNodesByName(testcase, "file");
				for (Node file: files) {
					NamedNodeMap fileAttrs = file.getAttributes();
					String path = fileAttrs.getNamedItem("path").getNodeValue();
					
					String cwe = "000";
					Node flaw = getChildNodeByName(file, "flaw"); // SARD-testsuite-103-PHP
					Node mixed = getChildNodeByName(file, "mixed"); // SARD-testsuite-87-java
					boolean isReal = true;
					if (null != flaw) {
						NamedNodeMap flawAttrs = flaw.getAttributes();
						String name = flawAttrs.getNamedItem("name").getNodeValue();
						cwe = name.substring(4, 7);
					} else if (null != mixed) {
						cwe = NistHelper.getTestCWEFromFilename(path);
					} else {
						isReal = false;
						cwe = NistHelper.getTestCWEFromFilename(path);
					}
					
					Integer cweNumber = getCWE(cwe);
					if (null != cweNumber) {
						//cweNumber = cweLookupExpected(cweNumber);
						String type = "CWE-" + cweNumber;
						
						TestCaseResult tcr = new TestCaseResult();
						tcr.setTestCaseName(NistHelper.getTestNameFromFilename(path));
						tcr.setCategory(type);
						tcr.setReal(isReal);
						tcr.setCWE(cweNumber);

						tcr.setNumber(NistHelper.getTestNumberFromFilename(path));
						//System.out.println("#### " + type + " Number= " + tcr.getNumber());
						// Handle situation where expected results has full details
						// Sometimes, it also has: source, data flow, data flow filename, sink
						/*
						if (parts.length > 4) {
							tcr.setSource(parts[4]);
							tcr.setDataFlow(parts[5]);
							tcr.setDataFlowFile(parts[6]);
							tcr.setSink(parts[7]);
						}
						*/
						
						tr.put( tcr );
					}
				}
			}
		} finally {
		}

		if (null != benchmarkVersion) {
			tr.setBenchmarkVersion(benchmarkVersion);
		}
		return tr;
	}
	
	private static Integer getCWE(String sCwe) {
		Integer cwe = null;
		try {
			cwe = Integer.parseInt(sCwe);
		} catch (Exception e) {
			cwe = null;
		}

		return cwe;
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
	
	private static List<Node> getChildNodesByName(Node parent, String childName) {
		List<Node> children = new ArrayList<>();
		NodeList nl = parent.getChildNodes();
		for ( int i = 0; i < nl.getLength(); i++ ) {
			Node n = nl.item( i );
			if (n.getNodeName().equals(childName)) {
				children.add(n);
			}
		}
		
		return children;
	}	
	
	private static TestResults readExpectedResults2(File f1) throws Exception {
		TestResults tr = new TestResults( "Expected", true, null);
		BufferedReader fr = null;
		
		try {
			fr = new BufferedReader( new FileReader( f1 ) );
			// Read the 1st line, and parse out the Benchmark version #.
			String line = fr.readLine();
			if (line != null) {
				int startOfBenchmarkVersionLocation = line.indexOf(BENCHMARK_VERSION_PREFIX);
				if (startOfBenchmarkVersionLocation != -1) {
					startOfBenchmarkVersionLocation+=BENCHMARK_VERSION_PREFIX.length();
				} else {
					String versionNumError = "Couldn't find " + BENCHMARK_VERSION_PREFIX 
							+ " on first line of expected results file";
					System.out.println(versionNumError);
					throw new IOException(versionNumError);
				}
				// Trim off everything exception the version # and everything past it.
				line = line.substring(startOfBenchmarkVersionLocation);
				int commaLocation = line.indexOf(",");
				if (commaLocation != -1) {
					tr.setBenchmarkVersion(line.substring(0, commaLocation));
				} else {
					String missingCommaError = "Couldn't find comma after version # listed after " 
							+ BENCHMARK_VERSION_PREFIX;
					System.out.println(missingCommaError);
					throw new IOException(missingCommaError);
				}
			}
			
			boolean reading = true;
			while ( reading ) {
				line = fr.readLine();
				reading = line != null;
				if ( reading ) {
				// Normally, each line contains: test name, category, real vulnerability, cwe #

//					String[] parts = line.split(",");
// regex from http://stackoverflow.com/questions/1757065/java-splitting-a-comma-separated-string-but-ignoring-commas-in-quotes
					// This regex needed because some 'full details' entries contain comma's inside quoted strings
					String[] parts = line.split(",(?=([^\"]*\"[^\"]*\")*[^\"]*$)");
					if ( parts[0] != null ) {
						TestCaseResult tcr = new TestCaseResult();
						tcr.setTestCaseName(parts[0]);
						tcr.setCategory( parts[1]);
						tcr.setReal( Boolean.parseBoolean( parts[2] ) );
						tcr.setCWE( Integer.parseInt( parts[3]) );
	
						tcr.setNumber(NistHelper.getTestNumberFromFilename(parts[0]));
						
						// Handle situation where expected results has full details
						// Sometimes, it also has: source, data flow, data flow filename, sink

						if (parts.length > 4) {
							tcr.setSource(parts[4]);
							tcr.setDataFlow(parts[5]);
							tcr.setDataFlowFile(parts[6]);
							tcr.setSink(parts[7]);
						}
						
						tr.put( tcr );
					}
				}
			}
		} finally {
			if (fr != null) fr.close();
		}
		return tr;
	}
	
	/**
	 * This produces the .csv of all the results for this tool. It's basically the expected results file
	 * with a couple of extra columns in it to say what the actual result for this tool was per test case
	 * and whether that result was a pass or fail.
	 * @param actual The actual TestResults to produce the actual results file for.
	 * @return The name of the results file produced
	 */
	private static String produceResultsFile( TestResults actual ) {
		
		File resultsFile = null;
		PrintStream ps = null;
		
		try {
			String benchmarkVersion = actual.getBenchmarkVersion();
			String resultsFileName = scoreCardDirName + File.separator + "Benchmark_v" 
					+ benchmarkVersion + "_Scorecard_for_" + actual.getToolNameAndVersion().replace( ' ', '_' ) 
					+ ".csv";
			resultsFile = new File(resultsFileName);
			FileOutputStream fos = new FileOutputStream(resultsFile, false);
			ps = new PrintStream(fos);
	
			Set<Integer> testCaseKeys = actual.keySet();

			boolean fulldetails = (actual.get(testCaseKeys.iterator().next()).get(0).getSource() != null);
				
			// Write actual results header
			ps.print("test name, #test number, category, CWE, ");
			if (fulldetails) ps.print("source, data flow, data flow filename, sink, ");
			ps.print("real vulnerability, identified by tool, pass/fail, Benchmark version: " + benchmarkVersion);
			
			// Append the date YYYY-MM-DD to the header in each .csv file
			Calendar c = Calendar.getInstance();
			String s = String.format("%1$tY-%1$tm-%1$te", c);
			ps.println(", Actual results generated: " + s);
	
			for (Integer expectedResultsKey : testCaseKeys) {
				// Write meta data to file here.
				TestCaseResult actualResult = actual.get(expectedResultsKey).get(0);
				ps.print(actualResult.getName());
				ps.print(", " + actualResult.getNumber());
				ps.print(", " + actualResult.getCategory());
				ps.print(", " + actualResult.getCWE());
				if (fulldetails) {
					ps.print("," + actualResult.getSource());
					ps.print("," + actualResult.getDataFlow());
					ps.print(", " + actualResult.getDataFlowFile());
					ps.print("," + actualResult.getSink());					
				}
				boolean isreal = actualResult.isReal();
				ps.print(", " + isreal);
				boolean passed = actualResult.isPassed();
				boolean toolresult = !(isreal^passed);
				ps.print(", " + toolresult);
				ps.println(", " + (passed ? "pass" : "fail"));
			}
			
			System.out.println("Actual results file generated: " + resultsFile.getAbsolutePath());
			
			return resultsFile.getName();
			
		} catch (FileNotFoundException e) {
			System.out.println("ERROR: Can't create actual results file: " + resultsFile.getAbsolutePath());
		} finally {
			if (ps != null) ps.close();
		}
		
		return null; // Should have returned results file name earlier if successful
	}
	
	/*
	 * Generate all the vulnerability scorecards. And then 1 commercial tool scorecard if there are commercial tool 
	 * results for at least 2 commercial tools.
	 */
	private static void generateVulnerabilityScorecards( Set<Report> toolResults, Set<String> catSet ) {
		StringBuilder htmlForCommercialAverages = null;
		
		int commercialToolTotal = 0;
		int numberOfVulnCategories = 0;
		int commercialLowTotal = 0;
		int commercialAveTotal = 0;
		int commercialHighTotal = 0;
		
        for (String cat : catSet ) {
            try {
            	ScatterVulns scatter = ScatterVulns.generateComparisonChart(scoreCardDirName, cat, toolResults, focus );
                String filename = "Benchmark_v" + benchmarkVersion + "_Scorecard_for_" + cat.replaceAll(":", "_");
                Path htmlfile = Paths.get( scoreCardDirName + "/" + filename + ".html" );
                Files.copy(Paths.get(pathToScorecardResources + "vulntemplate.html" ), htmlfile, StandardCopyOption.REPLACE_EXISTING );
                String html = new String(Files.readAllBytes( htmlfile ) );
                
                String CWEnr = Integer.toString(BenchmarkScore.translateNameToCWE(cat));
                
                String fullTitle = "NIST Benchmark Scorecard for <A HREF=https://cwe.mitre.org/data/definitions/" + 
                		CWEnr + ".html>" + cat + ": " + getCWEName(CWEnr) + "</A>";

                html = html.replace("${image}", filename + ".png" );
                html = html.replace( "${title}", fullTitle );
                html = html.replace( "${vulnerability}", cat);
                html = html.replace( "${version}", benchmarkVersion );
                
               
                
        		String table = generateVulnStatsTable(toolResults, cat);
        		html = html.replace("${table}", table);
                
                Files.write( htmlfile, html.getBytes() );
                //############## End HTML ##########################
                
                // Now build up the commercial stats scorecard if there are at least 2 commercial tools
                if (scatter.getCommercialToolCount() > 1) {
                	if (htmlForCommercialAverages == null) {
                		commercialToolTotal = scatter.getCommercialToolCount();
                		htmlForCommercialAverages = new StringBuilder();
                		htmlForCommercialAverages.append("<table class=\"table\">\n");
                		htmlForCommercialAverages.append("<tr>");
                		htmlForCommercialAverages.append("<th>Vulnerability Category</th>");
                		htmlForCommercialAverages.append("<th>Low Tool Type</th>");
                		htmlForCommercialAverages.append("<th>Low Score</th>");
                		htmlForCommercialAverages.append("<th>Ave Score</th>");
                		htmlForCommercialAverages.append("<th>High Score</th>");
                		htmlForCommercialAverages.append("<th>High Tool Type</th>");
                		htmlForCommercialAverages.append("</tr>\n");
                	} // if 1st time through
                	
                	numberOfVulnCategories++;

                	String style = "";
                	htmlForCommercialAverages.append("<tr>");
                	htmlForCommercialAverages.append("<td>" + cat + "</td>");
                	htmlForCommercialAverages.append("<td>" + scatter.getCommercialLowToolType() + "</td>");
    				if (scatter.getCommercialLow() <= 10)
    					style = "class=\"danger\"";
    				else if (scatter.getCommercialLow() >= 50)
    					style = "class=\"success\"";
                	htmlForCommercialAverages.append("<td " + style + ">" + scatter.getCommercialLow() + "</td>");
                	commercialLowTotal += scatter.getCommercialLow();
                	htmlForCommercialAverages.append("<td>" + scatter.getCommercialAve() + "</td>");
                	commercialAveTotal += scatter.getCommercialAve();
    				if (scatter.getCommercialHigh() <= 10)
    					style = "class=\"danger\"";
    				else if (scatter.getCommercialHigh() >= 50)
    					style = "class=\"success\"";
    				htmlForCommercialAverages.append("<td " + style + ">" + scatter.getCommercialHigh() + "</td>");
                	commercialHighTotal += scatter.getCommercialHigh();
                	htmlForCommercialAverages.append("<td>" + scatter.getCommercialHighToolType() + "</td>");
                	htmlForCommercialAverages.append("</tr>\n");
                }  // if more than 1 commercial tool
                
            } catch( IOException e ) {
                System.out.println( "Error generating vulnerability summaries: " + e.getMessage() );
                e.printStackTrace();
            }
        } // end for loop
        
	}
	
    /**
     * This generates the vulnerability stats table that goes at the bottom of each vulnerability category
     * page.
     * @param toolResults - The set of results across all the tools.
     * @param category - The vulnerabilty category to generate this table for.
     * @return The HTML of the vulnerability stats table.
     */
	private static String generateVulnStatsTable(Set<Report> toolResults, String category) {
		StringBuilder sb = new StringBuilder();
		sb.append("<table class=\"table\">\n");
		sb.append("<tr>");
		sb.append("<th>Tool</th>");
		if (mixedMode) sb.append("<th>Benchmark Version</th>");
		sb.append("<th>TP</th>");
		sb.append("<th>FN</th>");
		sb.append("<th>Total (P)</th>");
		sb.append("<th>Total (P+N)</th>");
		sb.append("<th>Score</th>");
		sb.append("</tr>\n");

		for (Report toolResult : toolResults) {
			
			if (!(showAveOnlyMode && toolResult.isCommercial())) {
				OverallResults or = toolResult.getOverallResults();
				Map<String, Counter> scores = toolResult.getScores();
				Counter c = scores.get(category);
				OverallResult r = or.getResults(category);
				String style = "";
				
				if (Math.abs(r.truePositiveRate) < .1) {
					style = "class=\"danger\"";
				} else if (r.truePositiveRate > .7) {
					style = "class=\"success\"";
				}

				sb.append("<tr " + style + ">");
				sb.append("<td>" + toolResult.getToolNameAndVersion() + "</td>");
				if (mixedMode) sb.append("<td>" + toolResult.getBenchmarkVersion() + "</td>");
				sb.append("<td>" + c.tp + "</td>");
				sb.append("<td>" + c.fn + "</td>");
				sb.append("<td>" + (c.tp + c.fn) + "</td>");
				sb.append("<td>" + r.total + "</td>");
				sb.append("<td>" + new DecimalFormat("#0.00%").format(r.score) + "</td>");
				sb.append("</tr>\n");
			}
		}

		sb.append("</tr>\n");
		sb.append("</table>");
		return sb.toString();
	}
	
    /**
     * This generates the overall stats table across all the tools that goes at the bottom of the home 
     * page.
     * @param toolResults - The set of results across all the tools.
     * @return The HTML of the overall stats table.
     */
	private static String generateOverallStatsTable(Set<Report> toolResults) {
		StringBuilder sb = new StringBuilder();
		sb.append("<table class=\"table\">\n");
		sb.append("<tr>");
		sb.append("<th>Tool</th>");
		if (mixedMode) sb.append("<th>Benchmark Version</th>");
//		sb.append("<th>TP</th>");
//		sb.append("<th>FN</th>");
//		sb.append("<th>TN</th>");
//		sb.append("<th>FP</th>");
//		sb.append("<th>Total</th>");
//		sb.append("<th>TPR*</th>");
//		sb.append("<th>FPR*</th>");
		sb.append("<th>Score</th>");
		sb.append("</tr>\n");

		for (Report toolResult : toolResults) {
			
			if (!(showAveOnlyMode && toolResult.isCommercial())) {
				OverallResults or = toolResult.getOverallResults();
				Counter c = or.getFindingCounts();
				String style = "";
				
				if (Math.abs(or.getTruePositiveRate() - or.getFalsePositiveRate()) < .1)
					style = "class=\"danger\"";
				else if (or.getTruePositiveRate() > .7 && or.getFalsePositiveRate() < .3)
					style = "class=\"success\"";
				sb.append("<tr " + style + ">");
				sb.append("<td>" + toolResult.getToolNameAndVersion() + "</td>");
				if (mixedMode) sb.append("<td>" + toolResult.getBenchmarkVersion() + "</td>");
/*				sb.append("<td>" + c.tp + "</td>");
				sb.append("<td>" + c.fn + "</td>");
				sb.append("<td>" + c.tn + "</td>");
				sb.append("<td>" + c.fp + "</td>");
				sb.append("<td>" + or.getTotal() + "</td>");
				sb.append("<td>" + new DecimalFormat("#0.00%").format(or.getTruePositiveRate()) + "</td>");
				sb.append("<td>" + new DecimalFormat("#0.00%").format(or.getFalsePositiveRate()) + "</td>");
*/				sb.append("<td>" + new DecimalFormat("#0.00%").format(or.getScore()) + "</td>");
				sb.append("</tr>\n");
			}
		}

		sb.append("</tr>\n");
		sb.append("</table>");
//		sb.append("<p>*-Please refer to each tool's scorecard for the data used to calculate these values.");

		return sb.toString();
	}

	
	/**
	 * This method updates the menus of all the scorecards previously generated so people can navigate
	 * between all the tool results.
	 */
	private static void updateMenus(Set<Report> toolResults, Set<String> catSet ) {

        // Create tool menu
        StringBuffer sb = new StringBuffer();
        for ( Report toolReport : toolResults ) {
			if (!(showAveOnlyMode && toolReport.isCommercial())) {
	            sb.append("<li><a href=\"");
	            sb.append(toolReport.getFilename());
	            sb.append(".html\">");
	            sb.append(toolReport.getToolNameAndVersion());
	            sb.append("</a></li>");
	            sb.append(System.lineSeparator());
			}
        }
        
        String toolmenu = sb.toString();
        
        // create vulnerability menu
        sb = new StringBuffer();
        for (String cat : catSet ) {
            String filename = "Benchmark_v" + benchmarkVersion+"_Scorecard_for_" + cat.replace(' ', '_');  
            sb.append("            <li><a href=\"");
            sb.append( filename );
            sb.append(".html\">");
            sb.append( cat );
            sb.append("</a></li>");
            sb.append(System.lineSeparator());
        }
        String vulnmenu = sb.toString();
        
		// rewrite HTML files with new menus
		updateMenuTemplates( toolmenu, vulnmenu );        
	}
	
	private static void updateMenuTemplates( String toolmenu, String vulnmenu ) {
	    File root = new File( scoreCardDirName );
	    for ( File f : root.listFiles() ) {
	        if ( !f.isDirectory() && f.getName().endsWith( ".html" ) ) {
	            try {
    	            String html = new String( Files.readAllBytes( f.toPath() ) );
    	            html = html.replace("${toolmenu}", toolmenu);
    	            html = html.replace("${vulnmenu}", vulnmenu);
    	            html = html.replace( "${version}", benchmarkVersion );
    	            Files.write( f.toPath(), html.getBytes() );
	            } catch ( IOException e ) {
	                System.out.println ( "Error updating menus in: " + f.getName() );
	                e.printStackTrace();
	            }
	        }
	    }
	}
	
	private static Document getXMLDocument( File f ) throws Exception {
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
		// Prevent XXE = Note, disabling this entirely breaks the parsing of some XML files, like a Burp results
        // file, so have to use the alternate defense.
		//dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        docBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
		docBuilderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        InputSource is = new InputSource(new FileInputStream(f));
        Document doc = docBuilder.parse(is);
        return doc;
	}
	
	private static StandardChartTheme initializeBarTheme() {
        String fontName = "Arial";
        StandardChartTheme theme = (StandardChartTheme) org.jfree.chart.StandardChartTheme.createJFreeTheme();
        theme.setExtraLargeFont(new Font(fontName, Font.PLAIN, 24)); // title
        theme.setLargeFont(new Font(fontName, Font.PLAIN, 20)); // axis-title
        theme.setRegularFont(new Font(fontName, Font.PLAIN, 16));
        theme.setSmallFont(new Font(fontName, Font.PLAIN, 12));
        return theme;
    }
    
    private static void initializeBarPlot(CategoryPlot catplot) {
    	ValueAxis rangeAxis = (ValueAxis) catplot.getRangeAxis();
    	CategoryAxis domainAxis = (CategoryAxis) catplot.getDomainAxis();

        rangeAxis.setRange(0.0, 100.0);
        rangeAxis.setTickLabelPaint(Color.decode("#666666"));
        rangeAxis.setMinorTickCount(5);
        rangeAxis.setMinorTickMarksVisible(true);
        rangeAxis.setTickMarksVisible(true);
        rangeAxis.setLowerMargin(10);
        rangeAxis.setUpperMargin(10);    	
    }
	
    private static void writeBarChartToFile(File f, int width, int height) throws IOException {
        FileOutputStream stream = new FileOutputStream(f);
        ChartUtilities.writeChartAsPNG(stream, barchart, width, height);
        stream.close();
    }
    
	private static Integer cweLookupExpected(int cwe) {
		switch (cwe) {
		case 23: // Relative path traversal
		case 36: // Absolute path traversal
			return 22; // OPT.JAVA.SEC_JAVA.PathTraversalRule
		case 404:  // Improper Resource Shutdown or Release
			return 459; // Incomplete Cleanup, temporal para regla: OPT.JAVA.IO.CS que deberia cambiar de 459->404. QAK-5038
			
		default:
			return cwe;
		}			
	}
	
	private static HashMap <String, String> getCWElist(File cwefile) {
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
	}
	
	public static final String getCWEName(String CWEnr) {
		return HmCWElist.get(CWEnr);
	}
}
