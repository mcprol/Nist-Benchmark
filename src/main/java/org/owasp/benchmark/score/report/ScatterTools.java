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

import java.awt.Color;
import java.awt.geom.Point2D;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map.Entry;

import javax.swing.JFrame;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.annotations.XYTextAnnotation;
import org.jfree.chart.plot.CategoryPlot;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.XYPlot;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;
import org.jfree.ui.TextAnchor;
import org.owasp.benchmark.score.parsers.OverallResult;
import org.owasp.benchmark.score.parsers.OverallResults;

public class ScatterTools extends ScatterPlot {
	public char averageLabel;
	public double atpr, afpr;
	public static HashSet <String> IgnCWEs = new HashSet <String>(); 
	private static String filespath = "./";
    //private DefaultCategoryDataset bardataset = new DefaultCategoryDataset();

	public ScatterTools(String title, int height, OverallResults or, DefaultCategoryDataset bardtset, String currenttool) {
		display("          " + title, height, or, bardtset, currenttool);
		//this.bardataset = bardtset;
		//bardtset.addValue(22, "Buu", "CWE-113");
		//bardtset.addValue(27, "Beu", "CWE-113");
		
		//bardataset.addValue(77, "Buu", "CWE-111");
		//bardataset.addValue(87, "Beu", "CWE-111");
	}

	private void ReadIgnoredCWEs() {
		try {
			BufferedReader infile = new BufferedReader(new FileReader(filespath + "IgnoredCWEs.txt"));

			String line;
			while ((line = infile.readLine()) != null) {
				if (!line.trim().equals("")) {
					IgnCWEs.add(line);
				}
			}
			infile.close();
		}
		catch (Exception e) {

		}
	}

	private JFreeChart display(String title, int height, OverallResults or, DefaultCategoryDataset bardataset, String currenttool) {

		JFrame f = new JFrame(title);
		f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		ReadIgnoredCWEs();

		XYSeriesCollection dataset = new XYSeriesCollection();
		XYSeries series = new XYSeries("Scores");
		int totalTools = 0;
		double totalToolTPR = 0;
		double totalToolFPR = 0;
		for (OverallResult r : or.getResults()) {
			// 20171030 RME skip unsupported CWE's
			if (!IgnCWEs.contains(r.category.substring(4))) {
				series.add(r.falsePositiveRate * 100, r.truePositiveRate * 100);
				totalTools++;
				totalToolTPR += r.truePositiveRate;
				totalToolFPR += r.falsePositiveRate;
			}
		}
		atpr = totalToolTPR / totalTools;
		afpr = totalToolFPR / totalTools;

		if ( or.getResults().size() > 1) {
			series.add(afpr * 100, atpr * 100);
		}

		dataset.addSeries(series);

		chart = ChartFactory.createScatterPlot(title, "False Positive Rate", "True Positive Rate", dataset, PlotOrientation.VERTICAL, true, true, false);
		theme.apply(chart);

        XYPlot xyplot = chart.getXYPlot();
		initializePlot( xyplot );
        
		makeDataLabels(or, xyplot);
		makeLegend( or, 103, 93, dataset, xyplot, bardataset, currenttool);

		XYTextAnnotation time = new XYTextAnnotation("Tool run time: " + or.getTime(), 12, -5.6);
		time.setTextAnchor(TextAnchor.TOP_LEFT);
		time.setFont(theme.getRegularFont());
		time.setPaint(Color.red);
		xyplot.addAnnotation(time);

		ChartPanel cp = new ChartPanel(chart, height, height, 400, 400, 1200, 1200, false, false, false, false, false, false);
		f.add(cp);
		f.pack();
		f.setLocationRelativeTo(null);
		// f.setVisible(true);
		return chart;
	}

	private void makeDataLabels(OverallResults or, XYPlot xyplot) {
		HashMap<Point2D, String> map = makePointList(or);
		for (Entry<Point2D, String> e : map.entrySet()) {
			if (e.getValue() != null) {
				Point2D p = e.getKey();
				String label = sort(e.getValue());
				XYTextAnnotation annotation = new XYTextAnnotation(label, p.getX(), p.getY());
				annotation.setTextAnchor(p.getX() < 3 ? TextAnchor.TOP_LEFT : TextAnchor.TOP_CENTER);
				annotation.setBackgroundPaint(Color.white);
				// set color of average to black and everything else to blue
				if(averageLabel==label.toCharArray()[0]){
					annotation.setPaint(Color.magenta);
				} else {
					annotation.setPaint(Color.blue);
				}
				annotation.setFont(theme.getRegularFont());
				xyplot.addAnnotation(annotation);
			}
		}
	}

	private String sort(String value) {
		String[] parts = value.split(",");
		Arrays.sort(parts);
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < parts.length; i++) {
			sb.append(parts[i]);
			if (i < parts.length - 1)
				sb.append(",");
		}
		return sb.toString();
	}

	SecureRandom sr = new SecureRandom();

	private HashMap<Point2D, String> makePointList(OverallResults or) {
		HashMap<Point2D, String> map = new HashMap<Point2D, String>();
		char ch = 'A';
		int size = 0;
		// make a list of all points. Add in a tiny random to prevent exact
		// duplicate coordinates in map
		for (OverallResult r : or.getResults()) {
			// 20171030 RME skip unsupported CWE's
			if (!IgnCWEs.contains(r.category.substring(4))) {
				//System.out.println("QQQQ " + ch + " " + r.truePositiveRate);
				size++;
				//double x = r.falsePositiveRate * 100 + sr.nextDouble() * .000001;
				double x = 0.0;
				// this puts the label just below the point
				double y = r.truePositiveRate * 100 + sr.nextDouble() * .000001 - 1;
				Point2D p = new Point2D.Double(x, y);
				String label = "" + ch;
				map.put(p, label);
				ch++;
			}
			//else {
			//	System.out.println("PPP---PPP " + r.category.substring(4));
			//}
		}
		// add  average point
		if(size>1){
			double x = afpr * 100 + sr.nextDouble() * .000001;
			double y = atpr * 100 + sr.nextDouble() * .000001 - 1;
			Point2D p = new Point2D.Double(x, y);
			String label = "" + ch;
			averageLabel = ch;
			map.put(p, label);
		}
		dedupify(map);
		return map;
	}

	private void dedupify(HashMap<Point2D, String> map) {
		for (Entry<Point2D, String> e1 : map.entrySet()) {
			Entry<Point2D, String> e2 = getMatch(map, e1);
			while (e2 != null) {
				StringBuilder label = new StringBuilder();
				if (e1.getValue() != null)
					label.append(e1.getValue());
				if (e1.getValue() != null && e2.getValue() != null)
					label.append(",");
				if (e2.getValue() != null)
					label.append(e2.getValue());
				e1.setValue(label.toString());
				e2.setValue(null);
				e2 = getMatch(map, e1);
			}
		}
	}

	private Entry<Point2D, String> getMatch(HashMap<Point2D, String> map, Entry<Point2D, String> e1) {
		for (Entry<Point2D, String> e2 : map.entrySet()) {
			Double xd = Math.abs(e1.getKey().getX() - e2.getKey().getX());
			Double yd = Math.abs(e1.getKey().getY() - e2.getKey().getY());
			boolean close = xd < 1 && yd < 3;
			if (e1 != e2 && e1.getValue() != null && e2.getValue() != null && close) {
				return e2;
			}
		}
		return null;
	}

	private void makeLegend(OverallResults or, double x, double y, XYSeriesCollection dataset, XYPlot xyplot, 
			DefaultCategoryDataset bardataset, String currenttool) {
		//bardataset.addValue(22, "Buu", "CWE-115");
		//bardataset.addValue(27, "Beu", "CWE-115");
		char ch = 'A';
		int i = 0;
		int toolCount = 0;
		double totalScore = 0, totalTPR = 0;
		for (OverallResult r : or.getResults()) {
			if (!Double.isNaN(r.truePositiveRate)) {
				toolCount++;
				// 20171030 RME skip unsupported CWE's
				if (!IgnCWEs.contains(r.category.substring(4))) {
					totalTPR += r.truePositiveRate;
					//System.out.println("LLL+++LLL " + r.category.substring(4) + " " + x + " " + y);
					// Add a bit more white space if the character is I, since its so thin.
					String label = (ch == 'I' ? ch + ":  " : "" + ch + ": ");
					//int score = (int) (100 * (r.truePositiveRate - r.falsePositiveRate));
					int score = (int) (100 * r.truePositiveRate);
					//System.out.println("LLLL " + r.category + " " + r.truePositiveRate + " " + r.falsePositiveRate + " " + score);
					String msg = "\u25A0 " + label + r.category + " (" + score + "%)";
					totalScore += score;
					XYTextAnnotation stroketext = new XYTextAnnotation(msg, x, y + i * -3.3);
					stroketext.setTextAnchor(TextAnchor.CENTER_LEFT);
					stroketext.setBackgroundPaint(Color.white);
					stroketext.setPaint(Color.blue);
					stroketext.setFont(theme.getRegularFont());
					xyplot.addAnnotation(stroketext);
					bardataset.addValue(100 * r.truePositiveRate, currenttool, r.category);
					i++;
					ch++;
					if (i == 28) {
						i = 0;
						x = x + 33;
					}
				}
			}
			//else {	
			//	System.out.println("LLL---LLL " + r.category.substring(4) + " " + x + " " + y);
			//}
		}

		if(toolCount>1) {
			double averageScore = 100.0 * totalTPR/toolCount;
			XYTextAnnotation stroketext = new XYTextAnnotation("\u25A0 " + ch + ": Av. Sc. Tool"+ " (" + (int)averageScore + "%)", x, y + i * -3.3);
			stroketext.setTextAnchor(TextAnchor.CENTER_LEFT);
			stroketext.setBackgroundPaint(Color.white);
			stroketext.setPaint(Color.magenta);
			stroketext.setFont(theme.getRegularFont());
			xyplot.addAnnotation(stroketext);

			Point2D averagePoint = new Point2D.Double( 0, averageScore );
			makePoint(xyplot, averagePoint, 3, Color.magenta );
		}
	}

	public static void main(String[] args) throws IOException {
		OverallResults or = new OverallResults();
		or.add("XSS1", .62, .2, 12, 5);
		or.add("XSS2", .64, .2, 12, 5);

		or.add("XSS25", .5, .3, 12, 5);
		or.add("XSS26", .5, .3, 12, 5);

		or.add("XSS31", .34, .2, 12, 5);
		or.add("XSS32", .36, .2, 12, 5);
		or.add("XSS33", .38, .2, 12, 5);

		or.add("XSS4", .72, .22, 12, 5);
		or.add("XSS5", .72, .18, 12, 5);
		or.add("XSS6", .28, .19, 12, 5);
		or.add("XSS7", .28, .21, 12, 5);
		or.add("SQL Injection", 1, .5, 1000, 5);
		or.add("Header Injection", 0, .5, 4, 5);
		or.add("Reflection Injection", 0, 0, 300, 5);
		or.add("LDAP Injection", .5, 1, 6, 5);
		or.add("Weak Encryption", .2, .9, 600, 5);
		//ScatterTools scatter = new ScatterTools("OWASP Benchmark Results for SomeTool", 800, or, null);
		System.exit(0);
	}
}