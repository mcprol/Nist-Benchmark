package org.owasp.benchmark.score.report;

import java.io.FileWriter;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmark.score.parsers.OverallResult;
import org.owasp.benchmark.score.parsers.OverallResults;

public class HighChartsGenerator {

	public static void generateToolsChartData(String dirname, String filename, String chartTitle, Set<Report> toolResults) {
		JSONObject chart = new JSONObject();
		chart.put("type", "bar");

		JSONObject title = new JSONObject();
		title.put("text", chartTitle);

		JSONObject legend = new JSONObject();
		legend.put("enabled", false);

		JSONObject xAxis = new JSONObject();
		populateToolsCategoryXAxis(xAxis, toolResults);

		JSONObject yAxis = new JSONObject();
		yAxis.put("min", 0);
		yAxis.put("max", 100);
		JSONObject yAxisTitle = new JSONObject();
		yAxisTitle.put("text", "");
		yAxis.put("title", yAxisTitle);


		JSONArray series = createToolsSeries(toolResults);

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("chart", chart);		
		jsonObject.put("title", title);		
		jsonObject.put("xAxis", xAxis);		
		jsonObject.put("yAxis", yAxis);		
		jsonObject.put("series", series);		
		jsonObject.put("legend", legend);		

		saveToFile(dirname, filename, jsonObject);
	}

	private static void saveToFile(String dirname, String filename, JSONObject jsonObject) {
		try {
			FileWriter file = new FileWriter(dirname + "/" + filename + ".js");
			String var = "var " + filename.replace("-", "_").replace(".", "_") + " = " + jsonObject.toString() + ";";
			file.write(var);
			file.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static JSONArray createToolsSeries(Set<Report> toolResults) {
		JSONArray serie_data = new JSONArray();
		for ( Report toolReport : toolResults ) {
			OverallResults overallResults = toolReport.getOverallResults();
			Double value = overallResults.getTruePositiveRate() * 100;

			serie_data.put(value);
		}

		JSONObject serie = new JSONObject();
		serie.put("data", serie_data);

		JSONArray series = new JSONArray();
		series.put(serie);

		return series;
	}

	private static JSONObject populateToolsCategoryXAxis(JSONObject xAxis, Set<Report> toolResults) {
		JSONArray categories = new JSONArray();
		for ( Report toolReport : toolResults ) {
			String toolNameAndVersion = toolReport.getToolNameAndVersion();

			categories.put(toolNameAndVersion);
		}

		xAxis.put("categories", categories);
		return xAxis;
	}

	public static void generateCWEChartData(String dirname, String filename, String chartTitle, Set<Report> toolResults) {
		JSONObject chart = new JSONObject();
		chart.put("type", "bar");

		JSONObject title = new JSONObject();
		title.put("text", chartTitle);

		JSONObject legend = new JSONObject();
		legend.put("enabled", true);
		legend.put("layout", "horizontal");
		legend.put("align", "center");
		legend.put("verticalAlign", "bottom");

		JSONObject tooltip = new JSONObject();
		tooltip.put("shared", true);

		JSONObject xAxis = new JSONObject();
		populateCWECategoryXAxis(xAxis, toolResults, false);

		JSONObject yAxis = new JSONObject();
		yAxis.put("min", 0);
		yAxis.put("max", 100);
		JSONObject yAxisTitle = new JSONObject();
		yAxisTitle.put("text", "");
		yAxis.put("title", yAxisTitle);

		JSONArray series = createCWESeries(toolResults);

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("chart", chart);		
		jsonObject.put("title", title);		
		jsonObject.put("xAxis", xAxis);		
		jsonObject.put("yAxis", yAxis);		
		jsonObject.put("series", series);		
		jsonObject.put("legend", legend);		
		jsonObject.put("tooltip", tooltip);		

		saveToFile(dirname, filename, jsonObject);
	}

	public static void generateCWEperToolChartData(String dirname, String version, Set<Report> toolResults) {
		// Generate series of .js files per tool analysed
		for ( Report toolReport : toolResults ) {
			String toolname = toolReport.getToolName();
			String toolversion = toolReport.getToolVersion();

			String filename = "Benchmark_v" + version + "_Scorecard_for_" + toolname + "_v" + toolversion;
			String chartTitle = "NIST Benchmark '" + version + "' for: '" + toolname + " v" + toolversion;

			JSONObject chart = new JSONObject();
			chart.put("type", "bar");

			JSONObject title = new JSONObject();
			title.put("text", chartTitle);

			JSONObject legend = new JSONObject();
			legend.put("enabled", true);
			legend.put("layout", "horizontal");
			legend.put("align", "center");
			legend.put("verticalAlign", "bottom");

			JSONObject tooltip = new JSONObject();
			tooltip.put("shared", true);

			JSONObject xAxis = new JSONObject();
			populateCWECategoryXAxis(xAxis, toolResults, true);

			JSONObject yAxis = new JSONObject();
			yAxis.put("min", 0);
			yAxis.put("max", 100);
			JSONObject yAxisTitle = new JSONObject();
			yAxisTitle.put("text", "");
			yAxis.put("title", yAxisTitle);

			JSONArray series = createCWESeriesPerTool(toolReport);

			JSONObject jsonObject = new JSONObject();
			jsonObject.put("chart", chart);		
			jsonObject.put("title", title);		
			jsonObject.put("xAxis", xAxis);		
			jsonObject.put("yAxis", yAxis);		
			jsonObject.put("series", series);		
			jsonObject.put("legend", legend);		
			jsonObject.put("tooltip", tooltip);		



			saveToFile(dirname, filename, jsonObject);
		}


	}


	private static JSONObject populateCWECategoryXAxis(JSONObject xAxis, Set<Report> toolResults, boolean addtotals) {
		JSONArray categories = new JSONArray();
		for ( Report toolReport : toolResults ) {
			OverallResults overallResults = toolReport.getOverallResults();
			Collection<String> rcategories = overallResults.getCategories();

			for (String category: rcategories) {
				categories.put(category);
			}
			break;
		}
		if (addtotals) {
			categories.put("Totals");
		}

		xAxis.put("categories", categories);
		return xAxis;
	}


	private static JSONArray createCWESeries(Set<Report> toolResults) {
		JSONArray series = new JSONArray();

		// first serie is a special serie with the number of test cases
		JSONObject serie = new JSONObject();
		series.put(serie);
		serie.put("name", "testcases");
		serie.put("color", "white");
		serie.put("pointWidth", 0);

		JSONObject dataLabels = new JSONObject();
		serie.put("dataLabels", dataLabels);

		dataLabels.put("enabled", false);
		dataLabels.put("align", "right");
		dataLabels.put("inside", true);

		JSONArray serie_data = new JSONArray();
		serie.put("data", serie_data);
		for ( Report toolReport : toolResults ) {
			OverallResults overallResults = toolReport.getOverallResults();

			for (OverallResult overallResult: overallResults.getResults()) {
				int testcases = overallResult.total;
				serie_data.put(testcases);
			}
			break;
		}


		// data series
		HashMap<String, JSONObject> mapSeries = new HashMap<>();
		for ( Report toolReport : toolResults ) {
			OverallResults overallResults = toolReport.getOverallResults();

			String key = toolReport.getToolNameAndVersion();
			serie = mapSeries.get(key);
			if (serie == null) {
				serie = new JSONObject();
				mapSeries.put(key, serie);
				series.put(serie);

				serie_data = new JSONArray();
				serie.put("data", serie_data);
				serie.put("name", key);
			}

			serie_data = serie.getJSONArray("data");
			Collection<String> categories = overallResults.getCategories();
			for (String category: categories) {
				OverallResult overallResult = overallResults.getResults(category);
				serie_data.put(overallResult.truePositiveRate * 100);
			}
		}

		return series;
	}

	private static JSONArray createCWESeriesPerTool(Report toolResult) {
		JSONArray series = new JSONArray();

		// first serie is a special serie with the number of test cases
		JSONObject serie = new JSONObject();
		series.put(serie);
		serie.put("name", "testcases");
		serie.put("color", "white");
		serie.put("pointWidth", 0);

		JSONObject dataLabels = new JSONObject();
		serie.put("dataLabels", dataLabels);

		dataLabels.put("enabled", false);
		dataLabels.put("align", "right");
		dataLabels.put("inside", true);

		JSONArray serie_data = new JSONArray();
		serie.put("data", serie_data);
		OverallResults overallResults = toolResult.getOverallResults();

		for (OverallResult overallResult: overallResults.getResults()) {
			int testcases = overallResult.total;
			serie_data.put(testcases);
		}
		serie_data.put(Integer.parseInt(toolResult.getTotalProc()));
		
		// data series
		HashMap<String, JSONObject> mapSeries = new HashMap<>();

		String key = toolResult.getToolNameAndVersion();
		JSONObject tooltipformat = new JSONObject();
		tooltipformat.put("valueDecimals", 2);
		tooltipformat.put("valueSuffix", " %");
		
		serie = mapSeries.get(key);
		if (serie == null) {
			serie = new JSONObject();
			mapSeries.put(key, serie);
			series.put(serie);

			serie_data = new JSONArray();
			serie.put("data", serie_data);
			serie.put("name", key);
			serie.put("tooltip", tooltipformat);
		}

		serie_data = serie.getJSONArray("data");
		Collection<String> categories = overallResults.getCategories();
		for (String category: categories) {
			OverallResult overallResult = overallResults.getResults(category);
			serie_data.put(overallResult.truePositiveRate * 100);
		}
		
		double totalscore = toolResult.getOverallResults().getScore() * 100;
		JSONObject totalinred = new JSONObject();
		totalinred.put("y", totalscore);
		totalinred.put("color", "red");
		serie_data.put(totalinred);
		//serie.put("data", serie_data);
		
		return series;
	}


}
