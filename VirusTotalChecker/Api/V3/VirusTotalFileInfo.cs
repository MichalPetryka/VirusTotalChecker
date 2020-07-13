using Newtonsoft.Json;

namespace VirusTotalChecker.Api.V3
{
	public class VirusTotalFileInfo
	{
		[JsonProperty("last_analysis_date")]
		public string Date { get; set; }
		[JsonProperty("last_analysis_stats")]
		public VirusTotalScanStatistics Results { get; set; }
	}
}
