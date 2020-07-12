using Newtonsoft.Json;

namespace VirusTotalChecker.Api.V2
{
	internal class VirusTotalReportResponse
	{
		[JsonProperty("response_code")]
		public VirusTotalResult Result { get; set; }
		[JsonProperty("scan_date")]
		public string Date { get; set; }
		[JsonProperty("permalink")]
		public string Link { get; set; }
		[JsonProperty("positives")]
		public int Positive { get; set; }
		[JsonProperty("total")]
		public int Total { get; set; }
	}
}