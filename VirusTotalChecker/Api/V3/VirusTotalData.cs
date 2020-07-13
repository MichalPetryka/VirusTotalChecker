using Newtonsoft.Json;

namespace VirusTotalChecker.Api.V3
{
	public class VirusTotalData
	{
		[JsonProperty("data")]
		public VirusTotalFileData Data { get; set; }
		[JsonProperty("error")]
		public VirusTotalError Error { get; set; }
	}
}
