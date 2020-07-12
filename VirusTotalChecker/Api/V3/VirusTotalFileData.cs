using Newtonsoft.Json;

namespace VirusTotalChecker.Api.V3
{
	public class VirusTotalFileData
	{
		[JsonProperty("id")]
		public string Id { get; set; }
		[JsonProperty("attributes")]
		public VirusTotalFileInfo Info { get; set; }
	}
}