using Newtonsoft.Json;

namespace VirusTotalChecker.Api.V3
{
	public class VirusTotalError
	{
		[JsonProperty("code")]
		public string Code { get; set; }
		[JsonProperty("message")]
		public string Message { get; set; }
	}
}