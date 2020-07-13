using Newtonsoft.Json;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace VirusTotalChecker.Api.V2
{
	internal class VirusTotalApiV2 : VirusTotalApi
	{
		public VirusTotalApiV2(string apiKey) : base(apiKey)
		{
		}

		public override async Task<VirusTotalReport> Report(string resource)
		{
			VirusTotalReportResponse response;
			using (HttpResponseMessage result = await Client.GetAsync($"https://www.virustotal.com/vtapi/v2/file/report?apikey={ApiKey}&resource={resource}"))
			{
				if (result.StatusCode == HttpStatusCode.NoContent)
					throw new RateLimitException(resource);

				response = JsonConvert.DeserializeObject<VirusTotalReportResponse>(await result.Content.ReadAsStringAsync());
			}

			return new VirusTotalReport
			{
				Available = response.Result == VirusTotalResult.Present,
				Date = response.Date,
				Link = response.Link,
				Positive = response.Positive,
				Total = response.Total
			};
		}
	}
}
