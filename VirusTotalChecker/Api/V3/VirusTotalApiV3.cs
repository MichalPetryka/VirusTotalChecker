using Newtonsoft.Json;
using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace VirusTotalChecker.Api.V3
{
	internal class VirusTotalApiV3 : VirusTotalApi
	{
		public VirusTotalApiV3(string apiKey) : base(apiKey)
		{
			Client.DefaultRequestHeaders.Add("x-apikey", apiKey);
		}

		public override async Task<VirusTotalReport> Report(string resource)
		{
			VirusTotalData data;
			using (HttpResponseMessage result = await Client.GetAsync($"https://www.virustotal.com/api/v3/files/{resource}"))
			{
				if (result.StatusCode == HttpStatusCode.TooManyRequests)
					throw new RateLimitException(resource);

				data = JsonConvert.DeserializeObject<VirusTotalData>(await result.Content.ReadAsStringAsync());
			}

			if (data.Error != null)
				return data.Error.Code == "NotFoundError" ? new VirusTotalReport { Available = false } : throw new VirusTotalException(data.Error.Message);

			VirusTotalFileData response = data.Data;
			return new VirusTotalReport
			{
				Available = true,
				Date = DateTimeOffset.FromUnixTimeSeconds(long.Parse(response.Info.Date)).ToString(),
				Link = $"https://www.virustotal.com/gui/file/{response.Id}/detection",
				Positive = response.Info.Results.Malicious + response.Info.Results.Suspicious,
				Total = response.Info.Results.Malicious + response.Info.Results.Suspicious +
						response.Info.Results.Harmless + response.Info.Results.Undetected
			};
		}
	}
}
