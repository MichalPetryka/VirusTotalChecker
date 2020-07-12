using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace VirusTotalChecker.Api
{
	internal abstract class VirusTotalApi : IDisposable
	{
		protected readonly HttpClient Client = new HttpClient();
		protected readonly string ApiKey;

		public VirusTotalApi(string apiKey)
		{
			ApiKey = apiKey;
		}

		public abstract Task<VirusTotalReport> Report(string resource);

		private void ReleaseUnmanagedResources()
		{
			Client.Dispose();
		}

		public void Dispose()
		{
			ReleaseUnmanagedResources();
			GC.SuppressFinalize(this);
		}

		~VirusTotalApi()
		{
			ReleaseUnmanagedResources();
		}
	}
}