using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace VirusTotalChecker.Api
{
	internal abstract class VirusTotalApi : IDisposable
	{
		protected readonly HttpClient Client = new HttpClient(new SocketsHttpHandler
		{
			AutomaticDecompression = DecompressionMethods.All
		});
		protected readonly string ApiKey;

		protected VirusTotalApi(string apiKey)
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
