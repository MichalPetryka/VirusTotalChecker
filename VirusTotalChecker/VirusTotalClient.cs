using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using VirusTotalChecker.Api;
using VirusTotalChecker.Api.V2;
using VirusTotalChecker.Api.V3;
using VirusTotalChecker.Logging;
using VirusTotalChecker.Utilities;

namespace VirusTotalChecker
{
	public class VirusTotalClient : IDisposable
	{
		private readonly VirusTotalApi _api;
		private readonly HashType _hashType;
		private readonly bool _cacheLast;
		private readonly ILogHandler _logHandler;

		private volatile string _lastHash;
		private volatile VirusTotalReport _lastReport;
		private readonly object _lastLock = new object();
		private volatile HttpClient _fileLinkClient;

		public VirusTotalClient(string apiKey, int apiVersion, HashType hashType, bool cacheLast,
			ILogHandler logHandler)
		{
			_api = apiVersion switch
			{
				2 => new VirusTotalApiV2(apiKey),
				3 => new VirusTotalApiV3(apiKey),
				_ => throw new NotSupportedException()
			};
			_hashType = hashType;
			_cacheLast = cacheLast;
			_logHandler = logHandler;
		}

		public async Task<VirusTotalReport> CheckHash(string hash)
		{
			if (!_cacheLast)
				return await _api.Report(hash);

			lock (_lastLock)
				if (string.Equals(_lastHash, hash, StringComparison.OrdinalIgnoreCase))
				{
					_logHandler.Log($"Returning cached data for {hash}");
					return _lastReport;
				}

			VirusTotalReport report = await _api.Report(hash);
			lock (_lastLock)
			{
				_lastHash = hash;
				_lastReport = report;
			}

			return report;
		}

		public async Task<VirusTotalReport> CheckFileLink(string link)
		{
			_fileLinkClient ??= new HttpClient();
			byte[] hash;
			using (HashAlgorithm hashAlgorithm = GetHashAlgorithm())
				using (HttpResponseMessage response = await _fileLinkClient.GetAsync(link))
					await using (Stream stream = await response.Content.ReadAsStreamAsync())
						hash = await hashAlgorithm.ComputeHashAsync(stream);

			return await CheckHash(hash.ToHexString());
		}

		public async Task<VirusTotalReport> CheckFile(string path)
		{
			byte[] hash;
			using (HashAlgorithm hashAlgorithm = GetHashAlgorithm())
				await using (FileStream fs = await WaitForFile(path, FileMode.Open, FileAccess.Read,
					FileShare.ReadWrite))
					hash = await hashAlgorithm.ComputeHashAsync(fs);

			return await CheckHash(hash.ToHexString());
		}

		private async Task<FileStream> WaitForFile(string fullPath, FileMode mode, FileAccess access,
			FileShare share)
		{
			IOException exception = null;
			for (int numTries = 0; numTries < 100; numTries++)
			{
				FileStream fs = null;
				try
				{
					fs = new FileStream(fullPath, mode, access, share);
					return fs;
				}
				catch (IOException ex)
				{
					exception = ex;
					if (fs != null)
						await fs.DisposeAsync();

					const int retryDelay = 200;
					// ReSharper disable once HeapView.BoxingAllocation
					// ReSharper disable once InconsistentlySynchronizedField
					_logHandler.Log($"Reading {fullPath} failed, retrying in {retryDelay}ms. Error: {ExceptionFilter.GetErrorMessage(ex)}",
						LogType.Warning);
					await Task.Delay(retryDelay);
				}
			}

			throw exception!;
		}

		private HashAlgorithm GetHashAlgorithm()
		{
			return _hashType switch
			{
				HashType.Md5 => MD5.Create(),
				HashType.Sha1 => SHA1.Create(),
				_ => SHA256.Create()
			};
		}

		private void ReleaseUnmanagedResources()
		{
			_api.Dispose();
		}

		public void Dispose()
		{
			ReleaseUnmanagedResources();
			GC.SuppressFinalize(this);
		}

		~VirusTotalClient()
		{
			ReleaseUnmanagedResources();
		}
	}
}
