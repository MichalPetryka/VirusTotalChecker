using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using VirusTotalChecker.Api;
using VirusTotalChecker.Utilities;

namespace VirusTotalChecker.Console
{
	public sealed class DataProcessor : IDisposable
	{
		private readonly VirusTotalClient _client;
		private readonly int _ratelimitRetryDelay;

		public DataProcessor(VirusTotalClient client, int ratelimitRetryDelay)
		{
			_client = client;
			_ratelimitRetryDelay = ratelimitRetryDelay;
		}

		public async void ProcessFile(string path, string hash = null)
		{
			await CheckFile(path, hash);
		}

		public async void ProcessFileLink(string path)
		{
			await CheckFileLink(path);
		}

		public async void ProcessDirectory(string path, string filter, bool recursive)
		{
			await Task.WhenAll(Directory.EnumerateFiles(path, filter,
					recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly)
				.Select(file => CheckFile(file)));
			ConsoleUtil.WriteLine($"All files in {path} have been scanned", ConsoleColor.Blue);
		}

		private async Task CheckFile(string path, string hash = null)
		{
			if (Program.Exitting)
				return;

			try
			{
				PrintResult(path, hash == null ? await _client.CheckFile(path) : await _client.CheckHash(hash));
			}
			catch (RateLimitException rateLimitException)
			{
				// ReSharper disable once HeapView.BoxingAllocation
				ConsoleUtil.WriteLine($"Request for {path} exceeded the ratelimit, retrying in {_ratelimitRetryDelay}ms",
					ConsoleColor.Yellow);
				await Task.Delay(_ratelimitRetryDelay);
				await CheckFile(path, rateLimitException.Resource);
			}
			catch (Exception ex)
			{
				ConsoleUtil.WriteLine(
					ex.InnerException == null
						? ExceptionFilter.GetErrorMessage(ex)
						: $"{ExceptionFilter.GetErrorMessage(ex)}. Inner error: {ExceptionFilter.GetErrorMessage(ex.InnerException)}",
					ConsoleColor.Red);
			}
		}

		private async Task CheckFileLink(string link, string hash = null)
		{
			if (Program.Exitting)
				return;

			try
			{
				PrintResult(link, hash == null ? await _client.CheckFileLink(link) : await _client.CheckHash(hash));
			}
			catch (RateLimitException rateLimitException)
			{
				// ReSharper disable once HeapView.BoxingAllocation
				ConsoleUtil.WriteLine($"Request for {link} exceeded the ratelimit, retrying in {_ratelimitRetryDelay}ms",
					ConsoleColor.Yellow);
				await Task.Delay(_ratelimitRetryDelay);
				await CheckFileLink(link, rateLimitException.Resource);
			}
			catch (Exception ex)
			{
				ConsoleUtil.WriteLine(
					ex.InnerException == null
						? ExceptionFilter.GetErrorMessage(ex)
						: $"{ExceptionFilter.GetErrorMessage(ex)}. Inner error: {ExceptionFilter.GetErrorMessage(ex.InnerException)}",
					ConsoleColor.Red);
			}
		}

		private void PrintResult(string name, VirusTotalReport report)
		{
			// ReSharper disable HeapView.BoxingAllocation
			if (report.Available)
			{
				if (report.Positive == 0)
					ConsoleUtil.WriteLine(
						$"File {name} clean, last checked on {report.Date} by {report.Total} AVs\n{report.Link}",
						ConsoleColor.Green);
				else if (report.Positive / (float)report.Total < 0.1f)
				{
					string message =
						$"File {name} detected by {report.Positive} out of {report.Total} AVs, last checked on {report.Date}\n{report.Link}";
					ConsoleUtil.WriteLine(message, ConsoleColor.Yellow);
					MessageBox.Show(name, message, MessageBox.Type.Warning);
				}
				else
				{
					string message =
						$"File {name} detected by {report.Positive} out of {report.Total} AVs, last checked on {report.Date}\n{report.Link}";
					ConsoleUtil.WriteLine(message, ConsoleColor.Red);
					MessageBox.Show(name, message, MessageBox.Type.Error);
				}
			}
			else
				ConsoleUtil.WriteLine($"File {name} not present in the database, upload it manually",
					ConsoleColor.Blue);
			// ReSharper restore HeapView.BoxingAllocation
		}

		public void Dispose()
		{
			_client?.Dispose();
		}
	}
}
