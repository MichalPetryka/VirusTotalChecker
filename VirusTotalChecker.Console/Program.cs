using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using VirusTotalChecker.Api;
using VirusTotalChecker.Configuration;

namespace VirusTotalChecker.Console
{
	internal static class Program
	{
		private static readonly List<FileSystemWatcher> Watchers = new List<FileSystemWatcher>();
		private static volatile bool _exitting;
		private static VirusTotalClient _client;
		private static int ratelimitRetryDelay = 60000;
		private static volatile bool _showStacktraces;

		private static void Main(string[] args)
		{
			_client = new VirusTotalClient(args[0], int.Parse(args[1]), HashType.Sha256, true, ConsoleUtil.LogHandler);
			MonitoredDirectory[] directories = new MonitoredDirectory[0];

			try
			{
				const string inotify = "/proc/sys/fs/inotify/max_user_watches";
				if (File.Exists(inotify))
				{
					string value;
					using (FileStream fs = new FileStream(inotify, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
					{
						using (StreamReader sr = new StreamReader(fs))
							value = sr.ReadToEnd();
					}

					if (int.TryParse(value, out int limit))
					{
						if (limit < 8192 + directories.Length)
							// ReSharper disable once HeapView.BoxingAllocation
							ConsoleUtil.WriteLine($"Low inotify limit: {limit}, consider increasing it's value",
								ConsoleColor.Yellow);
					}
					else
						ConsoleUtil.WriteLine($"Can't parse {value} as a valid inotify limit!", ConsoleColor.Red);
				}
			}
			catch (Exception ex)
			{
				ConsoleUtil.WriteLine($"Error while checking inotify limit: {GetErrorMessage(ex)}");
			}

			foreach (MonitoredDirectory directory in directories)
			{
				FileSystemWatcher watcher = new FileSystemWatcher(directory.Path);
				watcher.Filters.Clear();
				foreach (string filter in directory.Filters)
					watcher.Filters.Add(filter);

				watcher.IncludeSubdirectories = directory.IncludeSubdirectories;
				NotifyFilters filters = 0;
				foreach (string directoryEvent in directory.Events)
					if (Enum.TryParse(directoryEvent, true, out NotifyFilters filter))
						filters |= filter;
					else
						ConsoleUtil.WriteLine($"Invalid event {directoryEvent}", ConsoleColor.Yellow);

				watcher.NotifyFilter = filters;

				watcher.Changed += OnFileChange;
				watcher.Created += OnFileChange;
				Watchers.Add(watcher);
				ConsoleUtil.WriteLine($"Setting up a watcher for {directory.Path}", ConsoleColor.Blue);
			}

			ConsoleUtil.WriteLine("Directory monitoring setup complete!", ConsoleColor.Green);

			while (true)
			{
				string line = ConsoleUtil.ReadLine();
				try
				{
					string[] command = line.Split(" ", StringSplitOptions.RemoveEmptyEntries);
					switch (command[0])
					{
						case "exit":
							{
								Exit();
								return;
							}
						case "stacktraces":
							{
								if (_showStacktraces)
								{
									_showStacktraces = false;
									ConsoleUtil.WriteLine("Disabled stacktraces", ConsoleColor.Blue);
								}
								else
								{
									_showStacktraces = true;
									ConsoleUtil.WriteLine("Enabled stacktraces", ConsoleColor.Blue);
								}
								break;
							}
						case "eicar":
							{
								const string eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
								ProcessFile(eicar, eicar);
								break;
							}
						case "scan":
							{
								if (command.Length < 2)
								{
									ConsoleUtil.WriteLine("You need to specify the desired file!", ConsoleColor.Yellow);
									break;
								}

								string cmd = command[1];
								if (string.IsNullOrWhiteSpace(cmd))
								{
									ConsoleUtil.WriteLine("Specified path is empty!", ConsoleColor.Yellow);
									break;
								}

								string path = Path.GetFullPath(cmd);
								if (!File.Exists(path))
								{
									ConsoleUtil.WriteLine($"File {path} does not exist!", ConsoleColor.Yellow);
									break;
								}

								ProcessFile(path);
								break;
							}
						case "scandirectory":
							{
								if (command.Length < 2)
								{
									ConsoleUtil.WriteLine("You need to specify the desired directory!",
										ConsoleColor.Yellow);
									break;
								}

								string cmd = command[1];
								if (string.IsNullOrWhiteSpace(cmd))
								{
									ConsoleUtil.WriteLine("Specified path is empty!", ConsoleColor.Yellow);
									break;
								}

								string path = Path.GetFullPath(cmd);
								if (!Directory.Exists(path))
								{
									ConsoleUtil.WriteLine($"Directory {path} does not exist!", ConsoleColor.Yellow);
									break;
								}

								string filter = "*";
								if (command.Length >= 3)
									filter = command[2];

								bool recursive = true;
								if (command.Length >= 4)
									recursive = bool.Parse(command[3]);

								ProcessDirectory(path, filter, recursive);
								break;
							}
						case "scanhash":
							{
								if (command.Length < 2)
								{
									ConsoleUtil.WriteLine("You need to specify a hash!", ConsoleColor.Yellow);
									break;
								}

								string hash = command[1];
								if (string.IsNullOrWhiteSpace(hash))
								{
									ConsoleUtil.WriteLine("Specified hash is empty!", ConsoleColor.Yellow);
									break;
								}

								ProcessFile(hash, hash);
								break;
							}
						case "scanprocesses":
							{
								string filter = ".*";
								if (command.Length >= 2)
									filter = command[1];

								Regex regex = new Regex(filter);

								bool scanSubmodules = false;
								if (command.Length >= 3)
									scanSubmodules = bool.Parse(command[2]);

								foreach (Process process in Process.GetProcesses())
									try
									{
										if (regex.IsMatch(process.ProcessName))
										{
											ProcessFile(process.MainModule.FileName);
											if (scanSubmodules)
												foreach (ProcessModule module in process.Modules)
													ProcessFile(module.FileName);
										}
									}
									catch (Exception ex)
									{
										ConsoleUtil.WriteLine($"Failed to scan {process.ProcessName}. Error: {GetErrorMessage(ex)}", ConsoleColor.Red);
									}
								break;
							}
						case "scanfilelink":
							{
								if (command.Length < 2)
								{
									ConsoleUtil.WriteLine("You need to specify the desired link!", ConsoleColor.Yellow);
									break;
								}

								string link = command[1];
								if (string.IsNullOrWhiteSpace(link))
								{
									ConsoleUtil.WriteLine("Specified link is empty!", ConsoleColor.Yellow);
									break;
								}

								ProcessFileLink(link);
								break;
							}
						default:
							{
								ConsoleUtil.WriteLine("Unknown command!", ConsoleColor.Yellow);
								break;
							}
					}
				}
				catch (Exception ex)
				{
					ConsoleUtil.WriteLine($"Error {GetErrorMessage(ex)} when executing {line}", ConsoleColor.Red);
				}
			}
		}

		private static async void ProcessFile(string path, string hash = null)
		{
			await CheckFile(path, hash);
		}

		private static async void ProcessFileLink(string path)
		{
			await CheckFileLink(path);
		}

		private static async void ProcessDirectory(string path, string filter, bool recursive)
		{
			await Task.WhenAll(Directory.EnumerateFiles(path, filter,
					recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly)
				.Select(file => CheckFile(file)));
			ConsoleUtil.WriteLine($"All files in {path} have been scanned", ConsoleColor.Blue);
		}

		private static async Task CheckFile(string path, string hash = null)
		{
			if (_exitting)
				return;

			try
			{
				PrintResult(path, hash == null ? await _client.CheckFile(path) : await _client.CheckHash(hash));
			}
			catch (RateLimitException rateLimitException)
			{
				// ReSharper disable once HeapView.BoxingAllocation
				ConsoleUtil.WriteLine($"Request for {path} exceeded the ratelimit, retrying in {ratelimitRetryDelay}ms",
					ConsoleColor.Yellow);
				await Task.Delay(ratelimitRetryDelay);
				await CheckFile(path, rateLimitException.Resource);
			}
			catch (Exception ex)
			{
				ConsoleUtil.WriteLine(
					ex.InnerException == null
						? GetErrorMessage(ex)
						: $"{GetErrorMessage(ex)}. Inner error: {GetErrorMessage(ex.InnerException)}",
					ConsoleColor.Red);
			}
		}


		private static async Task CheckFileLink(string link, string hash = null)
		{
			if (_exitting)
				return;

			try
			{
				PrintResult(link, hash == null ? await _client.CheckFileLink(link) : await _client.CheckHash(hash));
			}
			catch (RateLimitException rateLimitException)
			{
				// ReSharper disable once HeapView.BoxingAllocation
				ConsoleUtil.WriteLine($"Request for {link} exceeded the ratelimit, retrying in {ratelimitRetryDelay}ms",
					ConsoleColor.Yellow);
				await Task.Delay(ratelimitRetryDelay);
				await CheckFileLink(link, rateLimitException.Resource);
			}
			catch (Exception ex)
			{
				ConsoleUtil.WriteLine(
					ex.InnerException == null
						? GetErrorMessage(ex)
						: $"{GetErrorMessage(ex)}. Inner error: {GetErrorMessage(ex.InnerException)}",
					ConsoleColor.Red);
			}
		}
		private static void OnFileChange(object sender, FileSystemEventArgs e)
		{
			ProcessFile(Path.GetFullPath(e.FullPath));
		}

		private static void PrintResult(string name, VirusTotalReport report)
		{
			if (report.Available)
			{
				if (report.Positive == 0)
					ConsoleUtil.WriteLine(
						// ReSharper disable once HeapView.BoxingAllocation
						$"File {name} clean, last checked on {report.Date} by {report.Total} AVs\n{report.Link}",
						ConsoleColor.Green);
				else if (report.Positive / (float)report.Total < 0.1f)
				{
					// ReSharper disable HeapView.BoxingAllocation
					string message =
						$"File {name} detected by {report.Positive} out of {report.Total} AVs, last checked on {report.Date}\n{report.Link}";
					// ReSharper restore HeapView.BoxingAllocation
					ConsoleUtil.WriteLine(message, ConsoleColor.Yellow);
					MessageBox.Show(name, message, MessageBox.Type.Warning);
				}
				else
				{
					// ReSharper disable HeapView.BoxingAllocation
					string message =
						$"File {name} detected by {report.Positive} out of {report.Total} AVs, last checked on {report.Date}\n{report.Link}";
					// ReSharper restore HeapView.BoxingAllocation
					ConsoleUtil.WriteLine(message, ConsoleColor.Red);
					MessageBox.Show(name, message, MessageBox.Type.Error);
				}
			}
			else
				ConsoleUtil.WriteLine($"File {name} not present in the database, upload it manually",
					ConsoleColor.Blue);
		}

		internal static string GetErrorMessage(Exception ex) => _showStacktraces ? ex.ToString() : ex.Message;

		private static void Exit()
		{
			_exitting = true;
			foreach (FileSystemWatcher watcher in Watchers)
				watcher.Dispose();

			_client.Dispose();
			ConsoleUtil.ResetColor();
			Environment.Exit(0);
		}
	}
}
