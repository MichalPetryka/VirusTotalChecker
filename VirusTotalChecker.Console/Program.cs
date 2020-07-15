using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using Newtonsoft.Json;
using VirusTotalChecker.Configuration;
using VirusTotalChecker.Console.ExitHandlers;
using VirusTotalChecker.Utilities;

namespace VirusTotalChecker.Console
{
	internal static class Program
	{
		private static readonly List<FileSystemWatcher> Watchers = new List<FileSystemWatcher>();
		public static readonly List<IExitHandler> ExitHandlers = new List<IExitHandler>();
		private static DataProcessor _processor;
		public static volatile bool Exitting;
		private static Stream _logStream;

		private static void Main(string[] args)
		{
			bool logFile = true;
			if (args.Length > 2)
				logFile = bool.Parse(args[2]);
			LogCompressionType compressionType = LogCompressionType.Gzip;
			if (args.Length > 3)
				compressionType = Enum.Parse<LogCompressionType>(args[2], true);
			if (logFile)
				try
				{
					if (!Directory.Exists("logs"))
						Directory.CreateDirectory("logs");
					static FileStream GetLogFileStream(string extension)
						// ReSharper disable once HeapView.BoxingAllocation
						=> new FileStream($"logs/{DateTime.Now:HH-mm-ss_dd-MM-yyyy}.{extension}", FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite);
					_logStream = compressionType switch
					{
						LogCompressionType.None => GetLogFileStream("txt"),
						LogCompressionType.Gzip => new GZipStream(GetLogFileStream("txt.gz"), CompressionLevel.Optimal),
						LogCompressionType.Brotli => new BrotliStream(GetLogFileStream("txt.br"), CompressionLevel.Optimal),
						_ => throw new ArgumentOutOfRangeException()
					};
					ConsoleUtil.LogStream = new StreamWriter(_logStream);
				}
				catch (Exception ex)
				{
					ConsoleUtil.WriteLine($"Failed to create a log file! Error: {ExceptionFilter.GetErrorMessage(ex)}");
				}

			string apikey = args.Length > 0 ? args[0] : ConsoleUtil.ReadLineLock("Input your api key:");
			int apiVersion = 3;
			if (args.Length > 1)
				apiVersion = int.Parse(args[1]);
			_processor = new DataProcessor(new VirusTotalClient(apikey, apiVersion, HashType.Sha256, true, ConsoleUtil.LogHandler), 60000);
			const string configPath = "config.json";
			if (!File.Exists(configPath))
				using (FileStream fs = new FileStream(configPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
					using (StreamWriter sw = new StreamWriter(fs))
						sw.Write(JsonConvert.SerializeObject(new VirusTotalConfig { MonitoredDirectories = new List<MonitoredDirectory>() }, Formatting.Indented));

			VirusTotalConfig config;
			using (FileStream fs = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
				using (StreamReader sr = new StreamReader(fs))
					config = JsonConvert.DeserializeObject<VirusTotalConfig>(sr.ReadToEnd());
			CheckInotify(config.MonitoredDirectories.Count);

			foreach (MonitoredDirectory directory in config.MonitoredDirectories)
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
				watcher.EnableRaisingEvents = true;
				Watchers.Add(watcher);
				ConsoleUtil.WriteLine($"Setting up a watcher for {directory.Path}", ConsoleColor.Blue);
			}

			ConsoleUtil.WriteLine("Directory monitoring setup complete!", ConsoleColor.Green);
			SetupExitHandlers();

			CommandProcessor commandProcessor = new CommandProcessor(_processor);
			while (true)
			{
				string line = ConsoleUtil.ReadLine();
				if (string.IsNullOrWhiteSpace(line))
				{
					ConsoleUtil.WriteLine("Cannot execute an empty command!", ConsoleColor.Yellow);
					continue;
				}
				try
				{
					commandProcessor.ProcessCommand(line.Split(" ", StringSplitOptions.RemoveEmptyEntries));
				}
				catch (Exception ex)
				{
					ConsoleUtil.WriteLine($"Error {ExceptionFilter.GetErrorMessage(ex)} when executing {line}", ConsoleColor.Red);
				}
			}
			// exit command closes the program
			// ReSharper disable once FunctionNeverReturns
		}

		private static void SetupExitHandlers()
		{
			try
			{
				ExitHandlers.Add(ProcessExitHandler.Singleton);
				ExitHandlers.Add(AppDomainExitHandler.Singleton);
				ExitHandlers.Add(CancelKeyPressExitHandler.Singleton);
				ExitHandlers.Add(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? WindowsExitHandler.Singleton : UnixExitHandler.Singleton);

				foreach (IExitHandler exitHandler in ExitHandlers)
					exitHandler.Setup();
			}
			catch (Exception ex)
			{
				ConsoleUtil.WriteLine($"Failed to setup exit handlers! Error: {ExceptionFilter.GetErrorMessage(ex)}", ConsoleColor.Red);
			}
		}

		private static void CheckInotify(int watcherCount)
		{
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
						if (limit < 8192 + watcherCount)
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
				ConsoleUtil.WriteLine($"Error while checking inotify limit: {ExceptionFilter.GetErrorMessage(ex)}");
			}
		}

		private static void OnFileChange(object sender, FileSystemEventArgs e)
		{
			if ((File.GetAttributes(e.FullPath) & FileAttributes.Hidden) != FileAttributes.Hidden)
				_processor.ProcessFile(Path.GetFullPath(e.FullPath));
		}

		public static void Exit(int exitCode = 0)
		{
			if (Exitting)
				return;
			Exitting = true;
			foreach (FileSystemWatcher watcher in Watchers)
				watcher.Dispose();
			Watchers.Clear();

			_processor.Dispose();
			ConsoleUtil.Exit();
			_logStream.Dispose();
			Environment.Exit(exitCode);
		}
	}
}
