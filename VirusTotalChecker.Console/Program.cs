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
		public static readonly string DataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\VirusTotalChecker";
		public static volatile bool Exitting;

		private static DataProcessor _processor;
		private static Stream _logStream;

		private static void Main()
		{
			if (!Directory.Exists(DataPath))
				Directory.CreateDirectory(DataPath);
			string configPath = DataPath + @"\config.json";
			if (!File.Exists(configPath))
				using (FileStream fs = new FileStream(configPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
					using (StreamWriter sw = new StreamWriter(fs))
						sw.Write(JsonConvert.SerializeObject(new VirusTotalConfig(), Formatting.Indented));

			string configText;
			using (FileStream fs = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
				using (StreamReader sr = new StreamReader(fs))
					configText = sr.ReadToEnd();
			VirusTotalConfig config = JsonConvert.DeserializeObject<VirusTotalConfig>(configText);

			ConsoleUtil.LogTime = config.LogTime;
			if (config.LogFile)
				try
				{
					string logPath = DataPath + @"\logs";
					if (!Directory.Exists(logPath))
						Directory.CreateDirectory(logPath);
					static FileStream GetLogFileStream(string logPath, string extension)
						// ReSharper disable once HeapView.BoxingAllocation
						=> new FileStream($"{logPath}\\{DateTime.Now:yyyy-MM-dd_HH-mm-ss}.{extension}", FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite);
					_logStream = config.LogCompression switch
					{
						LogCompressionType.None => GetLogFileStream(logPath, "txt"),
						LogCompressionType.Gzip => new GZipStream(GetLogFileStream(logPath, "txt.gz"), CompressionLevel.Optimal),
						LogCompressionType.Brotli => new BrotliStream(GetLogFileStream(logPath, "txt.br"), CompressionLevel.Optimal),
						_ => throw new ArgumentOutOfRangeException()
					};
					ConsoleUtil.LogStream = new StreamWriter(_logStream);
				}
				catch (Exception ex)
				{
					ConsoleUtil.WriteLine($"Failed to create a log file! Error: {ExceptionFilter.GetErrorMessage(ex)}");
				}
			MessageBox.Enabled = config.ShowDialogs;
			MessageBox.ForceSdl = config.ForceSdl;

			string apiKey;
			if (string.IsNullOrWhiteSpace(config.EncryptedApiKey))
			{
				apiKey = ConsoleUtil.ReadLineLock("Input your api key:");
				while (string.IsNullOrWhiteSpace(apiKey))
					apiKey = ConsoleUtil.ReadLineLock("Invalid api key, please try again:");
				string password = ConsoleUtil.ReadLineLock("Input your password:");
				while (!PasswordHelpers.IsValid(password, out string message))
					password = ConsoleUtil.ReadLineLock($"Invalid password: {message}, please try again:");
				config.EncryptedApiKey = PasswordHelpers.Encrypt(apiKey, password);
			}
			else
			{
				string password = ConsoleUtil.ReadLineLock("Input your password:");
				while (!PasswordHelpers.Decrypt(config.EncryptedApiKey, password, out apiKey))
					password = ConsoleUtil.ReadLineLock("Invalid password, please try again:");
			}

			string newConfigText = JsonConvert.SerializeObject(config, Formatting.Indented);
			if (configText != newConfigText)
				using (FileStream fs = new FileStream(configPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.Read))
					using (StreamWriter sw = new StreamWriter(fs))
						sw.Write(newConfigText);

			_processor = new DataProcessor(new VirusTotalClient(apiKey, config.ApiVersion, HashType.Sha256, true, ConsoleUtil.LogHandler), 60000);

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
