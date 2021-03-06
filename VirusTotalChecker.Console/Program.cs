﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using Newtonsoft.Json;
using VirusTotalChecker.Configuration;
using VirusTotalChecker.Console.ExitHandlers;
using VirusTotalChecker.Utilities;

namespace VirusTotalChecker.Console
{
	internal static class Program
	{
		private static readonly object ExitLock = new object();
		private static readonly List<FileSystemWatcher> Watchers = new List<FileSystemWatcher>();
		private static readonly List<IExitHandler> ExitHandlers = new List<IExitHandler>();

		public static readonly string DataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\VirusTotalChecker";
		public static volatile bool Exitting;

		private static DataProcessor _processor;

		private static void Main()
		{
			if (!Directory.Exists(DataPath))
				Directory.CreateDirectory(DataPath);
			string configPath = DataPath + @"\config.json";
			if (!File.Exists(configPath))
				using (FileStream fs = new FileStream(configPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
					using (StreamWriter sw = new StreamWriter(fs))
						sw.Write(JsonConvert.SerializeObject(new VirusTotalConfig(), Formatting.Indented));

			ConsoleUtil.WriteLine($"Reading config from {configPath}", ConsoleColor.Blue);
			string configText;
			using (FileStream fs = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
				using (StreamReader sr = new StreamReader(fs))
					configText = sr.ReadToEnd();
			VirusTotalConfig config = JsonConvert.DeserializeObject<VirusTotalConfig>(configText);

			ConsoleUtil.LogTime = config.LogTime;
			ExceptionFilter.ShowStacktraces = config.DebugSettings.ShowStacktraces;
			ConsoleUtil.SetLogFile(config.LogFile, config.LogCompression);
			MessageBox.Enabled = config.ShowDialogs;
			MessageBox.ForceSdl = config.DebugSettings.ForceSdl;

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
			ConsoleUtil.WriteLine("API key sucessfully obtained!", ConsoleColor.Blue);

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
			SetupExitHandlers(config.DebugSettings.LogExit);

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
					ConsoleUtil.WriteLine($"Error {ex.GetErrorMessage()} when executing {line}", ConsoleColor.Red);
				}
			}
			// exit command closes the program
			// ReSharper disable once FunctionNeverReturns
		}

		private static void SetupExitHandlers(bool logExit)
		{
			try
			{
				ExitHandlers.Add(ProcessExitHandler.Singleton);
				ExitHandlers.Add(AppDomainExitHandler.Singleton);
				ExitHandlers.Add(CancelKeyPressExitHandler.Singleton);
				ExitHandlers.Add(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? WindowsExitHandler.Singleton : UnixExitHandler.Singleton);

				foreach (IExitHandler exitHandler in ExitHandlers)
				{
					exitHandler.LogExit = logExit;
					exitHandler.Setup();
				}
			}
			catch (Exception ex)
			{
				ConsoleUtil.WriteLine($"Failed to setup exit handlers! Error: {ex.GetErrorMessage()}", ConsoleColor.Red);
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
				ConsoleUtil.WriteLine($"Error while checking inotify limit: {ex.GetErrorMessage()}");
			}
		}

		private static void OnFileChange(object sender, FileSystemEventArgs e)
		{
			if ((File.GetAttributes(e.FullPath) & FileAttributes.Hidden) != FileAttributes.Hidden)
				_processor.ProcessFile(Path.GetFullPath(e.FullPath));
		}

		public static void Exit(int exitCode = 0)
		{
			lock (ExitLock)
			{
				if (Exitting)
					return;
				Exitting = true;
				foreach (FileSystemWatcher watcher in Watchers)
					watcher.Dispose();
				Watchers.Clear();
				ExitHandlers.Clear();

				_processor.Dispose();
				ConsoleUtil.Exit();
			}
			Environment.Exit(exitCode);
		}
	}
}
