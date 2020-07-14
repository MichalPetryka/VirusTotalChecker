using System;
using System.Collections.Generic;
using System.IO;
using VirusTotalChecker.Configuration;
using VirusTotalChecker.Utilities;

namespace VirusTotalChecker.Console
{
	internal static class Program
	{
		private static readonly List<FileSystemWatcher> Watchers = new List<FileSystemWatcher>();
		private static DataProcessor _processor;
		public static volatile bool Exitting;

		private static void Main(string[] args)
		{
			string apikey = args.Length > 0 ? args[0] : ConsoleUtil.ReadLineLock("Input your api key:");
			int apiVersion = 3;
			if (args.Length > 1)
				apiVersion = int.Parse(args[1]);
			_processor = new DataProcessor(new VirusTotalClient(apikey, apiVersion, HashType.Sha256, true, ConsoleUtil.LogHandler), 60000);
			MonitoredDirectory[] directories = new MonitoredDirectory[0];
			CheckInotify(directories.Length);

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
			AppDomain.CurrentDomain.ProcessExit += (sender, arg) => Exit();

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
			Environment.Exit(exitCode);
		}
	}
}
