using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using Joveler.Compression.XZ;
using VirusTotalChecker.Logging;
using VirusTotalChecker.Utilities;
using SystemConsole = System.Console;

namespace VirusTotalChecker.Console
{
	public static class ConsoleUtil
	{
		private static readonly object WriteLock = new object();
		private static readonly bool NoColor = Environment.GetEnvironmentVariable("NO_COLOR") != null;

		public static readonly ILogHandler LogHandler = new ConsoleLogHandler();

		public static bool LogTime;

		private static StreamWriter _logStream;

		public static void SetLogFile(bool enabled, LogCompressionType compressionType)
		{
			lock (WriteLock)
			{
				_logStream?.Flush();
				_logStream?.Dispose();
				if (!enabled)
					return;
				try
				{
					string logDirectory = Program.DataPath + @"\logs";
					if (!Directory.Exists(logDirectory))
						Directory.CreateDirectory(logDirectory);
					// ReSharper disable once HeapView.BoxingAllocation
					string logPath = $@"{Program.DataPath}\logs\{DateTime.Now:yyyy-MM-dd_HH-mm-ss}.{compressionType switch
					{
						LogCompressionType.None => "txt",
						LogCompressionType.Gzip => "txt.gz",
						LogCompressionType.Xz => "txt.xz",
						LogCompressionType.Brotli => "txt.br",
						// ReSharper disable once HeapView.BoxingAllocation
						_ => throw new ArgumentOutOfRangeException(nameof(compressionType), compressionType, null)
					}}";

					static FileStream GetLogFileStream(string logPath)
						=> new FileStream(logPath, FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite);

					XzHelper.LogHandler = LogHandler;

					Stream logStream = compressionType switch
					{
						LogCompressionType.None => GetLogFileStream(logPath),
						LogCompressionType.Gzip => new GZipStream(GetLogFileStream(logPath), CompressionLevel.Optimal),
						LogCompressionType.Xz => XzHelper.GetXzStream(GetLogFileStream(logPath),
							new XZCompressOptions { Level = LzmaCompLevel.Level9 },
							new XZThreadedCompressOptions { Threads = Environment.ProcessorCount }),
						LogCompressionType.Brotli => new BrotliStream(GetLogFileStream(logPath), CompressionLevel.Optimal),
						// ReSharper disable once HeapView.BoxingAllocation
						_ => throw new ArgumentOutOfRangeException(nameof(compressionType), compressionType, null)
					};

					_logStream = new StreamWriter(logStream, Encoding.UTF8, leaveOpen: false);
					WriteLineNoLock($"Logging output to: {logPath}", ConsoleColor.Blue);
				}
				catch (Exception ex)
				{
					WriteLineNoLock($"Failed to create a log file! Error: {ExceptionFilter.GetErrorMessage(ex)}", ConsoleColor.Red);
				}
			}
		}

		public static string ReadLine()
		{
			return SystemConsole.ReadLine();
		}

		public static string ReadLineLock(string message)
		{
			lock (WriteLock)
			{
				WriteLineNoLock(message, ConsoleColor.Blue);
				return ReadLine();
			}
		}

		public static void WriteLine(string message, ConsoleColor? color = null)
		{
			lock (WriteLock)
				WriteLineNoLock(message, color);
		}

		public static void WriteLine(params (string message, ConsoleColor? color)[] lines)
		{
			lock (WriteLock)
				foreach ((string message, ConsoleColor? color) in lines)
					WriteLineNoLock(message, color);
		}

		private static void WriteLineNoLock(string message, ConsoleColor? color)
		{
			if (LogTime)
				// ReSharper disable once HeapView.BoxingAllocation
				message = $"[{DateTime.Now}] {message}";
			try
			{
				if (color != null && !NoColor)
					SystemConsole.ForegroundColor = color.Value;
			}
			catch
			{
				SystemConsole.ResetColor();
			}

			SystemConsole.WriteLine(message);
			_logStream?.WriteLine(message);

			SystemConsole.ResetColor();
		}

		internal static void Exit()
		{
			lock (WriteLock)
			{
				SystemConsole.ResetColor();
				WriteLineNoLock("Exitting...", ConsoleColor.Blue);
				_logStream?.Flush();
				_logStream?.Dispose();
				_logStream = null;
				SystemConsole.ResetColor();
			}
		}

		private class ConsoleLogHandler : ILogHandler
		{
			public void Log(string message, LogType logType = LogType.Info)
			{
				ConsoleColor? color = logType switch
				{
					LogType.Debug => null,
					LogType.Info => ConsoleColor.Blue,
					LogType.Warning => ConsoleColor.Yellow,
					LogType.Error => ConsoleColor.Red,
					// ReSharper disable once HeapView.BoxingAllocation
					_ => throw new ArgumentOutOfRangeException(nameof(logType), logType, null)
				};
				WriteLine(message, color);
			}
		}
	}
}
