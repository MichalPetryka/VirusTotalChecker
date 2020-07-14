using System;
using VirusTotalChecker.Logging;
using SystemConsole = System.Console;

namespace VirusTotalChecker.Console
{
	public static class ConsoleUtil
	{
		private static readonly object WriteLock = new object();
		private static readonly bool NoColor = Environment.GetEnvironmentVariable("NO_COLOR") != null;
		public static readonly ILogHandler LogHandler = new ConsoleLogHandler();

		public static string ReadLine()
		{
			return SystemConsole.ReadLine();
		}

		public static string ReadLineLock(string message = "Input your command and press enter to unlock output:")
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
			SystemConsole.ResetColor();
		}

		internal static void Exit()
		{
			lock (WriteLock)
			{
				SystemConsole.ResetColor();
				WriteLineNoLock("Exitting...", ConsoleColor.Blue);
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
