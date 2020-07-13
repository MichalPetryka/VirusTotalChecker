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

		public static void WriteLine(string message, ConsoleColor? color = null)
		{
			lock (WriteLock)
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
		}

		internal static void ResetColor()
		{
			lock (WriteLock)
				SystemConsole.ResetColor();
		}

		private class ConsoleLogHandler : ILogHandler
		{
			public void Log(string message, LogType logType = LogType.Info)
			{
				switch (logType)
				{
					case LogType.Debug:
						WriteLine(message);
						break;
					case LogType.Info:
						WriteLine(message, ConsoleColor.Blue);
						break;
					case LogType.Warning:
						WriteLine(message, ConsoleColor.Yellow);
						break;
					case LogType.Error:
						WriteLine(message, ConsoleColor.Red);
						break;
					default:
						// ReSharper disable once HeapView.BoxingAllocation
						throw new ArgumentOutOfRangeException(nameof(logType), logType, null);
				}
			}
		}
	}
}
