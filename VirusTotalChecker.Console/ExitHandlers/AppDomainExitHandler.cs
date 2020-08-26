using System;
using VirusTotalChecker.Utilities;

namespace VirusTotalChecker.Console.ExitHandlers
{
	internal class AppDomainExitHandler : IExitHandler
	{
		public static readonly IExitHandler Singleton = new AppDomainExitHandler();

		public bool LogExit { get; set; }

		public void Setup()
		{
			AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
			AppDomain.CurrentDomain.DomainUnload += OnDomandUnload;
			AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
		}

		private static void OnProcessExit(object sender, EventArgs e)
		{
			if (Singleton.LogExit)
				ConsoleUtil.WriteLine("AppDomain Process Exit detected!", ConsoleColor.Blue);
			Program.Exit();
		}

		private static void OnDomandUnload(object sender, EventArgs e)
		{
			if (Singleton.LogExit)
				ConsoleUtil.WriteLine("AppDomain Domain Unload detected!", ConsoleColor.Blue);
			Program.Exit();
		}

		private static void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
		{
			if (e.IsTerminating)
			{
				if (Singleton.LogExit)
					ConsoleUtil.WriteLine("AppDomain unhandled exception detected!", ConsoleColor.Blue);
				int exitCode = -1;
				if (e.ExceptionObject is Exception ex)
				{
					ConsoleUtil.WriteLine($"Unhandled Exception: {ex.GetErrorMessage()}", ConsoleColor.Red);
					if (ex.HResult != 0)
						exitCode = ex.HResult;
				}
				else
					ConsoleUtil.WriteLine("Unhandled Exception!", ConsoleColor.Red);

				Program.Exit(exitCode);
			}
		}
	}
}
