using System;
using System.Diagnostics;

namespace VirusTotalChecker.Console.ExitHandlers
{
	internal class ProcessExitHandler : IExitHandler
	{
		public static readonly IExitHandler Singleton = new ProcessExitHandler();

		public bool LogExit { get; set; }

		public void Setup()
		{
			Process process = Process.GetCurrentProcess();
			process.Exited += OnExit;
			process.EnableRaisingEvents = true;
		}

		private static void OnExit(object sender, EventArgs e)
		{
			if (Singleton.LogExit)
				ConsoleUtil.WriteLine("GetCurrentProcess Exit detected!", ConsoleColor.Blue);
			Program.Exit();
		}
	}
}
