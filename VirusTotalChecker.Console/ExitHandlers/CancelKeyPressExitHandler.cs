using System;

namespace VirusTotalChecker.Console.ExitHandlers
{
	internal class CancelKeyPressExitHandler : IExitHandler
	{
		public static readonly IExitHandler Singleton = new CancelKeyPressExitHandler();

		public bool LogExit { get; set; }

		public void Setup()
		{
			System.Console.CancelKeyPress += OnCancelKeyPress;
		}

		private static void OnCancelKeyPress(object sender, ConsoleCancelEventArgs args)
		{
			if (!args.Cancel)
			{
				if (Singleton.LogExit)
					// ReSharper disable once HeapView.BoxingAllocation
					ConsoleUtil.WriteLine($"Cancel Key Press detected! Type: {args.SpecialKey}", ConsoleColor.Blue);
				Program.Exit();
			}
		}
	}
}
