using System;
using System.Threading;
using Mono.Unix;
using Mono.Unix.Native;

namespace VirusTotalChecker.Console.ExitHandlers
{
	internal class UnixExitHandler : IExitHandler
	{
		public static readonly IExitHandler Singleton = new UnixExitHandler();

		private static readonly UnixSignal[] Signals = {
			new UnixSignal(Signum.SIGINT),  // CTRL + C
			new UnixSignal(Signum.SIGTERM), // Sending KILL
			new UnixSignal(Signum.SIGUSR1),
			new UnixSignal(Signum.SIGUSR2),
			new UnixSignal(Signum.SIGHUP)   // Terminal is closed
		};

		public bool LogExit { get; set; }

		public void Setup()
		{
			new Thread(ProcessExit) {IsBackground = true}.Start();
		}

		private static void ProcessExit()
		{
			// Blocking operation with infinite expectation of any signal
			int index = UnixSignal.WaitAny(Signals, -1);
			if (Singleton.LogExit)
				// ReSharper disable once HeapView.BoxingAllocation
				ConsoleUtil.WriteLine($"Unix Signal Exit detected! Signal: {Signals[index].Signum}", ConsoleColor.Blue);
			Program.Exit();
		}
	}
}
