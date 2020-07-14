using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace VirusTotalChecker.Console.ExitHandlers
{
	internal class WindowsExitHandler : IExitHandler
	{
		public static readonly IExitHandler Singleton = new WindowsExitHandler();

		private static readonly HandlerRoutine Routine = OnNativeSignal;

		public bool LogExit { get; set; }

		public void Setup()
		{
			if (!SetConsoleCtrlHandler(Routine, true))
				throw new Win32Exception();
		}

		private static bool OnNativeSignal(CtrlTypes type)
		{
			if (Singleton.LogExit)
				// ReSharper disable once HeapView.BoxingAllocation
				ConsoleUtil.WriteLine($"Windows Console Ctrl detected! Type: {type}", ConsoleColor.Blue);
			Program.Exit();
			return true;
		}

		[DllImport("Kernel32", SetLastError = true)]
		private static extern bool SetConsoleCtrlHandler(HandlerRoutine handler, bool add);

		[UnmanagedFunctionPointer(CallingConvention.Winapi)]
		private delegate bool HandlerRoutine(CtrlTypes ctrlType);

		// ReSharper disable UnusedMember.Local
		private enum CtrlTypes : uint
		{
			CtrlC = 0,
			CtrlBreak = 1,
			CtrlClose = 2,
			CtrlLogoff = 5,
			CtrlShutdown = 6
		}
		// ReSharper restore UnusedMember.Local
	}
}
