using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
using VirusTotalChecker.Utilities;

namespace VirusTotalChecker.Console
{
	public static class MessageBox
	{
		private const string WindowsDll = "User32";
		private const string SdlDll = "SDL2";

		public static bool Enabled = true;
		public static bool ForceSdl = false;
		private static bool _sdlLoaded;

		[DllImport(WindowsDll, EntryPoint = "MessageBoxW", CharSet = CharSet.Unicode, SetLastError = true)]
		private static extern int MessageBoxWindows(IntPtr hwnd, string message, string title, uint flags);

		[DllImport(SdlDll, EntryPoint = "SDL_ShowSimpleMessageBox")]
		private static extern int MessageBoxSdl(uint flags, [MarshalAs(UnmanagedType.LPUTF8Str)] string title,
			[MarshalAs(UnmanagedType.LPUTF8Str)] string message, IntPtr parent);

		[DllImport(SdlDll, EntryPoint = "SDL_GetError")]
		[return: MarshalAs(UnmanagedType.LPUTF8Str)]
		private static extern string SdlGetError();

		[DllImport(SdlDll, EntryPoint = "SDL_GetVersion")]
		private static extern void SdlGetVersion(out SdlVersion version);

		[StructLayout(LayoutKind.Sequential)]
		private readonly struct SdlVersion
		{
			// those are only assigned from the dllimport, ignore the warning
			public readonly byte Major;
			public readonly byte Minor;
			public readonly byte Patch;
		}

		private static bool LoadSdl()
		{
			try
			{
				SdlGetVersion(out SdlVersion version);
				// ReSharper disable HeapView.BoxingAllocation
				ConsoleUtil.WriteLine($"Loaded SDL2 version: {version.Major}.{version.Minor}.{version.Patch}",
					ConsoleColor.Blue);
				// ReSharper restore HeapView.BoxingAllocation
				_sdlLoaded = true;
			}
			catch (DllNotFoundException)
			{
				ConsoleUtil.WriteLine(
					"On platforms other than Windows SDL2 is required for Message Boxes, install it with your distributions package manager",
					ConsoleColor.Yellow);
				Enabled = false;
			}
			catch (Exception ex)
			{
				ConsoleUtil.WriteLine($"Error when loading SDL2: {ExceptionFilter.GetErrorMessage(ex)}", ConsoleColor.Red);
				Enabled = false;
			}

			return Enabled;
		}

		public static void Show(string title, string message, Type type = Type.Info)
		{
			if (!Enabled)
				return;

			void ShowDialog()
			{
				try
				{
					if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && !ForceSdl)
					{
						uint flags = type switch
						{
							Type.Info => 0x00000000 | 0x00000040 | 0x00040000,
							Type.Warning => 0x00000000 | 0x00000030 | 0x00040000 | 0x00001000 | 0x00010000,
							Type.Error => 0x00000000 | 0x00000010 | 0x00040000 | 0x00001000 | 0x00010000,
							// ReSharper disable once HeapView.BoxingAllocation
							_ => throw new ArgumentOutOfRangeException(nameof(type), type, "Invalid MessageBox type")
						};
						if (MessageBoxWindows(IntPtr.Zero, message, title, flags) == 0)
							throw new Win32Exception();
						return;
					}

					if (!_sdlLoaded && !LoadSdl())
						return;

					uint sdlflags = type switch
					{
						Type.Info => 0x00000040,
						Type.Warning => 0x00000020,
						Type.Error => 0x00000010,
						// ReSharper disable once HeapView.BoxingAllocation
						_ => throw new ArgumentOutOfRangeException(nameof(type), type, "Invalid MessageBox type")
					};
					if (MessageBoxSdl(sdlflags, title, message, IntPtr.Zero) != 0)
						throw new Exception(SdlGetError());
				}
				catch (Exception ex)
				{
					ConsoleUtil.WriteLine($"MessageBox creation failed: {ExceptionFilter.GetErrorMessage(ex)}",
						ConsoleColor.Red);
				}
			}

			new Thread(ShowDialog) { IsBackground = true, Priority = ThreadPriority.BelowNormal }.Start();
		}

		public enum Type
		{
			Info,
			Warning,
			Error
		}
	}
}
