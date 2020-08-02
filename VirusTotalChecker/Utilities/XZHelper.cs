using System;
using System.IO;
using System.Runtime.InteropServices;
using Joveler.Compression.XZ;
using VirusTotalChecker.Logging;

namespace VirusTotalChecker.Utilities
{
	public static class XzHelper
	{
		private static readonly object LoadLock = new object();
		private static bool _loaded;

		public static ILogHandler LogHandler;

		private static void InitNativeLibrary()
		{
			lock (LoadLock)
			{
				if (_loaded)
					return;
				string libPath = null;
				if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
					libPath = "liblzma.dll";
				else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
					libPath = "liblzma.so";
				else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
					libPath = "liblzma.dylib";

				try
				{
					XZInit.GlobalInit(libPath);
					_loaded = true;
				}
				catch (Exception ex)
				{
					LogHandler.Log(ExceptionFilter.GetErrorMessage(ex), LogType.Error);
					XZInit.GlobalInit();
					_loaded = true;
				}
				LogHandler.Log($"XZ {XZInit.VersionString()} has been loaded");
			}
		}

		public static Stream GetXzStream(Stream stream, XZCompressOptions compressOptions, XZThreadedCompressOptions threadedCompressOptions)
		{
			InitNativeLibrary();
			return new XZStream(stream, compressOptions, threadedCompressOptions);
		}
	}
}
