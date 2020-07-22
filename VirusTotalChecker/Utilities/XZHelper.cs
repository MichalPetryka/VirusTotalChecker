using System;
using System.IO;
using System.Runtime.InteropServices;
using Joveler.Compression.XZ;
using VirusTotalChecker.Logging;

namespace VirusTotalChecker.Utilities
{
	public static class XzHelper
	{
		private static bool _loaded;
		public static ILogHandler LogHandler;

		private static void InitNativeLibrary()
		{
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
		}

		public static Stream GetXzStream(Stream stream, XZCompressOptions compressOptions, XZThreadedCompressOptions threadedCompressOptions)
		{
			if (!_loaded)
				InitNativeLibrary();
			return new XZStream(stream, compressOptions, threadedCompressOptions);
		}
	}
}
