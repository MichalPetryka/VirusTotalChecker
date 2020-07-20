using System.Collections.Generic;
using System.ComponentModel;
using Newtonsoft.Json;
using VirusTotalChecker.Console;
using VirusTotalChecker.Utilities;

namespace VirusTotalChecker.Configuration
{
	public class VirusTotalConfig
	{
		public string EncryptedApiKey { get; set; }
		[DefaultValue(3)]
		public int ApiVersion { get; set; } = 3;
		[DefaultValue(true)]
		public bool ShowDialogs { get; set; } = true;
		[DefaultValue(false)]
		public bool ForceSdl { get; set; } = false;
		[DefaultValue(true)]
		public bool LogTime { get; set; } = true;
		[DefaultValue(true)]
		public bool LogFile { get; set; } = true;
		[DefaultValue(LogCompressionType.Gzip)]
		[JsonConverter(typeof(StringEnumIgnoreCaseConverter))]
		public LogCompressionType LogCompression { get; set; } = LogCompressionType.Gzip;
		public List<MonitoredDirectory> MonitoredDirectories { get; set; } = new List<MonitoredDirectory>();
	}
}
