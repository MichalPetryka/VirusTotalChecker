namespace VirusTotalChecker.Configuration
{
	public class MonitoredDirectory
	{
		public string Path { get; set; }
		public string[] Filters { get; set; }
		public bool IncludeSubdirectories { get; set; }
		public string[] Events { get; set; }
	}
}
