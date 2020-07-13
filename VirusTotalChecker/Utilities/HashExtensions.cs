using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace VirusTotalChecker.Utilities
{
	public static class HashExtensions
	{
		public static Task<byte[]> ComputeHashAsync(this HashAlgorithm hash, Stream stream)
		{
			byte[] Function() => hash.ComputeHash(stream);
			return Task.Run(Function);
		}
	}
}
