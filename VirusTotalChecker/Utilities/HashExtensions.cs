using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace VirusTotalChecker.Utilities
{
	public static class HashExtensions
	{
		public static Task<byte[]> ComputeHashAsync(this HashAlgorithm hash, Stream stream)
		{
			return Task.Run(() => hash.ComputeHash(stream));
		}
	}
}