using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using VirusTotalChecker.Utilities;
using Xunit;

namespace VirusTotalChecker.Tests
{
	public class HashExtensionsTests
	{
		[Fact]
		public async Task ComputeHashAsyncTest()
		{
			using (SHA256 hash = SHA256.Create())
			{
				byte[] bytes = new byte[500];
				new Random().NextBytes(bytes);
				await using (MemoryStream fs = new MemoryStream(bytes))
				{
					fs.Position = 0;
					byte[] sha1 = hash.ComputeHash(fs);
					fs.Position = 0;
					byte[] sha2 = await hash.ComputeHashAsync(fs);
					Assert.True(sha1.SequenceEqual(sha2));
				}
			}
		}
	}
}