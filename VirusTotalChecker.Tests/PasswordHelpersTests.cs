using System.Buffers;
using System.Text;
using VirusTotalChecker.Utilities;
using Xunit;

namespace VirusTotalChecker.Tests
{
	public class PasswordHelpersTests
	{
		[Theory]
		[InlineData("", "qwert test ąć@$%")]
		[InlineData("qwert test ąć@$%", "qwert test ąć@$%")]
		[InlineData("qwert test ąć@$%", "")]
		public void EncryptionTest(string text, string password)
		{
			Assert.True(PasswordHelpers.Decrypt(PasswordHelpers.Encrypt(text, password, out string keyHash), password, keyHash, out string result));
			Assert.Equal(text, result);
		}

		[Theory]
		[InlineData("", "qwert test ąć@$%", "fgdgfdfg")]
		[InlineData("qwert test ąć@$%", "qwert test ąć@$%", "")]
		[InlineData("qwert test ąć@$%", "", "gfdsdfh")]
		public void InvalidPasswordTest(string text, string encryptionPassword, string decryptionPassword)
		{
			Assert.False(PasswordHelpers.Decrypt(PasswordHelpers.Encrypt(text, encryptionPassword, out string keyHash), decryptionPassword, keyHash, out string result));
			Assert.NotEqual(text, result);
		}

		[Theory]
		[InlineData("")]
		[InlineData("qwert test ąć@$%")]
		public void GetPooledBytesTest(string text)
		{
			Assert.Equal(text, Encoding.UTF8.GetString(Encoding.UTF8.GetPooledBytes(text, out byte[] array)));
			ArrayPool<byte>.Shared.Return(array);
		}
	}
}
