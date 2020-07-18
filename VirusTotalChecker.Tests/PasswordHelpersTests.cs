using System.Buffers;
using System.Text;
using VirusTotalChecker.Utilities;
using Xunit;
using Xunit.Abstractions;

namespace VirusTotalChecker.Tests
{
	public class PasswordHelpersTests
	{
		private readonly ITestOutputHelper _output;
		public PasswordHelpersTests(ITestOutputHelper output) => _output = output;

		[Theory]
		[InlineData(null, false)]
		[InlineData("", false)]
		[InlineData("qwert testąć7@$%", false)]
		[InlineData("qwerttestąć@$%", false)]
		[InlineData("777777@$%", false)]
		[InlineData("qwerttestąć", false)]
		[InlineData("qwertte\0stąć5@$%", false)]
		[InlineData("qwerttestąć5@$%", true)]
		public void PasswordCheckTest(string password, bool valid)
		{
			Assert.Equal(valid, PasswordHelpers.IsValid(password, out string message));
			if (valid)
				Assert.Null(message);
			else
			{
				Assert.NotNull(message);
				Assert.NotEqual("", message);
				_output.WriteLine(message);
			}
		}

		[Theory]
		[InlineData("", "qwert test ąć@$%")]
		[InlineData("qwert test ąć@$%", "qwert test ąć@$%")]
		[InlineData("qwert te\0st ąć@$%", "qwert test ąć\0@$%")]
		[InlineData("qwert test ąć@$%", "")]
		public void EncryptionTest(string text, string password)
		{
			string encrypt = PasswordHelpers.Encrypt(text, password);
			_output.WriteLine(text);
			_output.WriteLine(password);
			_output.WriteLine(encrypt);
			Assert.NotEqual(string.Empty, encrypt);
			Assert.True(PasswordHelpers.Decrypt(encrypt, password, out string result));
			Assert.Equal(text, result);
		}

		[Theory]
		[InlineData("", "qwert test ąć@$%", "yc+u/QtUzdG/BJNIKIKChCSq2uCKzWo+BIvh/eTVv+s2b4BgniqrgnWwOztVuDA6HK8R59NxoWsCcevTH2S5FCGqfXB8aDI2GLcZ+BGAEES4fKCfBFFGjKd/yw/vJsvYocKM9Y8URrddOHXDhHu9G9Df//+uB77Ou7xLyA==")]
		[InlineData("qwert test ąć@$%", "qwert test ąć@$%", "IdE5uMMnX+9wVyABmJem5oJi0NY7SXwKgSda673FIHl7Ty89KTd1vCdOEg/vOssqURetbHROYxw9ceclohKd6ymyqNRca8cZZ0zLIvVrW9zV4ebPeI1T5L1IfsKtvR02ZM5HBbsMyJ+qu2/2S5PNccrD1QtFck/bi/xaKTViE82WLkuhV9vePZwZV/PuFQ==")]
		[InlineData("qwert test ąć@$%", "", "TzEo9TvamfAu1A/p818IFaxabhosNXJUkbKIBN0JDEmay1K/yBvrkdpFv3WJI2OfYlq3rBrAiwl16MKIxWWuVbL+UaAGsZeKFCLzZPV8irJnf+xQyh9mMOqyyYNy+TEUl4DBAcj1DzFJ43VlPq+dELHQHEmDDMK63O64rwlq045oGJOzAO/6qC4STlV18A==")]
		public void BinaryCompatibilityTest(string text, string password, string encrypted)
		{
			Assert.True(PasswordHelpers.Decrypt(encrypted, password, out string result));
			Assert.Equal(text, result);
		}

		[Theory]
		[InlineData("", "qwert test ąć@$%", "fgdgfdfg")]
		[InlineData("qwert test ąć@$%", "qwert test ąć@$%", "")]
		[InlineData("qwert test ąć@$%", "qwert test ąć@$%", "QWERT test ąć@$%")]
		[InlineData("qwert test ąć@$%", "", "gfdsdfh")]
		public void InvalidPasswordTest(string text, string encryptionPassword, string decryptionPassword)
		{
			Assert.False(PasswordHelpers.Decrypt(PasswordHelpers.Encrypt(text, encryptionPassword), decryptionPassword, out string result));
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
