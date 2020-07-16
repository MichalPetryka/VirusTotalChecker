using VirusTotalChecker.Utilities;
using Xunit;

namespace VirusTotalChecker.Tests
{
	public class PasswordHelpersTests
	{
		[Theory]
		[InlineData("", "qwert test ąć@$%")]
		[InlineData("qwert test ąć@$%", "qwert test ąć@$%")]
		public void EncryptionTest(string text, string key)
		{
			Assert.Equal(text, PasswordHelpers.Decrypt(PasswordHelpers.Encrypt(text, key), key));
		}

		[Theory]
		[InlineData("", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")]
		[InlineData("qwert test ąć@$%", "1E39C6CBCB4FEE56D0DFA60FB934A3724DAB99207AB841AED38935ADC33ECA8B")]
		public void Sha256Test(string text, string hash)
		{
			Assert.Equal(hash, PasswordHelpers.GetSha256Bytes(text).ToHexString());
		}

		[Theory]
		[InlineData("", "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E")]
		[InlineData("qwert test ąć@$%", "D03BAB1FBAC0CCEDEA1CE5DA13BF9428D02D1F24621FD5F32C1174C8E21DD6E7E688D2589E3AB426D7C65F466C0633D6535A2B75F9F019BC066ADB00F9143CFA")]
		public void Sha512Test(string text, string hash)
		{
			Assert.Equal(hash, PasswordHelpers.GetSha512(text));
		}
	}
}
