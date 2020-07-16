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
			Assert.Equal(text, PasswordHelpers.DecryptString(PasswordHelpers.EncryptString(text, key), key));
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
