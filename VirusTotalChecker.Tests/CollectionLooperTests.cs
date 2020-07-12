using VirusTotalChecker.Utilities;
using Xunit;

namespace VirusTotalChecker.Tests
{
	public class CollectionLooperTests
	{
		[Theory]
		[InlineData(new[] { 1, 2, 3, 4, 5 })]
		public void GetTest(int[] array)
		{
			CollectionLooper<int> looper = new CollectionLooper<int>(array);
			for (int i = 0; i < array.Length * 3; i++)
			{
				Assert.NotEqual(0, looper.Get());
			}
		}
	}
}