using System;
using System.Buffers;
using VirusTotalChecker.Utilities;
using Xunit;

namespace VirusTotalChecker.Tests
{
	public class ArrayPoolExtensionsTests
	{
		[Theory]
		[InlineData(0)]
		[InlineData(100)]
		public void RentInitializeTest(int count)
		{
			byte[] array = ArrayPool<byte>.Shared.Rent(count, true);
			for (int i = 0; i < array.Length; i++)
				Assert.Equal(0, array[i]);
			ArrayPool<byte>.Shared.Return(array);
		}

		[Theory]
		[InlineData(0)]
		[InlineData(100)]
		public void RentSegmentInitializeTest(int count)
		{
			ArraySegment<byte> buffer = ArrayPool<byte>.Shared.RentSegment(count, out byte[] array, true);
			Assert.Equal(count, buffer.Count);
			for (int i = buffer.Offset; i < buffer.Offset + buffer.Count; i++)
				Assert.Equal(0, buffer.Array![i]);
			ArrayPool<byte>.Shared.Return(array);
		}
	}
}
