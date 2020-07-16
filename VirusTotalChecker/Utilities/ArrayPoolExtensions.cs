using System;
using System.Buffers;

namespace VirusTotalChecker.Utilities
{
	public static class ArrayPoolExtensions
	{
		public static T[] Rent<T>(this ArrayPool<T> pool, int count, bool initialize)
		{
			T[] array = pool.Rent(count);
			if (initialize)
				Array.Clear(array, 0, array.Length);
			return array;
		}

		public static ArraySegment<T> RentSegment<T>(this ArrayPool<T> pool, int count, out T[] array, bool initialize = false)
		{
			array = pool.Rent(count);
			if (initialize)
				Array.Clear(array, 0, count);
			return new ArraySegment<T>(array, 0, count);
		}
	}
}
