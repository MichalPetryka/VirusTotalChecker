using System.Collections.Generic;

namespace VirusTotalChecker.Utilities
{
	public class CollectionLooper<T>
	{
		private readonly IReadOnlyList<T> _collection;
		private int _index;

		public CollectionLooper(IReadOnlyList<T> collection)
		{
			_collection = collection;
			_index = 0;
		}

		public T Get()
		{
			if (_index >= _collection.Count)
				_index = 0;

			return _collection[_index++];
		}
	}
}
