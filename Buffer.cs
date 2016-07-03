
namespace System.Security.Cryptography
{
    internal static class Buffer
    {
        internal static byte[] PieceOf(byte[] buffer, int offset, int count)
        {
            if (count > buffer.Length - offset)
                count = buffer.Length - offset;
            byte[] temp = new byte[count];
            Array.Copy(buffer, offset, temp, 0, count);
            return temp;
        }
        internal static bool IsEquals(byte[] array1, byte[] array2)
        {
            if (array1 == null || array2 == null)
                return false;

            if (array1.Length != array2.Length)
                return false;

            for (int i = 0; i < array1.Length; i++)
            {
                if (array1[i] != array2[i])
                    return false;
            }
            return true;
        }
        internal static byte[] Concat(byte[] array1, byte[] array2)
        {
            if (array2.Length == 0)
                return array1.Clone() as byte[];
            if (array1.Length == 0)
                return array2.Clone() as byte[];
            byte[] concat = new byte[array1.Length + array2.Length];
            Array.Copy(array1, 0, concat, 0, array1.Length);
            Array.Copy(array2, 0, concat, array1.Length, array2.Length);
            return concat;
        }
        internal static void ReverseCopy(byte[] sourceArray, int sourceIndex, byte[] destinationArray, int destinationIndex, int length)
        {
            if (length + sourceIndex > sourceArray.Length)
                throw new IndexOutOfRangeException();
            if (destinationIndex - length < -1)
                throw new IndexOutOfRangeException();
            if (length < 0)
                throw new IndexOutOfRangeException();
            if (sourceIndex < 0)
                throw new IndexOutOfRangeException();
            if (length > sourceArray.Length || length > destinationArray.Length)
                throw new IndexOutOfRangeException();
            if (length == 0)
                return;

            int lastSrc = sourceIndex + length;
            for (int i = sourceIndex; i < lastSrc; i++)
                destinationArray[destinationIndex--] = sourceArray[i];

        }
    }
}
