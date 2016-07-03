using System.Text;

namespace System.Security.Cryptography
{
    public sealed class RandomGenerator : RandomNumberGenerator, IDisposable
    {
        private static RandomGenerator _staticGenerator = new RandomGenerator(Guid.NewGuid().ToString());

        public static byte[] GenerateBytes(int length)
        {
            if (RandomGenerator._staticGenerator == null)
            {
                byte[] random = new byte[32];
                new Random().NextBytes(random);
                RandomGenerator._staticGenerator = new RandomGenerator(Encoding.ASCII.GetString(random));
            }
            return RandomGenerator._staticGenerator.GetBytes(length);
        }
        public static void GenerateBytes(byte[] buffer, int offset, int count)
        {
            byte[] rnd = RandomGenerator.GenerateBytes(count);
            Array.Copy(rnd, 0, buffer, offset, count);
        }
        public static byte[] GenerateNonZeroBytes(int length)
        {
            byte[] temp = RandomGenerator._staticGenerator._keyDeriver.GetBytes(length);
            for (int i = 0; i < length; i++)
            {
                while (temp[i] == 0)
                    temp[i] = RandomGenerator._staticGenerator._keyDeriver.GetBytes(1)[0];
            }
            return temp;
        }
        public static string GenerateString(int length)
        {
            if (RandomGenerator._staticGenerator == null)
            {
                byte[] random = new byte[32];
                new Random().NextBytes(random);
                RandomGenerator._staticGenerator = new RandomGenerator(Encoding.ASCII.GetString(random));
            }
            return Encoding.UTF8.GetString(RandomGenerator._staticGenerator.GetBytes(length));
        }

        private DRBytesGenerator _keyDeriver;

        public RandomGenerator()
        {
            if (RandomGenerator._staticGenerator == null)
            {
                byte[] random = new byte[32];
                new Random().NextBytes(random);
                RandomGenerator._staticGenerator = new RandomGenerator(Encoding.ASCII.GetString(random));
            }

            this._keyDeriver = new DRBytesGenerator(RandomGenerator._staticGenerator.GetBytes(32));
        }
        public RandomGenerator(string seedString)
        {
            this._keyDeriver = new DRBytesGenerator(seedString);
        }
        public RandomGenerator(byte[] seedBytes)
        {
            this._keyDeriver = new DRBytesGenerator(seedBytes);
        }

        public override void GetBytes(byte[] data)
        {
            byte[] temp = this._keyDeriver.GetBytes(data.Length);
            for (int i = 0; i < data.Length; i++)
                data[i] = temp[i];

        }
        public override void GetNonZeroBytes(byte[] data)
        {
            byte[] temp = this._keyDeriver.GetBytes(data.Length);
            for (int i = 0; i < data.Length; i++)
            {
                while (temp[i] == 0)
                    temp[i] = this._keyDeriver.GetBytes(1)[0];
                data[i] = temp[i];
            }
        }
        public byte[] GetBytes(int length)
        {
            return this._keyDeriver.GetBytes(length);
        }
        public byte[] GetNonZeroBytes(int length)
        {
            byte[] temp = this._keyDeriver.GetBytes(length);
            for (int i = 0; i < length; i++)
            {
                while (temp[i] == 0)
                    temp[i] = this._keyDeriver.GetBytes(1)[0];
            }
            return temp;
        }
        public short GetInt16()
        {
            return BitConverter.ToInt16(this._keyDeriver.GetBytes(2), 0);
        }
        public short GetInt16(short max)
        {
            return this.GetInt16(0, max);
        }
        public short GetInt16(short min, short max)
        {
            short value = Math.Abs(this.GetInt16());
            return (short)((value % (max - min)) + min);
        }
        public ushort GetUInt16()
        {
            return BitConverter.ToUInt16(this._keyDeriver.GetBytes(2), 0);
        }
        public ushort GetUInt16(ushort max)
        {
            return this.GetUInt16(0, max);
        }
        public ushort GetUInt16(ushort min, ushort max)
        {
            short value = Math.Abs(this.GetInt16());
            return (ushort)((value % (max - min)) + min);
        }
        public int GetInt32()
        {
            return BitConverter.ToInt32(this._keyDeriver.GetBytes(4), 0);
        }
        public int GetInt32(int max)
        {
            return this.GetInt32(0, max);
        }
        public int GetInt32(int min, int max)
        {
            int value = Math.Abs(this.GetInt32());
            return (value % (max - min)) + min;
        }
        public uint GetUInt32()
        {
            return BitConverter.ToUInt32(this._keyDeriver.GetBytes(4), 0);
        }
        public uint GetUInt32(uint max)
        {
            return this.GetUInt32(0, max);
        }
        public uint GetUInt32(uint min, uint max)
        {
            uint value = this.GetUInt32();
            return (value % (max - min)) + min;
        }
        public long GetInt64()
        {
            return BitConverter.ToInt64(this._keyDeriver.GetBytes(8), 0);
        }
        public long GetInt64(long max)
        {
            return this.GetInt64(0L, max);
        }
        public long GetInt64(long min, long max)
        {
            long value = Math.Abs(this.GetInt64());
            return (value % (max - min)) + min;
        }
        public ulong GetUInt64()
        {
            return BitConverter.ToUInt64(this._keyDeriver.GetBytes(8), 0);
        }
        public ulong GetUInt64(ulong max)
        {
            return this.GetUInt64(0L, max);
        }
        public ulong GetUInt64(ulong min, ulong max)
        {
            ulong value = this.GetUInt64();
            return (value % (max - min)) + min;
        }
        public float GetSingle()
        {
            return BitConverter.ToSingle(this._keyDeriver.GetBytes(4), 0);
        }
        public float GetSingle(float max)
        {
            return this.GetSingle(0f, max);
        }
        public float GetSingle(float min, float max)
        {
            float value = Math.Abs(this.GetSingle());
            return (value % (max - min)) + min;
        }
        public double GetDouble()
        {
            return BitConverter.ToDouble(this._keyDeriver.GetBytes(8), 0);
        }
        public double GetDouble(double max)
        {
            return this.GetDouble(0.0, max);
        }
        public double GetDouble(double min, double max)
        {
            double value = Math.Abs(this.GetDouble());
            return (value % (max - min)) + min;
        }
        public char[] GetChars(int length)
        {
            byte[] bits = this._keyDeriver.GetBytes(length);
            return Encoding.ASCII.GetChars(bits);
        }
        public char[] GetChars(int length, bool en_usCharSet)
        {
            if (en_usCharSet)
                return this.GetChars(length, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToCharArray());
            else
                return this.GetChars(length);
        }
        public char[] GetChars(int length, char[] charSet)
        {
            char[] chars = new char[length];
            for (int i = 0; i < length; i++)
                chars[i] = charSet[this.GetInt32(charSet.Length)];
            return chars;
        }
        public string GetString(int length)
        {
            byte[] bits = this._keyDeriver.GetBytes(length);
            return Encoding.ASCII.GetString(bits);
        }
        public string GetString(int length, bool en_usCharSet)
        {
            if (en_usCharSet)
                return this.GetString(length, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToCharArray());
            else
                return this.GetString(length);
        }
        public string GetString(int length, char[] charSet)
        {
            char[] chars = this.GetChars(length, charSet);
            return new string(chars);
        }
#pragma warning disable 108
#pragma warning disable 109
        public new void Dispose()
        {
            this._keyDeriver.Dispose();
        }
#pragma warning restore 108
#pragma warning restore 109
    }
}
