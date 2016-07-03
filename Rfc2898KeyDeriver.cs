
namespace System.Security.Cryptography
{
    public enum DerivationFunction { PBKDF1, PBKDF2 }
    public class Rfc2898KeyDeriver : DeriveBytes, IDisposable
    {
        private byte[] _buffer;
        private byte[] _salt;
        private HMACSHA1 _hmac;
        private byte[] _password;
        private uint _iterations;
        private uint _block;
        private int _startIndex;
        private int _endIndex;
        private DerivationFunction _derFunc;

        public int IterationCount
        {
            get
            {
                return (int)this._iterations;
            }
            set
            {
                if (value <= 0)
                {
                    throw new ArgumentOutOfRangeException("value", "IterationCount must be positive.");
                }
                this._iterations = (uint)value;
                this.Reset();
            }
        }
        public ulong Salt
        {
            get
            {
                return BitConverter.ToUInt64(this._salt, 0);
            }
            set
            {
                this._salt = BitConverter.GetBytes(value);
                this.Reset();
            }
        }


        public Rfc2898KeyDeriver(byte[] password, ulong salt, int iterations, DerivationFunction function)
        {
            this.Salt = salt;
            this.IterationCount = iterations;
            this._password = password;
            this._hmac = new HMACSHA1(password);
            this._derFunc = function;
            this.Reset();
        }

        public override byte[] GetBytes(int cb)
        {
            if (cb < 0)
                throw new ArgumentOutOfRangeException("cb", "cb must be positive.");
            if (cb == 0)
                return new byte[0];
            byte[] array = new byte[cb];
            int i = 0;
            int num = this._endIndex - this._startIndex;
            if (num > 0)
            {
                if (cb < num)
                {
                    Array.Copy(this._buffer, this._startIndex, array, 0, cb);
                    this._startIndex += cb;
                    return array;
                }
                Array.Copy(this._buffer, this._startIndex, array, 0, num);
                this._startIndex = (this._endIndex = 0);
                i += num;
            }
            while (i < cb)
            {
                byte[] src = this.deriveBlock();
                int num2 = cb - i;
                if (num2 <= 20)
                {
                    Array.Copy(src, 0, array, i, num2);
                    i += num2;
                    Array.Copy(src, num2, this._buffer, this._startIndex, 20 - num2);
                    this._endIndex += 20 - num2;
                    return array;
                }
                Array.Copy(src, 0, array, i, 20);
                i += 20;
            }
            return array;
        }
        public override void Reset()
        {
            if (this._buffer != null)
            {
                Array.Clear(this._buffer, 0, this._buffer.Length);
            }
            this._buffer = new byte[20];
            this._block = 1u;
            this._startIndex = (this._endIndex = 0);
        }
        public void Dispose()
        {
            if (this._hmac != null)
            {
                ((IDisposable)this._hmac).Dispose();
            }
            if (this._buffer != null)
            {
                Array.Clear(this._buffer, 0, this._buffer.Length);
            }
            if (this._salt != null)
            {
                Array.Clear(this._salt, 0, this._salt.Length);
            }
        }
        private byte[] deriveBlock()
        {
            byte[] array = BitConverter.GetBytes(this._block);
            Array.Reverse(array);
            this._hmac.TransformBlock(this._salt, 0, this._salt.Length, null, 0);
            this._hmac.TransformBlock(array, 0, array.Length, null, 0);
            this._hmac.TransformFinalBlock(new byte[0], 0, 0);
            byte[] hashValue = this._hmac.Hash;
            this._hmac.Initialize();
            byte[] array2 = hashValue;
            int num = 2;
            if (this._derFunc == DerivationFunction.PBKDF1)
            {
                while ((long)num <= (long)((ulong)this._iterations))
                {
                    this._hmac.TransformBlock(hashValue, 0, hashValue.Length, null, 0);
                    this._hmac.TransformFinalBlock(array2, 0, 20);
                    hashValue = this._hmac.Hash;
                    array2 = hashValue;
                    this._hmac.Initialize();
                    num++;
                }
            }
            else if (this._derFunc == DerivationFunction.PBKDF2)
            {
                while ((long)num <= (long)((ulong)this._iterations))
                {
                    this._hmac.TransformBlock(hashValue, 0, hashValue.Length, null, 0);
                    this._hmac.TransformFinalBlock(new byte[0], 0, 0);
                    hashValue = this._hmac.Hash;
                    for (int i = 0; i < 20; i++)
                    {
                        array2[i] ^= hashValue[i];
                    }
                    this._hmac.Initialize();
                    num++;
                }
            }
            this._block += 1u;
            return array2;
        }
    }
}
