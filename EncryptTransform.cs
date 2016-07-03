
namespace System.Security.Cryptography
{
    internal sealed class EncryptTransform : ICryptoTransform
    {
        private BlockCipherAlgorithm _algorithm;
        private byte[] _iv;
        private PaddingMode _padding;
        private CipherMode _cipher;
        private bool _disposed;
        private int _biLast;

        public bool CanReuseTransform
        {
            get
            {
                if (this._disposed)
                    throw new ObjectDisposedException("ICryptoTransform");
                return true;
            }
        }
        public bool CanTransformMultipleBlocks
        {
            get
            {
                if (this._disposed)
                    throw new ObjectDisposedException("ICryptoTransform");
                return true;
            }
        }
        public int InputBlockSize
        {
            get
            {
                if (this._disposed)
                    throw new ObjectDisposedException("ICryptoTransform");
                return this._algorithm.BlockSize;
            }
        }
        public int OutputBlockSize
        {
            get
            {
                if (this._disposed)
                    throw new ObjectDisposedException("ICryptoTransform");
                return this._algorithm.BlockSize;
            }
        }

        internal EncryptTransform(BlockCipherAlgorithm algorithm, byte[] iv, CipherMode cipher, PaddingMode padding)
        {
            this._algorithm = algorithm;
            this._iv = iv;
            this._padding = padding;
            this._cipher = cipher;
            this._biLast = algorithm.BlockSize - 1;
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (this._disposed)
                throw new ObjectDisposedException("ICryptoTransform");
            if (this._cipher == CipherMode.CTS)
            {
                if (inputCount < this._algorithm.BlockSize) //Use OFB (offsize)
                {
                    byte[] iv = this._iv.Clone() as byte[];

                    this._algorithm.Encrypt(ref iv);
                    for (int i = 0; i < inputCount; i++)
                    {
                        outputBuffer[outputOffset] = (byte)(inputBuffer[inputOffset] ^ iv[i]);
                        outputOffset++;
                        inputOffset++;
                    }
                    return inputCount;
                }
                else
                {
                    int cipherCount = inputCount;
                    byte[] iv = this._iv.Clone() as byte[];
                    byte[] block = new byte[this._algorithm.BlockSize];

                    while (inputCount > this._algorithm.BlockSize << 1)
                    {
                        Array.Copy(inputBuffer, inputOffset, block, 0, this._algorithm.BlockSize);
                        inputCount -= this._algorithm.BlockSize;
                        inputOffset += this._algorithm.BlockSize;
                        this._algorithm.Encrypt(ref block, iv);
                        iv = block.Clone() as byte[];
                        Array.Copy(block, 0, outputBuffer, outputOffset, this._algorithm.BlockSize);
                        outputOffset += this._algorithm.BlockSize;
                    }

                    byte[] c3 = new byte[this._algorithm.BlockSize];
                    Array.Copy(inputBuffer, inputOffset, c3, 0, this._algorithm.BlockSize);
                    inputCount -= this._algorithm.BlockSize;
                    inputOffset += this._algorithm.BlockSize;
                    byte[] c4 = new byte[this._algorithm.BlockSize];
                    Array.Copy(inputBuffer, inputOffset, c4, 0, inputCount);

                    this._algorithm.Encrypt(ref c3, iv);
                    iv = c3.Clone() as byte[];
                    this._algorithm.Encrypt(ref c4, iv);

                    Array.Copy(c4, 0, outputBuffer, outputOffset, this._algorithm.BlockSize);
                    outputOffset += this._algorithm.BlockSize;
                    Array.Copy(c3, 0, outputBuffer, outputOffset, inputCount);
                    return cipherCount;
                }
            }
            byte[] lastBlock = new byte[this._algorithm.BlockSize];
            byte pad = (byte)(this._algorithm.BlockSize - (inputCount & this._biLast));
            switch (this._padding)
            {
                case PaddingMode.ANSIX923:
                    for (int i = inputCount & this._biLast; i < this._biLast; i++)
                        lastBlock[i] = 0;
                    lastBlock[this._biLast] = pad;
                    break;
                case PaddingMode.ISO10126:
                    RandomGenerator.GenerateBytes(lastBlock, inputCount & this._biLast, pad - 1);
                    lastBlock[this._biLast] = pad;
                    break;
                case PaddingMode.None:
                    break;
                case PaddingMode.PKCS7:
                    for (int i = inputCount & this._biLast; i < this._algorithm.BlockSize; i++)
                        lastBlock[i] = pad;
                    break;
                case PaddingMode.Zeros:
                    break;
            }

            if (this._cipher == CipherMode.CBC)
            {
                byte[] iv = this._iv.Clone() as byte[];
                byte[] block = new byte[this._algorithm.BlockSize];
                int blockCount = ((inputCount / this._algorithm.BlockSize) + 1);

                while (inputCount > this._biLast)
                {
                    Array.Copy(inputBuffer, inputOffset, block, 0, this._algorithm.BlockSize);
                    inputCount -= this._algorithm.BlockSize;
                    inputOffset += this._algorithm.BlockSize;
                    this._algorithm.Encrypt(ref block, iv);
                    iv = block.Clone() as byte[];
                    Array.Copy(block, 0, outputBuffer, outputOffset, this._algorithm.BlockSize);
                    outputOffset += this._algorithm.BlockSize;
                }
                Array.Copy(inputBuffer, inputOffset, lastBlock, 0, inputCount);
                this._algorithm.Encrypt(ref lastBlock, iv);
                Array.Copy(lastBlock, 0, outputBuffer, outputOffset, this._algorithm.BlockSize);
                return blockCount * this._algorithm.BlockSize;
            }
            else if (this._cipher == CipherMode.ECB)
            {
                byte[] block = new byte[this._algorithm.BlockSize];
                int blockCount = ((inputCount / this._algorithm.BlockSize) + 1);

                while (inputCount > this._biLast)
                {
                    Array.Copy(inputBuffer, inputOffset, block, 0, this._algorithm.BlockSize);
                    inputCount -= this._algorithm.BlockSize;
                    inputOffset += this._algorithm.BlockSize;
                    this._algorithm.Encrypt(ref block);
                    Array.Copy(block, 0, outputBuffer, outputOffset, this._algorithm.BlockSize);
                    outputOffset += this._algorithm.BlockSize;
                }
                Array.Copy(inputBuffer, inputOffset, lastBlock, 0, inputCount);
                this._algorithm.Encrypt(ref lastBlock);
                Array.Copy(lastBlock, 0, outputBuffer, outputOffset, this._algorithm.BlockSize);
                return blockCount * this._algorithm.BlockSize;
            }
            else if (this._cipher == CipherMode.OFB)
            {
                int blockCount = ((inputCount / this._algorithm.BlockSize) + 1);
                byte[] iv = this._iv.Clone() as byte[];

                while (inputCount > this._biLast)
                {
                    this._algorithm.Encrypt(ref iv);
                    for (int i = 0; i < this._algorithm.BlockSize; i++)
                    {
                        outputBuffer[outputOffset] = (byte)(inputBuffer[inputOffset] ^ iv[i]);
                        outputOffset++;
                        inputOffset++;
                    }
                    inputCount -= this._algorithm.BlockSize;
                }
                this._algorithm.Encrypt(ref iv);
                Array.Copy(inputBuffer, inputOffset, lastBlock, 0, inputCount);
                for (int i = 0; i < this._algorithm.BlockSize; i++)
                {
                    outputBuffer[outputOffset] = (byte)(lastBlock[i] ^ iv[i]);
                    outputOffset++;
                }
                return blockCount * this._algorithm.BlockSize;
            }
            else if (this._cipher == CipherMode.CFB)
            {
                int blockCount = ((inputCount / this._algorithm.BlockSize) + 1);
                byte[] iv = this._iv.Clone() as byte[];

                while (inputCount > this._biLast)
                {
                    this._algorithm.Encrypt(ref iv);
                    for (int i = 0; i < this._algorithm.BlockSize; i++)
                    {
                        outputBuffer[outputOffset] = (byte)(inputBuffer[inputOffset] ^ iv[i]);
                        iv[i] = outputBuffer[outputOffset];
                        outputOffset++;
                        inputOffset++;
                    }
                    inputCount -= this._algorithm.BlockSize;
                }
                this._algorithm.Encrypt(ref iv);
                Array.Copy(inputBuffer, inputOffset, lastBlock, 0, inputCount);
                for (int i = 0; i < this._algorithm.BlockSize; i++)
                {
                    outputBuffer[outputOffset] = (byte)(lastBlock[i] ^ iv[i]);
                    outputOffset++;
                }
                return blockCount * this._algorithm.BlockSize;
            }
            else
                throw new CryptographicException("Unknown cipher mode.");
        }
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (this._disposed)
                throw new ObjectDisposedException("ICryptoTransform");
            if (this._cipher == CipherMode.CTS)
            {
                byte[] output = new byte[inputCount];
                this.TransformBlock(inputBuffer, inputOffset, inputCount, output, 0);
                return output;
            }
            else
            {
                int blockCount = inputCount / this._algorithm.BlockSize + 1;
                byte[] temp = new byte[blockCount * this._algorithm.BlockSize];
                int final = this.TransformBlock(inputBuffer, inputOffset, inputCount, temp, 0);
                byte[] block = new byte[final];
                Array.Copy(temp, block, final);
                return block;
            }
        }
        public void Dispose()
        {
            if (this._disposed)
                throw new ObjectDisposedException("ICryptoTransform");
            this._disposed = true;
            this._iv = null;
            this._algorithm = null;
        }

    }
}
