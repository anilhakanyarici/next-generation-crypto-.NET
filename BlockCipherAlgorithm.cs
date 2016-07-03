
namespace System.Security.Cryptography
{
    internal abstract class BlockCipherAlgorithm
    {
        internal int BlockSize { get; private set; }

        internal BlockCipherAlgorithm(int blockSizeBytes)
        {
            this.BlockSize = blockSizeBytes;
        }

        internal abstract void Encrypt(ref byte[] block);
        internal virtual void Encrypt(ref byte[] block, byte[] iv)
        {
            if (iv.Length != this.BlockSize)
                throw new ArgumentException("Invalid IV size.");
            if (block.Length != this.BlockSize)
                throw new ArgumentException("Invalid block size.");

            for (int i = 0; i < this.BlockSize; i++)
                block[i] ^= iv[i];
            this.Encrypt(ref block);
        }
        internal abstract void Decrypt(ref byte[] block);
        internal virtual void Decrypt(ref byte[] block, byte[] iv)
        {
            if (iv.Length != this.BlockSize)
                throw new ArgumentException("Invalid IV size.");
            if (block.Length != this.BlockSize)
                throw new ArgumentException("Invalid block size.");

            this.Decrypt(ref block);
            for (int i = 0; i < this.BlockSize; i++)
                block[i] ^= iv[i];
        }
    }
}
