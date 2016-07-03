using System.Text;

namespace System.Security.Cryptography
{
    public class DRBytesGenerator : DeriveBytes, IDisposable
    {
        private int _position;
        private HashAlgorithm _hashAlg;
        private bool _disposed;
        private byte[] _seedMaterial;
        private byte[] _currentSeed;
        private int _entropy;
        private DeriveBytes _entropyDeriver;

        public DRBytesGenerator()
        {
            byte[] seedMaterial = new byte[64];
            if (seedMaterial.Length != 0)
                new Random().NextBytes(seedMaterial);
            this.ctor(seedMaterial, 0);
        }
        public DRBytesGenerator(string seedMaterial)
        {
            byte[] keyBits = ASCIIEncoding.UTF8.GetBytes(seedMaterial);
            this.ctor(keyBits, 0);
        }
        public DRBytesGenerator(byte[] seedMaterial)
        {
            this.ctor(seedMaterial, 0);
        }
        public DRBytesGenerator(string seedMaterial, int entropy)
        {
            byte[] keyBits = ASCIIEncoding.UTF8.GetBytes(seedMaterial);
            this.ctor(keyBits, entropy);
        }
        public DRBytesGenerator(byte[] seedMaterial, int entropy)
        {
            this.ctor(seedMaterial, entropy);
        }

        private void ctor(byte[] seedMaterial, int entropy)
        {
            if (seedMaterial.Length > 255)
                throw new ArgumentException("Length of key is longer than 255.", "seedMaterial");
            if (entropy < 0)
                throw new ArgumentException("Entropy cannot be smaller than zero.", "entropy");

            this._entropyDeriver = new Rfc2898KeyDeriver(new Guid().ToByteArray(), (ulong)(new Random().Next()), 1, DerivationFunction.PBKDF1);
            this._entropy = (entropy + 7) >> 3;
            byte[] entropyBytes = this._entropyDeriver.GetBytes(this._entropy);
            this._seedMaterial = seedMaterial;
            this._hashAlg = SHA512.Create();
            this._currentSeed = DRBytesGenerator.instantiateSeed(seedMaterial, entropyBytes, null, this._hashAlg);
        }

        public override byte[] GetBytes(int cb)
        {
            if (this._disposed)
                throw new ObjectDisposedException("DRBytesGenerator");

            if (cb == 0)
                return new byte[0];
            if (cb < 0)
                throw new ArgumentException("cb cannot be smaller than 0.");

            byte[] cbBytes = new byte[cb];
            int readable = 64 - this._position;

            if (readable >= cb)
            {
                Array.Copy(this._hashAlg.Hash, this._position, cbBytes, 0, cb);
                this._position += cb;
                return cbBytes;
            }
            else
            {
                if (readable == 0)
                {
                    if (this._entropy == 0)
                    {
                        this._hashAlg.ComputeHash(this._hashAlg.Hash);
                    }
                    else
                    {
                        byte[] entropyBytes = this._entropyDeriver.GetBytes(this._entropy);
                        this._hashAlg.ComputeHash(System.Security.Cryptography.Buffer.Concat(this._hashAlg.Hash, entropyBytes));
                    }
                    readable = 64;
                    this._position = 0;
                }
                if (readable >= cb)
                {
                    Array.Copy(this._hashAlg.Hash, this._position, cbBytes, 0, cb);
                    this._position += cb;
                    return cbBytes;
                }
                Array.Copy(this._hashAlg.Hash, this._position, cbBytes, 0, readable);
                cb -= readable;
                int cbOffset = readable;
                this._position = 0;

                if (this._entropy == 0)
                {
                    this._hashAlg.ComputeHash(this._hashAlg.Hash);
                }
                else
                {
                    byte[] entropyBytes = this._entropyDeriver.GetBytes(this._entropy);
                    this._hashAlg.ComputeHash(System.Security.Cryptography.Buffer.Concat(this._hashAlg.Hash, entropyBytes));
                }

                while (cb > 63)
                {
                    Array.Copy(this._hashAlg.Hash, 0, cbBytes, cbOffset, 64);
                    cb -= 64;
                    cbOffset += 64;
                    if (this._entropy == 0)
                    {
                        this._hashAlg.ComputeHash(this._hashAlg.Hash);
                    }
                    else
                    {
                        byte[] entropyBytes = this._entropyDeriver.GetBytes(this._entropy);
                        this._hashAlg.ComputeHash(System.Security.Cryptography.Buffer.Concat(this._hashAlg.Hash, entropyBytes));
                    }
                }
                if (cb > 0)
                {
                    Array.Copy(this._hashAlg.Hash, 0, cbBytes, cbOffset, cb);
                    this._position += cb;
                }
                return cbBytes;
            }
        }
        public string GetBase64String(int cb)
        {
            byte[] cbBytes = this.GetBytes(cb);
            return Convert.ToBase64String(cbBytes);
        }
        public void Reseed(byte[] additionalInput)
        {
            if (this._disposed)
                throw new ObjectDisposedException("DRBytesGenerator");
            byte[] entropyBytes = new byte[this._entropy];
            if (entropyBytes.Length != 0)
                new Random().NextBytes(entropyBytes);
            this._currentSeed = DRBytesGenerator.reseed(this._currentSeed, entropyBytes, additionalInput, this._hashAlg);
            this._position = 0;
            DRBytesGenerator.generateRandomBlock(this._currentSeed, null, this._hashAlg);
        }
        public override void Reset()
        {
            if (this._disposed)
                throw new ObjectDisposedException("DRBytesGenerator");
            byte[] entropyBytes = new byte[this._entropy];
            if (entropyBytes.Length != 0)
                new Random().NextBytes(entropyBytes);
            this._currentSeed = DRBytesGenerator.instantiateSeed(this._seedMaterial, entropyBytes, null, this._hashAlg);
            this._position = 0;
        }

#pragma warning disable 108
#pragma warning disable 109
        public new void Dispose()
        {
            if (this._disposed)
                throw new ObjectDisposedException("DRBGKeyDeriver");
            this._disposed = true;
            this._seedMaterial = null;
            this._currentSeed = null;
        }
#pragma warning restore 108
#pragma warning restore 109

        private static byte[] instantiateSeed(byte[] seedMaterial, byte[] entropy, byte[] personalBytes, HashAlgorithm hash)
        {
            byte[] concat = new byte[seedMaterial.Length + entropy.Length + (personalBytes == null ? 0 : personalBytes.Length)];
            Array.Copy(seedMaterial, 0, concat, 0, seedMaterial.Length);
            Array.Copy(entropy, 0, concat, seedMaterial.Length, entropy.Length);
            if (personalBytes != null)
                Array.Copy(personalBytes, 0, concat, entropy.Length + seedMaterial.Length, personalBytes.Length);

            byte[] seed = hash.ComputeHash(concat);
            return seed;
        }
        private static byte[] reseed(byte[] seed, byte[] entropy, byte[] additionalInput, HashAlgorithm hash)
        {
            byte[] concat = new byte[seed.Length + entropy.Length + (additionalInput == null ? 0 : additionalInput.Length) + 1];
            concat[0] = 0x01;
            Array.Copy(seed, 0, concat, 1, seed.Length);
            Array.Copy(entropy, 0, concat, seed.Length + 1, entropy.Length);
            if (additionalInput != null)
                Array.Copy(additionalInput, 0, concat, entropy.Length + seed.Length + 1, additionalInput.Length);
            return hash.ComputeHash(concat);
        }
        private static byte[] generateRandomBlock(byte[] seed, byte[] additionalInput, HashAlgorithm hash)
        {
            byte[] concat = new byte[seed.Length + (additionalInput == null ? 0 : additionalInput.Length)];
            Array.Copy(seed, 0, concat, 1, seed.Length);
            if (additionalInput != null)
                Array.Copy(additionalInput, 0, concat, seed.Length, additionalInput.Length);
            return hash.ComputeHash(concat);
        }
    }
}
