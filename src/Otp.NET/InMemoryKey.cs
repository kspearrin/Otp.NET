/*
Credits to Devin Martin and the original OtpSharp library:
https://bitbucket.org/devinmartin/otp-sharp/overview 

Copyright (C) 2012 Devin Martin

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

using System;
using System.Security.Cryptography;

namespace OtpNet
{
    /// <summary>
    /// Represents a key in memory
    /// </summary>
    /// <remarks>
    /// This will attempt to use the Windows data protection api to encrypt the key in memory.
    /// However, this type favors working over memory protection. This is an attempt to minimize
    /// exposure in memory, nothing more. This protection is flawed in many ways and is limited
    /// to Windows.
    /// 
    /// In order to use the key to compute an hmac it must be temporarily decrypted, used,
    /// then re-encrypted. This does expose the key in memory for a time. If a memory dump occurs in this time
    /// the plaintext key will be part of it. Furthermore, there are potentially
    /// artifacts from the hmac computation, GC compaction, or any number of other leaks even after
    /// the key is re-encrypted.
    /// 
    /// This type favors working over memory protection. If the particular platform isn't supported then,
    /// unless forced by modifying the IsPlatformSupported method, it will just store the key in a standard
    /// byte array.
    /// </remarks>
    public class InMemoryKey : IKeyProvider
    {
        static readonly object platformSupportSync = new object();

        readonly object stateSync = new object();
        readonly byte[] KeyData;
        readonly int keyLength;

        /// <summary>
        /// Creates an instance of a key.
        /// </summary>
        /// <param name="key">Plaintext key data</param>
        public InMemoryKey(byte[] key)
        {
            if(!(key != null))
                throw new ArgumentNullException("key");
            if(!(key.Length > 0))
                throw new ArgumentException("The key must not be empty");

            this.keyLength = key.Length;
            int paddedKeyLength = (int)Math.Ceiling((decimal)key.Length / (decimal)16) * 16;
            this.KeyData = new byte[paddedKeyLength];
            Array.Copy(key, this.KeyData, key.Length);
        }

        /// <summary>
        /// Gets a copy of the plaintext key
        /// </summary>
        /// <remarks>
        /// This is internal rather than protected so that the tests can use this method
        /// </remarks>
        /// <returns>Plaintext Key</returns>
        internal byte[] GetCopyOfKey()
        {
            var plainKey = new byte[this.keyLength];
            lock(this.stateSync)
            {
                Array.Copy(this.KeyData, plainKey, this.keyLength);
            }
            return plainKey;
        }

        /// <summary>
        /// Uses the key to get an HMAC using the specified algorithm and data
        /// </summary>
        /// <param name="mode">The HMAC algorithm to use</param>
        /// <param name="data">The data used to compute the HMAC</param>
        /// <returns>HMAC of the key and data</returns>
        public byte[] ComputeHmac(OtpHashMode mode, byte[] data)
        {
            byte[] hashedValue = null;
            using(HMAC hmac = CreateHmacHash(mode))
            {
                byte[] key = this.GetCopyOfKey();
                try
                {
                    hmac.Key = key;
                    hashedValue = hmac.ComputeHash(data);
                }
                finally
                {
                    KeyUtilities.Destroy(key);
                }
            }

            return hashedValue;
        }

        /// <summary>
        /// Create an HMAC object for the specified algorithm
        /// </summary>
        private static HMAC CreateHmacHash(OtpHashMode otpHashMode)
        {
            HMAC hmacAlgorithm = null;
            switch(otpHashMode)
            {
                case OtpHashMode.Sha256:
                    hmacAlgorithm = new HMACSHA256();
                    break;
                case OtpHashMode.Sha512:
                    hmacAlgorithm = new HMACSHA512();
                    break;
                default: //case OtpHashMode.Sha1:
                    hmacAlgorithm = new HMACSHA1();
                    break;
            }
            return hmacAlgorithm;
        }
    }
}