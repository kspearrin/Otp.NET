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
    /// Helpers to work with keys
    /// </summary>
    public static class KeyGeneration
    {
        /// <summary>
        /// Generates a random key in accordance with the RFC recommened length for each algorithm
        /// </summary>
        /// <param name="length">Key length</param>
        /// <returns>The generated key</returns>
        public static byte[] GenerateRandomKey(int length)
        {
            byte[] key = new byte[length];
            using(var rnd = RandomNumberGenerator.Create())
            {
                rnd.GetBytes(key);
                return key;
            }
        }

        /// <summary>
        /// Generates a random key in accordance with the RFC recommened length for each algorithm
        /// </summary>
        /// <param name="mode">HashMode</param>
        /// <returns>Key</returns>
        public static byte[] GenerateRandomKey(OtpHashMode mode = OtpHashMode.Sha1)
        {
            return GenerateRandomKey(LengthForMode(mode));
        }

        /// <summary>
        /// Uses the procedure defined in RFC 4226 section 7.5 to derive a key from the master key
        /// </summary>
        /// <param name="masterKey">The master key from which to derive a device specific key</param>
        /// <param name="publicIdentifier">The public identifier that is unique to the authenticating device</param>
        /// <param name="mode">The hash mode to use.  This will determine the resulting key lenght.  The default is sha-1 (as per the RFC) which is 20 bytes</param>
        /// <returns>Derived key</returns>
        public static byte[] DeriveKeyFromMaster(IKeyProvider masterKey, byte[] publicIdentifier, OtpHashMode mode = OtpHashMode.Sha1)
        {
            if(masterKey == null)
                throw new ArgumentNullException("masterKey");
            return masterKey.ComputeHmac(mode, publicIdentifier);
        }

        /// <summary>
        /// Uses the procedure defined in RFC 4226 section 7.5 to derive a key from the master key
        /// </summary>
        /// <param name="masterKey">The master key from which to derive a device specific key</param>
        /// <param name="serialNumber">A serial number that is unique to the authenticating device</param>
        /// <param name="mode">The hash mode to use.  This will determine the resulting key lenght.  The default is sha-1 (as per the RFC) which is 20 bytes</param>
        /// <returns>Derived key</returns>
        public static byte[] DeriveKeyFromMaster(IKeyProvider masterKey, int serialNumber, OtpHashMode mode = OtpHashMode.Sha1)
        {
            return DeriveKeyFromMaster(masterKey, KeyUtilities.GetBigEndianBytes(serialNumber), mode);
        }

        private static HashAlgorithm GetHashAlgorithmForMode(OtpHashMode mode)
        {
            switch(mode)
            {
                case OtpHashMode.Sha256:
                    return SHA256.Create();
                case OtpHashMode.Sha512:
                    return SHA512.Create();
                default: //case OtpHashMode.Sha1:
                    return SHA1.Create();
            }
        }

        private static int LengthForMode(OtpHashMode mode)
        {
            switch(mode)
            {
                case OtpHashMode.Sha256:
                    return 32;
                case OtpHashMode.Sha512:
                    return 64;
                default: //case OtpHashMode.Sha1:
                    return 20;
            }
        }
    }
}