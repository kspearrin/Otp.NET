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
    /// An abstract class that contains common OTP calculations
    /// </summary>
    /// <remarks>
    /// https://tools.ietf.org/html/rfc4226
    /// </remarks>
    public abstract class Otp
    {
        /// <summary>
        /// Secret key
        /// </summary>
        protected readonly byte[] secretKey;

        /// <summary>
        /// The hash mode to use
        /// </summary>
        protected readonly OtpHashMode hashMode;

        /// <summary>
        /// Constructor for the abstract class.  This is to guarantee that all implementations have a secret key
        /// </summary>
        /// <param name="secretKey"></param>
        /// <param name="mode">The hash mode to use</param>
        public Otp(byte[] secretKey, OtpHashMode mode)
        {
            if(!(secretKey != null))
                throw new ArgumentNullException("secretKey");
            if(!(secretKey.Length > 0))
                throw new ArgumentException("secretKey empty");

            // when passing a key into the constructor the caller may depend on the reference to the key remaining intact.
            this.secretKey = secretKey;

            this.hashMode = mode;
        }

        /// <summary>
        /// An abstract definition of a compute method.  Takes a counter and runs it through the derived algorithm.
        /// </summary>
        /// <param name="counter">Counter or step</param>
        /// <param name="mode">The hash mode to use</param>
        /// <returns>OTP calculated code</returns>
        protected abstract string Compute(long counter, OtpHashMode mode);

        /// <summary>
        /// Helper method that calculates OTPs
        /// </summary>
        protected internal long CalculateOtp(byte[] data, OtpHashMode mode)
        {
            byte[] hmacComputedHash = ComputeHmac(mode, data);

            // The RFC has a hard coded index 19 in this value.
            // This is the same thing but also accomodates SHA256 and SHA512
            // hmacComputedHash[19] => hmacComputedHash[hmacComputedHash.Length - 1]

            int offset = hmacComputedHash[hmacComputedHash.Length - 1] & 0x0F;
            return (hmacComputedHash[offset] & 0x7f) << 24
                | (hmacComputedHash[offset + 1] & 0xff) << 16
                | (hmacComputedHash[offset + 2] & 0xff) << 8
                | (hmacComputedHash[offset + 3] & 0xff) % 1000000;
        }

        /// <summary>
        /// truncates a number down to the specified number of digits
        /// </summary>
        protected internal static string Digits(long input, int digitCount)
        {
            var truncatedValue = ((int)input % (int)Math.Pow(10, digitCount));
            return truncatedValue.ToString().PadLeft(digitCount, '0');
        }

        /// <summary>
        /// Verify an OTP value
        /// </summary>
        /// <param name="initialStep">The initial step to try</param>
        /// <param name="valueToVerify">The value to verify</param>
        /// <param name="matchedStep">Output parameter that provides the step where the match was found.  If no match was found it will be 0</param>
        /// <param name="window">The window to verify</param>
        /// <returns>True if a match is found</returns>
        protected bool Verify(long initialStep, string valueToVerify, out long matchedStep, VerificationWindow window)
        {
            if(window == null)
                window = new VerificationWindow();
            foreach(var frame in window.ValidationCandidates(initialStep))
            {
                var comparisonValue = this.Compute(frame, this.hashMode);
                if(comparisonValue == valueToVerify)
                {
                    matchedStep = frame;
                    return true;
                }
            }

            matchedStep = 0;
            return false;
        }

        /// <summary>
        /// Uses the key to get an HMAC using the specified algorithm and data
        /// </summary>
        /// <param name="mode">The HMAC algorithm to use</param>
        /// <param name="data">The data used to compute the HMAC</param>
        /// <returns>HMAC of the key and data</returns>
        private byte[] ComputeHmac(OtpHashMode mode, byte[] data)
        {
            byte[] hashedValue = null;
            using(HMAC hmac = CreateHmacHash(mode))
            {
                try
                {
                    hmac.Key = this.secretKey;
                    hashedValue = hmac.ComputeHash(data);
                }
                finally
                {
                    KeyUtilities.Destroy(this.secretKey);
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