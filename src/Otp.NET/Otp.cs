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
        protected readonly IKeyProvider secretKey;

        /// <summary>
        /// The hash mode to use
        /// </summary>
        protected readonly OtpHashMode hashMode;

        /// <summary>
        /// Constructor for the abstract class using an explicit secret key
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
            this.secretKey = new InMemoryKey(secretKey);

            this.hashMode = mode;
        }

        /// <summary>
        /// Constructor for the abstract class using a generic key provider
        /// </summary>
        /// <param name="key"></param>
        /// <param name="mode">The hash mode to use</param>
        public Otp(IKeyProvider key, OtpHashMode mode)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            this.secretKey = key;

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
            byte[] hmacComputedHash = this.secretKey.ComputeHmac(mode, data);

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
                if(ValuesEqual(comparisonValue, valueToVerify))
                {
                    matchedStep = frame;
                    return true;
                }
            }

            matchedStep = 0;
            return false;
        }

        // Constant time comparison of two values
        private bool ValuesEqual(string a, string b)
        {
            if(a.Length != b.Length)
            {
                return false;
            }

            var result = 0;
            for(int i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }

            return result == 0;
        }
    }
}