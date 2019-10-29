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

namespace OtpNet
{
    /// <summary>
    /// Calculate HMAC-Based One-Time-Passwords (HOTP) from a secret key
    /// </summary>
    /// <remarks>
    /// The specifications for this are found in RFC 4226
    /// http://tools.ietf.org/html/rfc4226
    /// </remarks>
    public class Hotp : Otp
    {
        private readonly int hotpSize;

        /// <summary>
        /// Create a HOTP instance
        /// </summary>
        /// <param name="secretKey">The secret key to use in HOTP calculations</param>
        /// <param name="mode">The hash mode to use</param>
        /// <param name="hotpSize">The number of digits that the returning HOTP should have.  The default is 6.</param>
        public Hotp(byte[] secretKey, OtpHashMode mode = OtpHashMode.Sha1, int hotpSize = 6)
            : base(secretKey, mode)
        {
            VerifyParameters(hotpSize);

            this.hotpSize = hotpSize;
        }

        /// <summary>
        /// Create a HOTP instance
        /// </summary>
        /// <param name="key">The key to use in HOTP calculations</param>
        /// <param name="mode">The hash mode to use</param>
        /// <param name="hotpSize">The number of digits that the returning HOTP should have.  The default is 6.</param>
        public Hotp(IKeyProvider key, OtpHashMode mode = OtpHashMode.Sha1, int hotpSize = 6)
            : base(key, mode)
        {
            VerifyParameters(hotpSize);

            this.hotpSize = hotpSize;
        }

        private static void VerifyParameters(int hotpSize)
        {
            if(!(hotpSize >= 6))
                throw new ArgumentOutOfRangeException("hotpSize");
            if(!(hotpSize <= 8))
                throw new ArgumentOutOfRangeException("hotpSize");
        }

        /// <summary>
        /// Takes a counter and then computes a HOTP value
        /// </summary>
        /// <param name="timestamp">The timestamp to use for the HOTP calculation</param>
        /// <returns>a HOTP value</returns>
        public string ComputeHOTP(long counter)
        {
            return this.Compute(counter, this.hashMode);
        }

        /// <summary>
        /// Verify a value that has been provided with the calculated value
        /// </summary>
        /// <param name="hotp">the trial HOTP value</param>
        /// <param name="counter">The counter value to verify/param>
        /// <returns>True if there is a match.</returns>
        public bool VerifyHotp(string hotp, long counter)
        {
            if(hotp == ComputeHOTP(counter))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Takes a time step and computes a HOTP code
        /// </summary>
        /// <param name="counter">counter</param>
        /// <param name="mode">The hash mode to use</param>
        /// <returns>HOTP calculated code</returns>
        protected override string Compute(long counter, OtpHashMode mode)
        {
            var data = KeyUtilities.GetBigEndianBytes(counter);
            var otp = this.CalculateOtp(data, mode);
            return Digits(otp, this.hotpSize);
        }
    }
}
