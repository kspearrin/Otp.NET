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
    /// Some helper methods to perform common key functions
    /// </summary>
    internal class KeyUtilities
    {
        /// <summary>
        /// Overwrite potentially sensitive data with random junk
        /// </summary>
        /// <remarks>
        /// Warning!
        /// 
        /// This isn't foolproof by any means.  The garbage collector could have moved the actual
        /// location in memory to another location during a collection cycle and left the old data in place
        /// simply marking it as available.  We can't control this or even detect it.
        /// This method is simply a good faith effort to limit the exposure of sensitive data in memory as much as possible
        /// </remarks>
        internal static void Destroy(byte[] sensitiveData)
        {
            if(sensitiveData == null)
                throw new ArgumentNullException("sensitiveData");
            new Random().NextBytes(sensitiveData);
        }

        /// <summary>
        /// converts a long into a big endian byte array.
        /// </summary>
        /// <remarks>
        /// RFC 4226 specifies big endian as the method for converting the counter to data to hash.
        /// </remarks>
        static internal byte[] GetBigEndianBytes(long input)
        {
            // Since .net uses little endian numbers, we need to reverse the byte order to get big endian.
            var data = BitConverter.GetBytes(input);
            Array.Reverse(data);
            return data;
        }

        /// <summary>
        /// converts an int into a big endian byte array.
        /// </summary>
        /// <remarks>
        /// RFC 4226 specifies big endian as the method for converting the counter to data to hash.
        /// </remarks>
        static internal byte[] GetBigEndianBytes(int input)
        {
            // Since .net uses little endian numbers, we need to reverse the byte order to get big endian.
            var data = BitConverter.GetBytes(input);
            Array.Reverse(data);
            return data;
        }
    }
}
