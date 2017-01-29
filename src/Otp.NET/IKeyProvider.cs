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

namespace OtpNet
{
    /// <summary>
    /// Interface used to interact with a key
    /// </summary>
    public interface IKeyProvider
    {
        /// <summary>
        /// Uses the key to get an HMAC using the specified algorithm and data
        /// </summary>
        /// <remarks>
        /// This is a much better API than the previous API which would briefly expose the key for all derived types.
        /// 
        /// Now a derived type could be bound to an HSM/smart card/etc if required and a lot of the security limitations
        /// of in app/memory exposure of the key can be eliminated.
        /// </remarks>
        /// <param name="mode">The HMAC algorithm to use</param>
        /// <param name="data">The data used to compute the HMAC</param>
        /// <returns>HMAC of the key and data</returns>
        byte[] ComputeHmac(OtpHashMode mode, byte[] data);
    }
}
