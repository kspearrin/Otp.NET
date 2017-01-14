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

using System.Collections.Generic;

namespace OtpNet
{
    /// <summary>
    /// A verification window
    /// </summary>
    public class VerificationWindow
    {
        private readonly int previous;
        private readonly int future;

        /// <summary>
        /// Create an instance of a verification window
        /// </summary>
        /// <param name="previous">The number of previous frames to accept</param>
        /// <param name="future">The number of future frames to accept</param>
        public VerificationWindow(int previous = 0, int future = 0)
        {
            this.previous = previous;
            this.future = future;
        }

        /// <summary>
        /// Gets an enumberable of all the possible validation candidates
        /// </summary>
        /// <param name="initialFrame">The initial frame to validate</param>
        /// <returns>Enumberable of all possible frames that need to be validated</returns>
        public IEnumerable<long> ValidationCandidates(long initialFrame)
        {
            yield return initialFrame;
            for(int i = 1; i <= previous; i++)
            {
                var val = initialFrame - i;
                if(val < 0)
                    break;
                yield return val;
            }

            for(int i = 1; i <= future; i++)
                yield return initialFrame + i;
        }

        /// <summary>
        /// The verification window that accomodates network delay that is recommended in the RFC
        /// </summary>
        public static readonly VerificationWindow RfcSpecifiedNetworkDelay = new VerificationWindow(previous: 1, future: 1);
    }
}
