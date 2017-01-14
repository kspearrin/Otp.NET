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
    /// Class to apply a correction factor to the system time
    /// </summary>
    /// <remarks>
    /// In cases where the local system time is incorrect it is preferable to simply correct the system time.
    /// This class is provided to handle cases where it isn't possible for the client, the server, or both, to be on the correct time.
    /// 
    /// This library provides limited facilities to to ping NIST for a correct network time.  This class can be used manually however in cases where a server's time is off
    /// and the consumer of this library can't control it.  In that case create an instance of this class and provide the current server time as the correct time parameter
    /// 
    /// This class is immutable and therefore threadsafe
    /// </remarks>
    public class TimeCorrection
    {
        /// <summary>
        /// An instance that provides no correction factor
        /// </summary>
        public static readonly TimeCorrection UncorrectedInstance = new TimeCorrection();

        private readonly TimeSpan timeCorrectionFactor;

        /// <summary>
        /// Constructor used solely for the UncorrectedInstance static field to provide an instance without a correction factor.
        /// </summary>
        private TimeCorrection()
        {
            this.timeCorrectionFactor = TimeSpan.FromSeconds(0);
        }

        /// <summary>
        /// Creates a corrected time object by providing the known correct current UTC time.  The current system UTC time will be used as the reference
        /// </summary>
        /// <remarks>
        /// This overload assumes UTC.  If a base and reference time other than UTC are required then use the other overlaod.
        /// </remarks>
        /// <param name="correctUtc">The current correct UTC time</param>
        public TimeCorrection(DateTime correctUtc)
        {
            this.timeCorrectionFactor = DateTime.UtcNow - correctUtc;
        }

        /// <summary>
        /// Creates a corrected time object by providing the known correct current time and the current reference time that needs correction
        /// </summary>
        /// <param name="correctTime">The current correct time</param>
        /// <param name="referenceTime">The current reference time (time that will have the correction factor applied in subsequent calls)</param>
        public TimeCorrection(DateTime correctTime, DateTime referenceTime)
        {
            this.timeCorrectionFactor = referenceTime - correctTime;
        }

        /// <summary>
        /// Applies the correction factor to the reference time and returns a corrected time
        /// </summary>
        /// <param name="referenceTime">The reference time</param>
        /// <returns>The reference time with the correction factor applied</returns>
        public DateTime GetCorrectedTime(DateTime referenceTime)
        {
            return referenceTime - timeCorrectionFactor;
        }

        /// <summary>
        /// Applies the correction factor to the current system UTC time and returns a corrected time
        /// </summary>
        public DateTime CorrectedUtcNow
        {
            get { return GetCorrectedTime(DateTime.UtcNow); }
        }

        /// <summary>
        /// The timespan that is used to calculate a corrected time
        /// </summary>
        public TimeSpan CorrectionFactor
        {
            get { return this.timeCorrectionFactor; }
        }
    }
}