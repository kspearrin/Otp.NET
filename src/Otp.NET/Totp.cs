﻿/*
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
FITNESS FOR A PARTICULAR PURPOSE AND NONINFINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

using System;

namespace OtpNet;

/// <summary>
/// Calculate Timed-One-Time-Passwords (TOTP) from a secret key
/// </summary>
/// <remarks>
/// The specifications for this are found in RFC 6238
/// http://tools.ietf.org/html/rfc6238
/// </remarks>
public class Totp : Otp
{
    /// <summary>
    /// The number of ticks as Measured at Midnight Jan 1st 1970;
    /// </summary>
    private const long UnicEpocTicks = 621355968000000000L;

    /// <summary>
    /// A divisor for converting ticks to seconds
    /// </summary>
    private const long TicksToSeconds = 10000000L;

    private readonly int _step;
    private readonly int _totpSize;
    private readonly TimeCorrection _correctedTime;

    /// <summary>
    /// Gets the time window step amount to use in calculating time windows
    /// </summary>
    public int Step => _step;
    
    /// <summary>
    /// Gets the number of digits that the returning TOTP should have
    /// </summary>
    public int TotpSize => _totpSize;
    
    /// <summary>
    /// Gets the time correction to componensate out of sync local clock
    /// </summary>
    public TimeCorrection TimeCorrection => _correctedTime;

    /// <summary>
    /// Create a TOTP instance
    /// </summary>
    /// <param name="secretKey">The secret key to use in TOTP calculations</param>
    /// <param name="step">The time window step amount to use in calculating time windows.
    /// The default is 30 as recommended in the RFC</param>
    /// <param name="mode">The hash mode to use</param>
    /// <param name="totpSize">The number of digits that the returning TOTP should have.  The default is 6.</param>
    /// <param name="timeCorrection">If required, a time correction can be specified to compensate of
    /// an out of sync local clock</param>
    public Totp(
        byte[] secretKey,
        int step = 30,
        OtpHashMode mode = OtpHashMode.Sha1,
        int totpSize = 6,
        TimeCorrection timeCorrection = null)
        : base(secretKey, mode)
    {
        VerifyParameters(step, totpSize);

        _step = step;
        _totpSize = totpSize;

        // we never null check the corrected time object.  Since it's readonly, we'll
        // ensure that it isn't null here and provide neutral functionality in this case.
        _correctedTime = timeCorrection ?? TimeCorrection.UncorrectedInstance;
    }

    /// <summary>
    /// Create a TOTP instance
    /// </summary>
    /// <param name="key">The secret key to use in TOTP calculations</param>
    /// <param name="step">The time window step amount to use in calculating time windows.
    /// The default is 30 as recommended in the RFC</param>
    /// <param name="mode">The hash mode to use</param>
    /// <param name="totpSize">The number of digits that the returning TOTP should have.
    /// The default is 6.</param>
    /// <param name="timeCorrection">If required, a time correction can be specified to compensate
    /// of an out of sync local clock</param>
    public Totp(
        IKeyProvider key,
        int step = 30,
        OtpHashMode mode = OtpHashMode.Sha1,
        int totpSize = 6,
        TimeCorrection timeCorrection = null)
        : base(key, mode)
    {
        VerifyParameters(step, totpSize);

        _step = step;
        _totpSize = totpSize;

        // we never null check the corrected time object.
        // Since it's readonly, we'll ensure that it isn't null here and provide neutral functionality in this case.
        _correctedTime = timeCorrection ?? TimeCorrection.UncorrectedInstance;
    }

    private static void VerifyParameters(int step, int totpSize)
    {
        if (step <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(step));
        }
        if (totpSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(totpSize));
        }
        if (totpSize > 10)
        {
            throw new ArgumentOutOfRangeException(nameof(totpSize));
        }
    }

    /// <summary>
    /// Takes a timestamp and applies correction (if provided) and then computes a TOTP value
    /// </summary>
    /// <param name="timestamp">The timestamp to use for the TOTP calculation</param>
    /// <returns>a TOTP value</returns>
    public string ComputeTotp(DateTime timestamp) =>
        ComputeTotpFromSpecificTime(_correctedTime.GetCorrectedTime(timestamp));

    /// <summary>
    /// Takes a timestamp and computes a TOTP value for corrected UTC now
    /// </summary>
    /// <remarks>
    /// It will be corrected against a corrected UTC time using the provided time correction.
    /// If none was provided then simply the current UTC will be used.
    /// </remarks>
    /// <returns>a TOTP value</returns>
    public string ComputeTotp() => ComputeTotpFromSpecificTime(_correctedTime.CorrectedUtcNow);

    private string ComputeTotpFromSpecificTime(DateTime timestamp)
    {
        var window = CalculateTimeStepFromTimestamp(timestamp);
        return Compute(window, _hashMode);
    }

    /// <summary>
    /// Verify a value that has been provided with the calculated value.
    /// </summary>
    /// <remarks>
    /// It will be corrected against a corrected UTC time using the provided time correction.
    /// If none was provided then simply the current UTC will be used.
    /// </remarks>
    /// <param name="totp">the trial TOTP value</param>
    /// <param name="timeStepMatched">
    /// This is an output parameter that gives that time step that was used to find a match.
    /// This is useful in cases where a TOTP value should only be used once.  This value is a unique identifier of the
    /// time step (not the value) that can be used to prevent the same step from being used multiple times
    /// </param>
    /// <param name="window">The window of steps to verify</param>
    /// <returns>True if there is a match.</returns>
    public bool VerifyTotp(string totp, out long timeStepMatched, VerificationWindow window = null) =>
        VerifyTotpForSpecificTime(_correctedTime.CorrectedUtcNow, totp, window, out timeStepMatched);

    /// <summary>
    /// Verify a value that has been provided with the calculated value
    /// </summary>
    /// <param name="timestamp">The timestamp to use</param>
    /// <param name="totp">the trial TOTP value</param>
    /// <param name="timeStepMatched">
    /// This is an output parameter that gives that time step that was used to find a match.
    /// This is useful in cases where a TOTP value should only be used once.
    /// This value is a unique identifier of the time step (not the value) that can be used
    /// to prevent the same step from being used multiple times
    /// </param>
    /// <param name="window">The window of steps to verify</param>
    /// <returns>True if there is a match.</returns>
    public bool VerifyTotp(
        DateTime timestamp,
        string totp,
        out long timeStepMatched,
        VerificationWindow window = null) =>
        VerifyTotpForSpecificTime(
            _correctedTime.GetCorrectedTime(timestamp),
            totp,
            window,
            out timeStepMatched);

    private bool VerifyTotpForSpecificTime(
        DateTime timestamp,
        string totp,
        VerificationWindow window,
        out long timeStepMatched)
    {
        var initialStep = CalculateTimeStepFromTimestamp(timestamp);
        return Verify(initialStep, totp, out timeStepMatched, window);
    }

    /// <summary>
    /// Takes a timestamp and calculates a time step
    /// </summary>
    private long CalculateTimeStepFromTimestamp(DateTime timestamp)
    {
        var unixTimestamp = (timestamp.Ticks - UnicEpocTicks) / TicksToSeconds;
        var window = unixTimestamp / (long)_step;
        return window;
    }

    /// <summary>
    /// Remaining seconds in current window based on UtcNow
    /// </summary>
    /// <remarks>
    /// It will be corrected against a corrected UTC time using the provided time correction.
    /// If none was provided then simply the current UTC will be used.
    /// </remarks>
    /// <returns>Number of remaining seconds</returns>
    public int RemainingSeconds()
    {
        return RemainingSecondsForSpecificTime(_correctedTime.CorrectedUtcNow);
    }

    /// <summary>
    /// Remaining seconds in current window
    /// </summary>
    /// <param name="timestamp">The timestamp</param>
    /// <returns>Number of remaining seconds</returns>
    public int RemainingSeconds(DateTime timestamp) =>
        RemainingSecondsForSpecificTime(_correctedTime.GetCorrectedTime(timestamp));

    private int RemainingSecondsForSpecificTime(DateTime timestamp) =>
        _step - (int)(((timestamp.Ticks - UnicEpocTicks) / TicksToSeconds) % _step);

    /// <summary>
    /// Start of the current window based on UtcNow
    /// </summary>
    /// <remarks>
    /// It will be corrected against a corrected UTC time using the provided time correction.
    /// If none was provided then simply the current UTC will be used.
    /// </remarks>
    /// <returns>Start of the current window</returns>
    public DateTime WindowStart()
    {
        return WindowStartForSpecificTime(_correctedTime.CorrectedUtcNow);
    }

    public DateTime WindowStart(DateTime timestamp) =>
        WindowStartForSpecificTime(_correctedTime.GetCorrectedTime(timestamp));

    private DateTime WindowStartForSpecificTime(DateTime timestamp) =>
        timestamp.AddTicks(-(timestamp.Ticks - UnicEpocTicks) % (TicksToSeconds * _step));

    /// <summary>
    /// Takes a time step and computes a TOTP code
    /// </summary>
    /// <param name="counter">time step</param>
    /// <param name="mode">The hash mode to use</param>
    /// <returns>TOTP calculated code</returns>
    protected override string Compute(long counter, OtpHashMode mode)
    {
        var data = KeyUtilities.GetBigEndianBytes(counter);
        var otp = CalculateOtp(data, mode);
        return Digits(otp, _totpSize);
    }
}