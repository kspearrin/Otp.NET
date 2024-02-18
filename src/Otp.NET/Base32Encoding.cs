﻿/*
Credits to "Shane" from StackOverflow answer here:
https://stackoverflow.com/a/7135008
https://stackoverflow.com/users/904128/shane
*/

using System;

namespace OtpNet;

public class Base32Encoding
{
    public static byte[] ToBytes(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            throw new ArgumentNullException(nameof(input));
        }

        // remove padding characters
        input = input.TrimEnd('=');
        // this must be TRUNCATED
        var byteCount = input.Length * 5 / 8;
        var returnArray = new byte[byteCount];

        byte curByte = 0, bitsRemaining = 8;
        var arrayIndex = 0;

        foreach (var c in input)
        {
            var cValue = CharToValue(c);

            int mask;
            if (bitsRemaining > 5)
            {
                mask = cValue << (bitsRemaining - 5);
                curByte = (byte)(curByte | mask);
                bitsRemaining -= 5;
            }
            else
            {
                mask = cValue >> (5 - bitsRemaining);
                curByte = (byte)(curByte | mask);
                returnArray[arrayIndex++] = curByte;
                curByte = (byte)(cValue << (3 + bitsRemaining));
                bitsRemaining += 3;
            }
        }

        // if we didn't end with a full byte
        if (arrayIndex != byteCount)
        {
            returnArray[arrayIndex] = curByte;
        }

        return returnArray;
    }

    public static string ToString(byte[] input)
    {
        if (input == null || input.Length == 0)
        {
            throw new ArgumentNullException(nameof(input));
        }

        var charCount = (int)Math.Ceiling(input.Length / 5d) * 8;
        var returnArray = new char[charCount];

        byte nextChar = 0, bitsRemaining = 5;
        var arrayIndex = 0;

        foreach (byte b in input)
        {
            nextChar = (byte)(nextChar | (b >> (8 - bitsRemaining)));
            returnArray[arrayIndex++] = ValueToChar(nextChar);

            if (bitsRemaining < 4)
            {
                nextChar = (byte)((b >> (3 - bitsRemaining)) & 31);
                returnArray[arrayIndex++] = ValueToChar(nextChar);
                bitsRemaining += 5;
            }

            bitsRemaining -= 3;
            nextChar = (byte)((b << bitsRemaining) & 31);
        }

        // if we didn't end with a full char
        if (arrayIndex != charCount)
        {
            returnArray[arrayIndex++] = ValueToChar(nextChar);
            // padding
            while (arrayIndex != charCount)
            {
                returnArray[arrayIndex++] = '=';
            }
        }

        return new string(returnArray);
    }

    private static int CharToValue(char c)
    {
        int value = c;

        // 65-90 == uppercase letters
        if (value < 91 && value > 64)
        {
            return value - 65;
        }

        // 50-55 == numbers 2-7
        if (value < 56 && value > 49)
        {
            return value - 24;
        }

        // 97-122 == lowercase letters
        if (value < 123 && value > 96)
        {
            return value - 97;
        }

        throw new ArgumentException("Character is not a Base32 character.", nameof(c));
    }

    private static char ValueToChar(byte b)
    {
        if (b < 26)
        {
            return (char)(b + 65);
        }

        if (b < 32)
        {
            return (char)(b + 24);
        }

        throw new ArgumentException("Byte is not a Base32 value.", nameof(b));
    }
}
