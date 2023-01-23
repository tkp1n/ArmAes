using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

namespace ArmAes;

internal static partial class AesUtil
{
    private const nuint BytesPerRoundKey = 16;

    #region 128

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Encrypt128(
        ref Vector128<byte> ta0,
        ref Vector128<byte> ta1,
        ref Vector128<byte> ta2,
        ref Vector128<byte> ta3,
        ref Vector128<byte> ta4,
        ref Vector128<byte> ta5,
        ref Vector128<byte> ta6,
        ref Vector128<byte> ta7,
        ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.Encrypt128(
                ref ta0, ref ta1, ref ta2, ref ta3,
                ref ta4, ref ta5, ref ta6, ref ta7,
                ref keySchedule
            );
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.Encrypt128(
                ref ta0, ref ta1, ref ta2, ref ta3,
                ref ta4, ref ta5, ref ta6, ref ta7,
                ref keySchedule
            );
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Encrypt128(
        ref Vector128<byte> ta0,
        ref Vector128<byte> ta1,
        ref Vector128<byte> ta2,
        ref Vector128<byte> ta3,
        ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.Encrypt128(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.Encrypt128(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Encrypt128(
        ref Vector128<byte> ta0,
        ref Vector128<byte> ta1,
        ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.Encrypt128(ref ta0, ref ta1, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.Encrypt128(ref ta0, ref ta1, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> Encrypt128(ref byte keySchedule, Vector128<byte> input)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            return Arm.Encrypt128(ref keySchedule, input);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            return X86.Encrypt128(ref keySchedule, input);
        }

        ThrowHelper.ThrowPlatformNotSupportedException();
        return default;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Decrypt128(
        ref Vector128<byte> ta0,
        ref Vector128<byte> ta1,
        ref Vector128<byte> ta2,
        ref Vector128<byte> ta3,
        ref Vector128<byte> ta4,
        ref Vector128<byte> ta5,
        ref Vector128<byte> ta6,
        ref Vector128<byte> ta7,
        ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.Decrypt128(
                ref ta0, ref ta1, ref ta2, ref ta3,
                ref ta4, ref ta5, ref ta6, ref ta7,
                ref keySchedule
            );
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.Decrypt128(
                ref ta0, ref ta1, ref ta2, ref ta3,
                ref ta4, ref ta5, ref ta6, ref ta7,
                ref keySchedule
            );
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Decrypt128(
        ref Vector128<byte> ta0,
        ref Vector128<byte> ta1,
        ref Vector128<byte> ta2,
        ref Vector128<byte> ta3,
        ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.Decrypt128(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.Decrypt128(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> Decrypt128(ref byte keySchedule, Vector128<byte> input)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            return Arm.Decrypt128(ref keySchedule, input);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            return X86.Decrypt128(ref keySchedule, input);
        }

        ThrowHelper.ThrowPlatformNotSupportedException();
        return default;
    }

    #endregion

    #region 192

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Encrypt192(
        ref Vector128<byte> ta0,
        ref Vector128<byte> ta1,
        ref Vector128<byte> ta2,
        ref Vector128<byte> ta3,
        ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.Encrypt192(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.Encrypt192(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Encrypt192(
        ref Vector128<byte> ta0,
        ref Vector128<byte> ta1,
        ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.Encrypt192(ref ta0, ref ta1, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.Encrypt192(ref ta0, ref ta1, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> Encrypt192(ref byte keySchedule, Vector128<byte> input)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            return Arm.Encrypt192(ref keySchedule, input);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            return X86.Encrypt192(ref keySchedule, input);
        }

        ThrowHelper.ThrowPlatformNotSupportedException();
        return default;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Decrypt192(
        ref Vector128<byte> ta0,
        ref Vector128<byte> ta1,
        ref Vector128<byte> ta2,
        ref Vector128<byte> ta3,
        ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.Decrypt192(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.Decrypt192(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    #endregion

    #region 256

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Encrypt256(
        ref Vector128<byte> ta0,
        ref Vector128<byte> ta1,
        ref Vector128<byte> ta2,
        ref Vector128<byte> ta3,
        ref Vector128<byte> ta4,
        ref Vector128<byte> ta5,
        ref Vector128<byte> ta6,
        ref Vector128<byte> ta7,
        ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.Encrypt256(ref ta0, ref ta1, ref ta2, ref ta3, ref ta4, ref ta5, ref ta6, ref ta7, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.Encrypt256(ref ta0, ref ta1, ref ta2, ref ta3, ref ta4, ref ta5, ref ta6, ref ta7, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Encrypt256(
        ref Vector128<byte> ta0,
        ref Vector128<byte> ta1,
        ref Vector128<byte> ta2,
        ref Vector128<byte> ta3,
        ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.Encrypt256(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.Encrypt256(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Encrypt256(
        ref Vector128<byte> ta0,
        ref Vector128<byte> ta1,
        ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.Encrypt256(ref ta0, ref ta1, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.Encrypt256(ref ta0, ref ta1, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> Encrypt256(ref byte keySchedule, Vector128<byte> input)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            return Arm.Encrypt256(ref keySchedule, input);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            return X86.Encrypt256(ref keySchedule, input);
        }

        ThrowHelper.ThrowPlatformNotSupportedException();
        return default;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Decrypt256(
        ref Vector128<byte> ta0,
        ref Vector128<byte> ta1,
        ref Vector128<byte> ta2,
        ref Vector128<byte> ta3,
        ref Vector128<byte> ta4,
        ref Vector128<byte> ta5,
        ref Vector128<byte> ta6,
        ref Vector128<byte> ta7,
        ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.Decrypt256(ref ta0, ref ta1, ref ta2, ref ta3, ref ta4, ref ta5, ref ta6, ref ta7, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.Decrypt256(ref ta0, ref ta1, ref ta2, ref ta3, ref ta4, ref ta5, ref ta6, ref ta7, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Decrypt256(
        ref Vector128<byte> ta0,
        ref Vector128<byte> ta1,
        ref Vector128<byte> ta2,
        ref Vector128<byte> ta3,
        ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.Decrypt256(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.Decrypt256(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> Decrypt256(ref byte keySchedule, Vector128<byte> input)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            return Arm.Decrypt256(ref keySchedule, input);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            return X86.Decrypt256(ref keySchedule, input);
        }

        ThrowHelper.ThrowPlatformNotSupportedException();
        return default;
    }

    #endregion
}