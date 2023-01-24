using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

namespace ArmAes;

public static partial class XtsUtil
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> XtsMulAlpha(Vector128<byte> input)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported)
        {
            return Arm.XtsMulAlpha(input);
        }
        else if (System.Runtime.Intrinsics.X86.Sse2.IsSupported)
        {
            return X86.XtsMulAlpha(input);
        }
        else
        {
             ThrowHelper.ThrowPlatformNotSupportedException();
             return default;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> XtsMulAlpha2(Vector128<byte> input)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported)
        {
            return Arm.XtsMulAlpha2(input);
        }
        else if (System.Runtime.Intrinsics.X86.Sse2.IsSupported)
        {
            return X86.XtsMulAlpha2(input);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
            return default;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> XtsMulAlpha4(Vector128<byte> input)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported)
        {
            return Arm.XtsMulAlpha4(input);
        }
        else if (System.Runtime.Intrinsics.X86.Sse2.IsSupported)
        {
            return X86.XtsMulAlpha4(input);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
            return default;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> XtsMulAlpha5(Vector128<byte> input)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported)
        {
            return Arm.XtsMulAlpha5(input);
        }
        else if (System.Runtime.Intrinsics.X86.Sse2.IsSupported)
        {
            return X86.XtsMulAlpha5(input);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
            return default;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> XtsMulAlpha8(Vector128<byte> input)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported)
        {
            return Arm.XtsMulAlpha8(input);
        }
        else if (System.Runtime.Intrinsics.X86.Ssse3.IsSupported &&
                 System.Runtime.Intrinsics.X86.Pclmulqdq.IsSupported)
        {
            return X86.XtsMulAlpha8(input);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
            return default;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> Pad(Vector128<byte> lastFull, ref byte lastInSlice, nuint lastSliceLen, ref byte lastOutSlice)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported)
        {
            return Arm.Pad(lastFull, ref lastInSlice, lastSliceLen, ref lastOutSlice);
        }
        else if (System.Runtime.Intrinsics.X86.Sse2.IsSupported)
        {
            return X86.Pad(lastFull, ref lastInSlice, lastSliceLen, ref lastOutSlice);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
            return default;
        }
    }
}