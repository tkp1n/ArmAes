using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

namespace ArmAes;

internal static partial class Ghash
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> Gfmul(Vector128<byte> H, Vector128<byte> X)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported &&
            System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported)
        {
            return Arm.Gfmul(H.AsUInt64(), X.AsUInt64()).AsByte();
        }
        else if (System.Runtime.Intrinsics.X86.Pclmulqdq.IsSupported &&
                 System.Runtime.Intrinsics.X86.Sse2.IsSupported)
        {
            return X86.Gfmul(H.AsUInt64(), X.AsUInt64()).AsByte();
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
            return default;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> Reduce4(
        Vector128<byte> H1, Vector128<byte> H2, Vector128<byte> H3, Vector128<byte> H4,
        Vector128<byte> X1, Vector128<byte> X2, Vector128<byte> X3, Vector128<byte> X4)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported &&
            System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported)
        {
            return Arm.Reduce4(
                H1.AsUInt64(), H2.AsUInt64(), H3.AsUInt64(), H4.AsUInt64(),
                X1.AsUInt64(), X2.AsUInt64(), X3.AsUInt64(), X4.AsUInt64()
            ).AsByte();
        }
        else if (System.Runtime.Intrinsics.X86.Pclmulqdq.IsSupported &&
                 System.Runtime.Intrinsics.X86.Sse2.IsSupported)
        {
            return X86.Reduce4(
                H1.AsUInt64(), H2.AsUInt64(), H3.AsUInt64(), H4.AsUInt64(),
                X1.AsUInt64(), X2.AsUInt64(), X3.AsUInt64(), X4.AsUInt64()
            ).AsByte();
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
            return default;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> BswapVec(Vector128<byte> v)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.Arm64.IsSupported)
        {
            return Arm.BswapVec(v);
        }
        else if (System.Runtime.Intrinsics.X86.Ssse3.IsSupported)
        {
            return X86.BswapVec(v);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
            return default;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> Bswap64(Vector128<byte> v)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.Arm64.IsSupported)
        {
            return Arm.Bswap64(v);
        }
        else if (System.Runtime.Intrinsics.X86.Ssse3.IsSupported)
        {
            return X86.Bswap64(v);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
            return default;
        }
    }
}