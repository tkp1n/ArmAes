using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

namespace ArmAes;

public static partial class Ecb
{
    public static void EncryptEcb128(
        in AesKey key,
        ReadOnlySpan<byte> input,
        Span<byte> output)
    {
        ref var pt = ref MemoryMarshal.GetReference(input);
        var ptLen = (nuint)input.Length;
        ref var ct = ref MemoryMarshal.GetReference(output);

        Debug.Assert(ptLen % BytesPerBlock == 0);

        ref var keySchedule = ref key.EncryptKeySchedule;

        while (ptLen >= 8 * BytesPerBlock)
        {
            var t0 = Vector128.LoadUnsafe(ref pt);
            var t1 = Vector128.LoadUnsafe(ref pt, 1 * BytesPerBlock);
            var t2 = Vector128.LoadUnsafe(ref pt, 2 * BytesPerBlock);
            var t3 = Vector128.LoadUnsafe(ref pt, 3 * BytesPerBlock);
            var t4 = Vector128.LoadUnsafe(ref pt, 4 * BytesPerBlock);
            var t5 = Vector128.LoadUnsafe(ref pt, 5 * BytesPerBlock);
            var t6 = Vector128.LoadUnsafe(ref pt, 6 * BytesPerBlock);
            var t7 = Vector128.LoadUnsafe(ref pt, 7 * BytesPerBlock);

            AesUtil.Encrypt128(
                ref t0, ref t1, ref t2, ref t3,
                ref t4, ref t5, ref t6, ref t7,
                ref keySchedule);

            t0.StoreUnsafe(ref ct);
            t1.StoreUnsafe(ref ct, 1 * BytesPerBlock);
            t2.StoreUnsafe(ref ct, 2 * BytesPerBlock);
            t3.StoreUnsafe(ref ct, 3 * BytesPerBlock);
            t4.StoreUnsafe(ref ct, 4 * BytesPerBlock);
            t5.StoreUnsafe(ref ct, 5 * BytesPerBlock);
            t6.StoreUnsafe(ref ct, 6 * BytesPerBlock);
            t7.StoreUnsafe(ref ct, 7 * BytesPerBlock);

            pt = ref Unsafe.AddByteOffset(ref pt, 8 * BytesPerBlock);
            ct = ref Unsafe.AddByteOffset(ref ct, 8 * BytesPerBlock);
            ptLen -= 8 * BytesPerBlock;
        }

        while (ptLen >= 4 * BytesPerBlock)
        {
            var t0 = Vector128.LoadUnsafe(ref pt);
            var t1 = Vector128.LoadUnsafe(ref pt, 1 * BytesPerBlock);
            var t2 = Vector128.LoadUnsafe(ref pt, 2 * BytesPerBlock);
            var t3 = Vector128.LoadUnsafe(ref pt, 3 * BytesPerBlock);

            AesUtil.Encrypt128(
                ref t0, ref t1, ref t2, ref t3,
                ref keySchedule);

            t0.StoreUnsafe(ref ct);
            t1.StoreUnsafe(ref ct, 1 * BytesPerBlock);
            t2.StoreUnsafe(ref ct, 2 * BytesPerBlock);
            t3.StoreUnsafe(ref ct, 3 * BytesPerBlock);

            pt = ref Unsafe.AddByteOffset(ref pt, 4 * BytesPerBlock);
            ct = ref Unsafe.AddByteOffset(ref ct, 4 * BytesPerBlock);
            ptLen -= 4 * BytesPerBlock;
        }

        while (ptLen > 0)
        {
            var t0 = Vector128.LoadUnsafe(ref pt);
            t0 = AesUtil.Encrypt128(ref keySchedule, t0);
            t0.StoreUnsafe(ref ct);

            pt = ref Unsafe.AddByteOffset(ref pt, BytesPerBlock);
            ct = ref Unsafe.AddByteOffset(ref ct, BytesPerBlock);
            ptLen -= BytesPerBlock;
        }
    }
}