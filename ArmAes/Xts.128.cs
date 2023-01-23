using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

namespace ArmAes;

public static partial class Xts
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void EncryptDataUnit128(
        in AesKey key,
        ref byte tweak,
        ref byte pt, nuint ptLen,
        ref byte ct)
    {
        var t0 = Vector128.LoadUnsafe(ref tweak);

        ref var keySchedule = ref key.EncryptKeySchedule;

        while (ptLen >= 8 * BytesPerBlock)
        {
            var t4 = XtsUtil.XtsMulAlpha4(t0);
            var t1 = XtsUtil.XtsMulAlpha (t0);
            var t5 = XtsUtil.XtsMulAlpha (t4);
            var t2 = XtsUtil.XtsMulAlpha (t1);
            var t6 = XtsUtil.XtsMulAlpha (t5);
            var t3 = XtsUtil.XtsMulAlpha (t2);
            var t7 = XtsUtil.XtsMulAlpha (t6);

            var p0 = t0 ^ Vector128.LoadUnsafe(ref pt);
            var p1 = t1 ^ Vector128.LoadUnsafe(ref pt, 1 * BytesPerBlock);
            var p2 = t2 ^ Vector128.LoadUnsafe(ref pt, 2 * BytesPerBlock);
            var p3 = t3 ^ Vector128.LoadUnsafe(ref pt, 3 * BytesPerBlock);
            var p4 = t4 ^ Vector128.LoadUnsafe(ref pt, 4 * BytesPerBlock);
            var p5 = t5 ^ Vector128.LoadUnsafe(ref pt, 5 * BytesPerBlock);
            var p6 = t6 ^ Vector128.LoadUnsafe(ref pt, 6 * BytesPerBlock);
            var p7 = t7 ^ Vector128.LoadUnsafe(ref pt, 7 * BytesPerBlock);

            for (;;)
            {
                pt = ref Unsafe.AddByteOffset(ref pt, 8 * BytesPerBlock);

                AesUtil.Encrypt128(
                    ref p0, ref p1, ref p2, ref p3,
                    ref p4, ref p5, ref p6, ref p7,
                    ref keySchedule
                );

                ptLen -= 8 * BytesPerBlock;
                if (ptLen < 8 * BytesPerBlock)
                {
                    break;
                }

                (p0 ^ t0).StoreUnsafe(ref ct, 0 * BytesPerBlock);
                (p1 ^ t1).StoreUnsafe(ref ct, 1 * BytesPerBlock);
                (p2 ^ t2).StoreUnsafe(ref ct, 2 * BytesPerBlock);
                (p3 ^ t3).StoreUnsafe(ref ct, 3 * BytesPerBlock);
                (p4 ^ t4).StoreUnsafe(ref ct, 4 * BytesPerBlock);
                (p5 ^ t5).StoreUnsafe(ref ct, 5 * BytesPerBlock);
                (p6 ^ t6).StoreUnsafe(ref ct, 6 * BytesPerBlock);
                (p7 ^ t7).StoreUnsafe(ref ct, 7 * BytesPerBlock);

                t0 = XtsUtil.XtsMulAlpha8(t0);
                t1 = XtsUtil.XtsMulAlpha8(t1);
                t2 = XtsUtil.XtsMulAlpha8(t2);
                t3 = XtsUtil.XtsMulAlpha8(t3);
                t4 = XtsUtil.XtsMulAlpha8(t4);
                t5 = XtsUtil.XtsMulAlpha8(t5);
                t6 = XtsUtil.XtsMulAlpha8(t6);
                t7 = XtsUtil.XtsMulAlpha8(t7);

                p0 = Vector128.LoadUnsafe(ref pt, 0 * BytesPerBlock) ^ t0;
                p1 = Vector128.LoadUnsafe(ref pt, 1 * BytesPerBlock) ^ t1;
                p2 = Vector128.LoadUnsafe(ref pt, 2 * BytesPerBlock) ^ t2;
                p3 = Vector128.LoadUnsafe(ref pt, 3 * BytesPerBlock) ^ t3;
                p4 = Vector128.LoadUnsafe(ref pt, 4 * BytesPerBlock) ^ t4;
                p5 = Vector128.LoadUnsafe(ref pt, 5 * BytesPerBlock) ^ t5;
                p6 = Vector128.LoadUnsafe(ref pt, 6 * BytesPerBlock) ^ t6;
                p7 = Vector128.LoadUnsafe(ref pt, 7 * BytesPerBlock) ^ t7;

                ct = ref Unsafe.AddByteOffset(ref ct, 8 * BytesPerBlock);
            }

            (p0 ^ t0).StoreUnsafe(ref ct, 0 * BytesPerBlock);
            (p1 ^ t1).StoreUnsafe(ref ct, 1 * BytesPerBlock);
            (p2 ^ t2).StoreUnsafe(ref ct, 2 * BytesPerBlock);
            (p3 ^ t3).StoreUnsafe(ref ct, 3 * BytesPerBlock);
            (p4 ^ t4).StoreUnsafe(ref ct, 4 * BytesPerBlock);
            (p5 ^ t5).StoreUnsafe(ref ct, 5 * BytesPerBlock);
            (p6 ^ t6).StoreUnsafe(ref ct, 6 * BytesPerBlock);
            (p7 ^ t7).StoreUnsafe(ref ct, 7 * BytesPerBlock);

            t0 = XtsUtil.XtsMulAlpha8(t0);

            ct = ref Unsafe.AddByteOffset(ref ct, 8 * BytesPerBlock);
        }

        while (ptLen >= BytesPerBlock)
        {
            var p0 = Vector128.LoadUnsafe(ref pt) ^ t0;
            pt = ref Unsafe.AddByteOffset(ref pt, BytesPerBlock);

            p0 = AesUtil.Encrypt128(ref keySchedule, p0);

            (p0 ^ t0).StoreUnsafe(ref ct);
            ct = ref Unsafe.AddByteOffset(ref ct, BytesPerBlock);

            t0 = XtsUtil.XtsMulAlpha(t0);

            ptLen -= BytesPerBlock;
        }

        if (ptLen > 0)
        {
            ref var lastCtBlockRef = ref Unsafe.Subtract(ref ct, BytesPerBlock);

            var lastCtBlock = Vector128.LoadUnsafe(ref lastCtBlockRef);
            lastCtBlock = XtsUtil.Pad(lastCtBlock, ref pt, ptLen, ref ct);
            lastCtBlock ^= t0;
            lastCtBlock = AesUtil.Encrypt128(ref keySchedule, lastCtBlock);
            (lastCtBlock ^ t0).StoreUnsafe(ref lastCtBlockRef);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void DecryptDataUnit128(
        in AesKey key,
        ref byte tweak,
        ref byte ct, nuint ctLen,
        ref byte pt)
    {
        var t0 = Vector128.LoadUnsafe(ref tweak);

        ref var keySchedule = ref key.DecryptKeySchedule;

        while (ctLen >= 8 * BytesPerBlock)
        {
            var t4 = XtsUtil.XtsMulAlpha4(t0);
            var t1 = XtsUtil.XtsMulAlpha (t0);
            var t5 = XtsUtil.XtsMulAlpha (t4);
            var t2 = XtsUtil.XtsMulAlpha (t1);
            var t6 = XtsUtil.XtsMulAlpha (t5);
            var t3 = XtsUtil.XtsMulAlpha (t2);
            var t7 = XtsUtil.XtsMulAlpha (t6);

            var c0 = t0 ^ Vector128.LoadUnsafe(ref ct);
            var c1 = t1 ^ Vector128.LoadUnsafe(ref ct, 1 * BytesPerBlock);
            var c2 = t2 ^ Vector128.LoadUnsafe(ref ct, 2 * BytesPerBlock);
            var c3 = t3 ^ Vector128.LoadUnsafe(ref ct, 3 * BytesPerBlock);
            var c4 = t4 ^ Vector128.LoadUnsafe(ref ct, 4 * BytesPerBlock);
            var c5 = t5 ^ Vector128.LoadUnsafe(ref ct, 5 * BytesPerBlock);
            var c6 = t6 ^ Vector128.LoadUnsafe(ref ct, 6 * BytesPerBlock);
            var c7 = t7 ^ Vector128.LoadUnsafe(ref ct, 7 * BytesPerBlock);

            for (;;)
            {
                ct = ref Unsafe.AddByteOffset(ref ct, 8 * BytesPerBlock);

                AesUtil.Decrypt128(
                    ref c0, ref c1, ref c2, ref c3,
                    ref c4, ref c5, ref c6, ref c7,
                    ref keySchedule
                );

                ctLen -= 8 * BytesPerBlock;
                if (ctLen < 8 * BytesPerBlock)
                {
                    break;
                }

                (c0 ^ t0).StoreUnsafe(ref pt, 0 * BytesPerBlock);
                (c1 ^ t1).StoreUnsafe(ref pt, 1 * BytesPerBlock);
                (c2 ^ t2).StoreUnsafe(ref pt, 2 * BytesPerBlock);
                (c3 ^ t3).StoreUnsafe(ref pt, 3 * BytesPerBlock);
                (c4 ^ t4).StoreUnsafe(ref pt, 4 * BytesPerBlock);
                (c5 ^ t5).StoreUnsafe(ref pt, 5 * BytesPerBlock);
                (c6 ^ t6).StoreUnsafe(ref pt, 6 * BytesPerBlock);
                (c7 ^ t7).StoreUnsafe(ref pt, 7 * BytesPerBlock);

                t0 = XtsUtil.XtsMulAlpha8(t0);
                t1 = XtsUtil.XtsMulAlpha8(t1);
                t2 = XtsUtil.XtsMulAlpha8(t2);
                t3 = XtsUtil.XtsMulAlpha8(t3);
                t4 = XtsUtil.XtsMulAlpha8(t4);
                t5 = XtsUtil.XtsMulAlpha8(t5);
                t6 = XtsUtil.XtsMulAlpha8(t6);
                t7 = XtsUtil.XtsMulAlpha8(t7);

                c0 = Vector128.LoadUnsafe(ref ct, 0 * BytesPerBlock) ^ t0;
                c1 = Vector128.LoadUnsafe(ref ct, 1 * BytesPerBlock) ^ t1;
                c2 = Vector128.LoadUnsafe(ref ct, 2 * BytesPerBlock) ^ t2;
                c3 = Vector128.LoadUnsafe(ref ct, 3 * BytesPerBlock) ^ t3;
                c4 = Vector128.LoadUnsafe(ref ct, 4 * BytesPerBlock) ^ t4;
                c5 = Vector128.LoadUnsafe(ref ct, 5 * BytesPerBlock) ^ t5;
                c6 = Vector128.LoadUnsafe(ref ct, 6 * BytesPerBlock) ^ t6;
                c7 = Vector128.LoadUnsafe(ref ct, 7 * BytesPerBlock) ^ t7;

                pt = ref Unsafe.AddByteOffset(ref pt, 8 * BytesPerBlock);
            }

            (c0 ^ t0).StoreUnsafe(ref pt, 0 * BytesPerBlock);
            (c1 ^ t1).StoreUnsafe(ref pt, 1 * BytesPerBlock);
            (c2 ^ t2).StoreUnsafe(ref pt, 2 * BytesPerBlock);
            (c3 ^ t3).StoreUnsafe(ref pt, 3 * BytesPerBlock);
            (c4 ^ t4).StoreUnsafe(ref pt, 4 * BytesPerBlock);
            (c5 ^ t5).StoreUnsafe(ref pt, 5 * BytesPerBlock);
            (c6 ^ t6).StoreUnsafe(ref pt, 6 * BytesPerBlock);
            (c7 ^ t7).StoreUnsafe(ref pt, 7 * BytesPerBlock);

            t0 = XtsUtil.XtsMulAlpha8(t0);

            pt = ref Unsafe.AddByteOffset(ref pt, 8 * BytesPerBlock);
        }

        while (ctLen >= BytesPerBlock * 2)
        {
            var c0 = Vector128.LoadUnsafe(ref ct) ^ t0;
            ct = ref Unsafe.AddByteOffset(ref ct, BytesPerBlock);

            c0 = AesUtil.Decrypt128(ref keySchedule, c0);

            (c0 ^ t0).StoreUnsafe(ref pt);
            pt = ref Unsafe.AddByteOffset(ref pt, BytesPerBlock);

            t0 = XtsUtil.XtsMulAlpha(t0);

            ctLen -= BytesPerBlock;
        }

        if (ctLen == BytesPerBlock)
        {
            var c0 = Vector128.LoadUnsafe(ref ct) ^ t0;
            c0 = AesUtil.Decrypt128(ref keySchedule, c0);
            (c0 ^ t0).StoreUnsafe(ref pt);
        }
        else
        {
            var tLast = XtsUtil.XtsMulAlpha(t0);
            var c0 = Vector128.LoadUnsafe(ref ct) ^ tLast;
            c0 = AesUtil.Decrypt128(ref keySchedule, c0);
            var pp = c0 ^ tLast;

            var lastPtBlock = XtsUtil.Pad(
                pp,
                ref Unsafe.AddByteOffset(ref ct, BytesPerBlock), ctLen - BytesPerBlock,
                ref Unsafe.AddByteOffset(ref pt, BytesPerBlock)
            );

            lastPtBlock ^= t0;
            lastPtBlock = AesUtil.Decrypt128(ref keySchedule, lastPtBlock);
            (lastPtBlock ^ t0).StoreUnsafe(ref pt);
        }
    }
}