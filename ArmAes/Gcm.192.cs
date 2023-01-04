using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

namespace ArmAes;

public static partial class Gcm
{
    private static void AeEncrypt192(
        in AesKey key,
        ref byte pt, nuint ptLen,
        ref byte nonce, nuint nonceLen,
        ref byte ad, nuint adLen,
        ref byte ct,
        ref byte tag, nuint tagLen)
    {
        Unsafe.SkipInit(out Vector128<byte> tmp1);
        Unsafe.SkipInit(out Vector128<byte> tmp2);
        Unsafe.SkipInit(out Vector128<byte> tmp3);
        Unsafe.SkipInit(out Vector128<byte> tmp4);

        Unsafe.SkipInit(out Vector128<byte> h);
        Unsafe.SkipInit(out Vector128<byte> h2);
        Unsafe.SkipInit(out Vector128<byte> h3);
        Unsafe.SkipInit(out Vector128<byte> h4);
        Unsafe.SkipInit(out Vector128<byte> t);

        Unsafe.SkipInit(out Vector128<byte> ctr1);
        Unsafe.SkipInit(out Vector128<byte> ctr2);
        Unsafe.SkipInit(out Vector128<byte> ctr3);
        Unsafe.SkipInit(out Vector128<byte> ctr4);

        var x = Vector128<byte>.Zero;
        Unsafe.SkipInit(out Vector128<byte> y);

        Span<byte> lastBlock = stackalloc byte[(int)BytesPerBlock];
        ref var lastBlockRef = ref MemoryMarshal.GetReference(lastBlock);

        var nonceLeft = nonceLen;
        var adLeft = adLen;
        var ptLeft = ptLen;

        if (nonceLeft == 96 / 8)
        {
            Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref nonce, 96 / 8);
            Unsafe.Add(ref Unsafe.As<byte, uint>(ref lastBlockRef), 3) = 0x1000000;
            y = Vector128.LoadUnsafe(ref lastBlockRef);

            /*(Compute E[ZERO, KS] and E[Y0, KS] together*/
            tmp1 = x;
            tmp2 = y;
            AesUtil.Encrypt192(ref tmp1, ref tmp2, ref key.EncryptKeySchedule);
            h = tmp1;
            t = tmp2;

            h = Ghash.BswapVec(h);
        }
        else
        {
            h = AesUtil.Encrypt192(ref key.EncryptKeySchedule, x);

            h = Ghash.BswapVec(h);
            y = Vector128<byte>.Zero;

            while (nonceLeft >= BytesPerBlock)
            {
                tmp1 = Vector128.LoadUnsafe(ref nonce);
                tmp1 = Ghash.BswapVec(tmp1);
                y ^= tmp1;
                y = Ghash.Gfmul(y, h);

                nonce = ref Unsafe.AddByteOffset(ref nonce, BytesPerBlock);
                nonceLeft -= BytesPerBlock;
            }

            if (nonceLeft != 0)
            {
                Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref nonce, (uint)nonceLeft);
                tmp1 = Vector128.LoadUnsafe(ref lastBlockRef);
                tmp1 = Ghash.BswapVec(tmp1);
                y ^= tmp1;
                y = Ghash.Gfmul(y, h);
            }

            tmp1 = Vector128.Create(nonceLen * 8, 0).AsByte();

            y ^= tmp1;
            y = Ghash.Gfmul(y, h);
            y = Ghash.BswapVec(y);
            t = AesUtil.Encrypt192(ref key.EncryptKeySchedule, y);
        }

        h2 = Ghash.Gfmul(h, h);
        h3 = Ghash.Gfmul(h, h2);
        h4 = Ghash.Gfmul(h, h3);

        while (adLeft >= BytesPerBlock * 4)
        {
            tmp1 = Vector128.LoadUnsafe(ref ad);
            tmp2 = Vector128.LoadUnsafe(ref ad, 1 * BytesPerBlock);
            tmp3 = Vector128.LoadUnsafe(ref ad, 2 * BytesPerBlock);
            tmp4 = Vector128.LoadUnsafe(ref ad, 3 * BytesPerBlock);

            tmp1 = Ghash.BswapVec(tmp1);
            tmp2 = Ghash.BswapVec(tmp2);
            tmp3 = Ghash.BswapVec(tmp3);
            tmp4 = Ghash.BswapVec(tmp4);
            tmp1 ^= x;

            x = Ghash.Reduce4(h, h2, h3, h4, tmp4, tmp3, tmp2, tmp1);

            ad = ref Unsafe.AddByteOffset(ref ad, 4 * BytesPerBlock);
            adLeft -= BytesPerBlock * 4;
        }

        while (adLeft >= BytesPerBlock)
        {
            tmp1 = Vector128.LoadUnsafe(ref ad);
            tmp1 = Ghash.BswapVec(tmp1);
            x ^= tmp1;
            x = Ghash.Gfmul(x, h);

            ad = ref Unsafe.AddByteOffset(ref ad, BytesPerBlock);
            adLeft -= BytesPerBlock;
        }

        if (adLeft != 0)
        {
            lastBlock.Clear();
            Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref ad, (uint)adLeft);
            tmp1 = Vector128.LoadUnsafe(ref lastBlockRef);
            tmp1 = Ghash.BswapVec(tmp1);
            x ^= tmp1;
            x = Ghash.Gfmul(x, h);
        }

        ctr1 = Ghash.Bswap64(y);
        ctr1 = Vector128.Add(ctr1.AsUInt64(), One.AsUInt64()).AsByte();
        ctr2 = Vector128.Add(ctr1.AsUInt64(), One.AsUInt64()).AsByte();
        ctr3 = Vector128.Add(ctr2.AsUInt64(), One.AsUInt64()).AsByte();
        ctr4 = Vector128.Add(ctr3.AsUInt64(), One.AsUInt64()).AsByte();

        while (ptLeft >= BytesPerBlock * 4)
        {
            tmp1 = Ghash.Bswap64(ctr1);
            tmp2 = Ghash.Bswap64(ctr2);
            tmp3 = Ghash.Bswap64(ctr3);
            tmp4 = Ghash.Bswap64(ctr4);

            ctr1 = Vector128.Add(ctr1.AsUInt64(), Four.AsUInt64()).AsByte();
            ctr2 = Vector128.Add(ctr2.AsUInt64(), Four.AsUInt64()).AsByte();
            ctr3 = Vector128.Add(ctr3.AsUInt64(), Four.AsUInt64()).AsByte();
            ctr4 = Vector128.Add(ctr4.AsUInt64(), Four.AsUInt64()).AsByte();

            AesUtil.Encrypt192(ref tmp1, ref tmp2, ref tmp3, ref tmp4, ref key.EncryptKeySchedule);

            tmp1 ^= Vector128.LoadUnsafe(ref pt);
            tmp2 ^= Vector128.LoadUnsafe(ref pt, 1 * BytesPerBlock);
            tmp3 ^= Vector128.LoadUnsafe(ref pt, 2 * BytesPerBlock);
            tmp4 ^= Vector128.LoadUnsafe(ref pt, 3 * BytesPerBlock);

            tmp1.StoreUnsafe(ref ct);
            tmp2.StoreUnsafe(ref ct, 1 * BytesPerBlock);
            tmp3.StoreUnsafe(ref ct, 2 * BytesPerBlock);
            tmp4.StoreUnsafe(ref ct, 3 * BytesPerBlock);

            tmp1 = Ghash.BswapVec(tmp1);
            tmp2 = Ghash.BswapVec(tmp2);
            tmp3 = Ghash.BswapVec(tmp3);
            tmp4 = Ghash.BswapVec(tmp4);

            tmp1 ^= x;

            x = Ghash.Reduce4(h, h2, h3, h4, tmp4, tmp3, tmp2, tmp1);

            pt = ref Unsafe.AddByteOffset(ref pt, 4 * BytesPerBlock);
            ct = ref Unsafe.AddByteOffset(ref ct, 4 * BytesPerBlock);
            ptLeft -= BytesPerBlock * 4;
        }

        while (ptLeft >= BytesPerBlock)
        {
            tmp1 = Ghash.Bswap64(ctr1);
            ctr1 = Vector128.Add(ctr1.AsUInt64(), One.AsUInt64()).AsByte();
            tmp1 = AesUtil.Encrypt192(ref key.EncryptKeySchedule, tmp1);
            tmp1 ^= Vector128.LoadUnsafe(ref pt);
            tmp1.StoreUnsafe(ref ct);
            tmp1 = Ghash.BswapVec(tmp1);
            x ^= tmp1;
            x = Ghash.Gfmul(x, h);

            pt = ref Unsafe.AddByteOffset(ref pt, BytesPerBlock);
            ct = ref Unsafe.AddByteOffset(ref ct, BytesPerBlock);
            ptLeft -= BytesPerBlock;
        }

        //If remains one incomplete block
        if (ptLeft != 0)
        {
            tmp1 = Ghash.Bswap64(ctr1);
            tmp1 = AesUtil.Encrypt192(ref key.EncryptKeySchedule, tmp1);
            tmp1 ^= Vector128.LoadUnsafe(ref pt);
            tmp1.StoreUnsafe(ref lastBlockRef);

            Unsafe.CopyBlockUnaligned(ref ct, ref lastBlockRef, (uint)ptLeft);
            Unsafe.InitBlockUnaligned(ref Unsafe.AddByteOffset(ref lastBlockRef, ptLeft), 0x00, (uint)(BytesPerBlock - ptLeft));

            tmp1 = Vector128.LoadUnsafe(ref lastBlockRef);
            tmp1 = Ghash.BswapVec(tmp1);
            x ^= tmp1;
            x = Ghash.Gfmul(x, h);
        }

        tmp1 = Vector128.Create(ptLen * 8, adLen * 8).AsByte();

        x ^= tmp1;
        x = Ghash.Gfmul(x, h);
        x = Ghash.BswapVec(x);
        t ^= x;
        t.StoreUnsafe(ref lastBlockRef);
        Unsafe.CopyBlockUnaligned(ref tag, ref lastBlockRef, (uint)tagLen);
    }

    private static void AeDecrypt192(
        in AesKey key,
        ref byte ct, nuint ctLen,
        ref byte nonce, nuint nonceLen,
        ref byte ad, nuint adLen,
        ref byte pt,
        ref byte tag, nuint tagLen)
    {
        Unsafe.SkipInit(out Vector128<byte> tmp1);
        Unsafe.SkipInit(out Vector128<byte> tmp2);
        Unsafe.SkipInit(out Vector128<byte> tmp3);
        Unsafe.SkipInit(out Vector128<byte> tmp4);

        Unsafe.SkipInit(out Vector128<byte> ct1);
        Unsafe.SkipInit(out Vector128<byte> ct2);
        Unsafe.SkipInit(out Vector128<byte> ct3);
        Unsafe.SkipInit(out Vector128<byte> ct4);

        Unsafe.SkipInit(out Vector128<byte> h);
        Unsafe.SkipInit(out Vector128<byte> h2);
        Unsafe.SkipInit(out Vector128<byte> h3);
        Unsafe.SkipInit(out Vector128<byte> h4);
        Unsafe.SkipInit(out Vector128<byte> t);

        Unsafe.SkipInit(out Vector128<byte> ctr1);
        Unsafe.SkipInit(out Vector128<byte> ctr2);
        Unsafe.SkipInit(out Vector128<byte> ctr3);
        Unsafe.SkipInit(out Vector128<byte> ctr4);

        var x = Vector128<byte>.Zero;
        Unsafe.SkipInit(out Vector128<byte> y);

        Span<byte> lastBlock = stackalloc byte[(int)BytesPerBlock];
        ref var lastBlockRef = ref MemoryMarshal.GetReference(lastBlock);

        var nonceLeft = nonceLen;
        var adLeft = adLen;
        var ctLeft = ctLen;

        if (nonceLeft == 96 / 8)
        {
            Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref nonce, 96 / 8);
            Unsafe.Add(ref Unsafe.As<byte, uint>(ref lastBlockRef), 3) = 0x1000000;
            y = Vector128.LoadUnsafe(ref lastBlockRef);

            /*(Compute E[ZERO, KS] and E[Y0, KS] together*/
            tmp1 = x;
            tmp2 = y;
            AesUtil.Encrypt192(ref tmp1, ref tmp2, ref key.EncryptKeySchedule);
            h = tmp1;
            t = tmp2;

            h = Ghash.BswapVec(h);
        }
        else
        {
            h = AesUtil.Encrypt192(ref key.EncryptKeySchedule, x);

            h = Ghash.BswapVec(h);
            y = Vector128<byte>.Zero;

            while (nonceLeft >= BytesPerBlock)
            {
                tmp1 = Vector128.LoadUnsafe(ref nonce);
                tmp1 = Ghash.BswapVec(tmp1);
                y ^= tmp1;
                y = Ghash.Gfmul(y, h);

                nonce = ref Unsafe.AddByteOffset(ref nonce, BytesPerBlock);
                nonceLeft -= BytesPerBlock;
            }

            if (nonceLeft != 0)
            {
                Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref nonce, (uint)nonceLeft);
                tmp1 = Vector128.LoadUnsafe(ref lastBlockRef);
                tmp1 = Ghash.BswapVec(tmp1);
                y ^= tmp1;
                y = Ghash.Gfmul(y, h);
            }

            tmp1 = Vector128.Create(nonceLen * 8, 0).AsByte();

            y ^= tmp1;
            y = Ghash.Gfmul(y, h);
            y = Ghash.BswapVec(y);
            t = AesUtil.Encrypt192(ref key.EncryptKeySchedule, y);
        }

        h2 = Ghash.Gfmul(h, h);
        h3 = Ghash.Gfmul(h, h2);
        h4 = Ghash.Gfmul(h, h3);

        while (adLeft >= BytesPerBlock * 4)
        {
            tmp1 = Vector128.LoadUnsafe(ref ad);
            tmp2 = Vector128.LoadUnsafe(ref ad, 1 * BytesPerBlock);
            tmp3 = Vector128.LoadUnsafe(ref ad, 2 * BytesPerBlock);
            tmp4 = Vector128.LoadUnsafe(ref ad, 3 * BytesPerBlock);

            tmp1 = Ghash.BswapVec(tmp1);
            tmp2 = Ghash.BswapVec(tmp2);
            tmp3 = Ghash.BswapVec(tmp3);
            tmp4 = Ghash.BswapVec(tmp4);
            tmp1 ^= x;

            x = Ghash.Reduce4(h, h2, h3, h4, tmp4, tmp3, tmp2, tmp1);

            ad = ref Unsafe.AddByteOffset(ref ad, 4 * BytesPerBlock);
            adLeft -= BytesPerBlock * 4;
        }

        while (adLeft >= BytesPerBlock)
        {
            tmp1 = Vector128.LoadUnsafe(ref ad);
            tmp1 = Ghash.BswapVec(tmp1);
            x ^= tmp1;
            x = Ghash.Gfmul(x, h);

            ad = ref Unsafe.AddByteOffset(ref ad, BytesPerBlock);
            adLeft -= BytesPerBlock;
        }

        if (adLeft != 0)
        {
            lastBlock.Clear();
            Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref ad, (uint)adLeft);
            tmp1 = Vector128.LoadUnsafe(ref lastBlockRef);
            tmp1 = Ghash.BswapVec(tmp1);
            x ^= tmp1;
            x = Ghash.Gfmul(x, h);
        }

        ctr1 = Ghash.Bswap64(y);
        ctr1 = Vector128.Add(ctr1.AsUInt64(), One.AsUInt64()).AsByte();
        ctr2 = Vector128.Add(ctr1.AsUInt64(), One.AsUInt64()).AsByte();
        ctr3 = Vector128.Add(ctr2.AsUInt64(), One.AsUInt64()).AsByte();
        ctr4 = Vector128.Add(ctr3.AsUInt64(), One.AsUInt64()).AsByte();

        while (ctLeft >= BytesPerBlock * 4)
        {
            ct1 = Vector128.LoadUnsafe(ref ct);
            ct2 = Vector128.LoadUnsafe(ref ct, 1 * BytesPerBlock);
            ct3 = Vector128.LoadUnsafe(ref ct, 2 * BytesPerBlock);
            ct4 = Vector128.LoadUnsafe(ref ct, 3 * BytesPerBlock);

            tmp1 = Ghash.BswapVec(ct1);
            tmp2 = Ghash.BswapVec(ct2);
            tmp3 = Ghash.BswapVec(ct3);
            tmp4 = Ghash.BswapVec(ct4);

            tmp1 ^= x;

            x = Ghash.Reduce4(h, h2, h3, h4, tmp4, tmp3, tmp2, tmp1);

            tmp1 = Ghash.Bswap64(ctr1);
            tmp2 = Ghash.Bswap64(ctr2);
            tmp3 = Ghash.Bswap64(ctr3);
            tmp4 = Ghash.Bswap64(ctr4);

            ctr1 = Vector128.Add(ctr1.AsUInt64(), Four.AsUInt64()).AsByte();
            ctr2 = Vector128.Add(ctr2.AsUInt64(), Four.AsUInt64()).AsByte();
            ctr3 = Vector128.Add(ctr3.AsUInt64(), Four.AsUInt64()).AsByte();
            ctr4 = Vector128.Add(ctr4.AsUInt64(), Four.AsUInt64()).AsByte();

            AesUtil.Encrypt192(ref tmp1, ref tmp2, ref tmp3, ref tmp4, ref key.EncryptKeySchedule);

            (tmp1 ^ ct1).StoreUnsafe(ref pt);
            (tmp2 ^ ct2).StoreUnsafe(ref pt, 1 * BytesPerBlock);
            (tmp3 ^ ct3).StoreUnsafe(ref pt, 2 * BytesPerBlock);
            (tmp4 ^ ct4).StoreUnsafe(ref pt, 3 * BytesPerBlock);

            ct = ref Unsafe.AddByteOffset(ref ct, 4 * BytesPerBlock);
            pt = ref Unsafe.AddByteOffset(ref pt, 4 * BytesPerBlock);
            ctLeft -= BytesPerBlock * 4;
        }

        while (ctLeft >= BytesPerBlock)
        {
            ct1 = Vector128.LoadUnsafe(ref ct);
            tmp1 = Ghash.BswapVec(ct1);
            x ^= tmp1;
            x = Ghash.Gfmul(x, h);

            tmp1 = Ghash.Bswap64(ctr1);
            ctr1 = Vector128.Add(ctr1.AsUInt64(), One.AsUInt64()).AsByte();
            tmp1 = AesUtil.Encrypt192(ref key.EncryptKeySchedule, tmp1);
            (tmp1 ^ ct1).StoreUnsafe(ref pt);

            ct = ref Unsafe.AddByteOffset(ref ct, BytesPerBlock);
            pt = ref Unsafe.AddByteOffset(ref pt, BytesPerBlock);
            ctLeft -= BytesPerBlock;
        }

        //If remains one incomplete block
        if (ctLeft != 0)
        {
            Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref ct, (uint)ctLeft);
            Unsafe.InitBlockUnaligned(ref Unsafe.AddByteOffset(ref lastBlockRef, ctLeft), 0x00, (uint)(BytesPerBlock - ctLeft));

            ct1 = Vector128.LoadUnsafe(ref lastBlockRef);
            tmp1 = Ghash.BswapVec(ct1);
            x ^= tmp1;
            x = Ghash.Gfmul(x, h);

            tmp1 = Ghash.Bswap64(ctr1);
            tmp1 = AesUtil.Encrypt192(ref key.EncryptKeySchedule, tmp1);
            (tmp1 ^ ct1).StoreUnsafe(ref lastBlockRef);

            Unsafe.CopyBlockUnaligned(ref pt, ref lastBlockRef, (uint)ctLeft);
        }

        tmp1 = Vector128.Create(ctLen * 8, adLen * 8).AsByte();

        x ^= tmp1;
        x = Ghash.Gfmul(x, h);
        x = Ghash.BswapVec(x);
        t ^= x;
        t.StoreUnsafe(ref lastBlockRef);
        Unsafe.CopyBlockUnaligned(ref tag, ref lastBlockRef, (uint)tagLen);
    }
}