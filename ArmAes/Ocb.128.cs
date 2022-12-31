using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using static ArmAes.OcbHelpers;

namespace ArmAes;

public static partial class Ocb
{
    private static void AeEncrypt128(
        in OcbContext ctx,
        in AesKey key,
        ref byte pt, nuint ptLen,
        ref byte nonce,
        ref byte ad, nuint adLen,
        ref byte ct,
        ref byte tag, nuint tagLen)
    {
        Unsafe.SkipInit(out Vector128<byte> oa0);
        Unsafe.SkipInit(out Vector128<byte> oa1);
        Unsafe.SkipInit(out Vector128<byte> oa2);
        Unsafe.SkipInit(out Vector128<byte> oa3);
        Unsafe.SkipInit(out Vector128<byte> ta0);
        Unsafe.SkipInit(out Vector128<byte> ta1);
        Unsafe.SkipInit(out Vector128<byte> ta2);
        Unsafe.SkipInit(out Vector128<byte> ta3);

        var adChecksum = ProcessAd128(ctx, ref key.EncryptKeySchedule, ref ad, adLen);
        var offset = GenOffsetFromNonce128(ref nonce, ref key.EncryptKeySchedule, tagLen);
        var checksum  = Vector128<byte>.Zero;
        var l0 = ctx.L(0);
        var l1 = ctx.L(1);

        var (i, remaining) = Math.DivRem(ptLen, Bpi * 16);
        if (i > 0)
        {
            nuint blockNum = 0;
            oa3 = offset;
            do
            {
                blockNum += Bpi;
                var lLast = ctx.L(nuint.TrailingZeroCount(blockNum));
                var pt0 = Vector128.LoadUnsafe(ref pt);
                var pt1 = Vector128.LoadUnsafe(ref pt, 1 * BytesPerBlock);
                var pt2 = Vector128.LoadUnsafe(ref pt, 2 * BytesPerBlock);
                var pt3 = Vector128.LoadUnsafe(ref pt, 3 * BytesPerBlock);

                oa0 = oa3 ^ l0;
                ta0 = oa0 ^ pt0;
                checksum ^= pt0;

                oa1 = oa0 ^ l1;
                ta1 = oa1 ^ pt1;
                checksum ^= pt1;

                oa2 = oa1 ^ l0;
                ta2 = oa2 ^ pt2;
                checksum ^= pt2;

                oa3 = oa2 ^ lLast;
                ta3 = oa3 ^ pt3;
                checksum ^= pt3;

                AesUtil.Encrypt128(ref ta0, ref ta1, ref ta2, ref ta3, ref key.EncryptKeySchedule);

                (ta0 ^ oa0).StoreUnsafe(ref ct);
                (ta1 ^ oa1).StoreUnsafe(ref ct, 1 * BytesPerBlock);
                (ta2 ^ oa2).StoreUnsafe(ref ct, 2 * BytesPerBlock);
                (ta3 ^ oa3).StoreUnsafe(ref ct, 3 * BytesPerBlock);

                pt = ref Unsafe.AddByteOffset(ref pt, 4 * BytesPerBlock);
                ct = ref Unsafe.AddByteOffset(ref ct, 4 * BytesPerBlock);
            } while (--i > 0);
            offset = oa3;
        }

        Span<byte> tmp = stackalloc byte[Vector128<byte>.Count];
        ref var last = ref ta0;
        nuint k = 0;

        if (remaining > 0)
        {
            if (remaining >= 48)
            {
                var pt0 = Vector128.LoadUnsafe(ref pt);
                var pt1 = Vector128.LoadUnsafe(ref pt, 1 * BytesPerBlock);
                var pt2 = Vector128.LoadUnsafe(ref pt, 2 * BytesPerBlock);

                oa0 = offset ^ l0;
                ta0 = oa0 ^ pt0;
                checksum ^= pt0;

                oa1 = oa0 ^ l1;
                ta1 = oa1 ^ pt1;
                checksum ^= pt1;

                offset = oa2 = oa1 ^ l0;
                ta2 = offset ^ pt2;
                checksum ^= pt2;

                last = ref ta3;
                remaining -= 48;
                k = 3;
            }
            else if (remaining >= 32)
            {
                var pt0 = Vector128.LoadUnsafe(ref pt);
                var pt1 = Vector128.LoadUnsafe(ref pt, 1 * BytesPerBlock);

                oa0 = offset ^ l0;
                ta0 = oa0 ^ pt0;
                checksum ^= pt0;

                offset = oa1 = oa0 ^ l1;
                ta1 = offset ^ pt1;
                checksum ^= pt1;

                last = ref ta2;
                remaining -= 32;
                k = 2;
            }
            else if (remaining >= 16)
            {
                var pt0 = Vector128.LoadUnsafe(ref pt);

                offset = oa0 = offset ^ l0;
                ta0 = offset ^ pt0;
                checksum ^= pt0;

                last = ref ta1;
                remaining -= 16;
                k = 1;
            }

            if (remaining > 0) {
                tmp.Clear();
                Unsafe.CopyBlockUnaligned(
                    destination: ref MemoryMarshal.GetReference(tmp),
                    source: ref Unsafe.AddByteOffset(ref pt, BytesPerBlock * k),
                    byteCount: (uint)remaining
                );
                tmp[(int)remaining] = (byte)0x80u;
                checksum ^= Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(tmp));
                last = offset ^= ctx.Lstar;
            }
        }

        AesUtil.Encrypt128(ref ta0, ref ta1, ref ta2, ref ta3, ref key.EncryptKeySchedule);

        offset ^= ctx.Ldollar;
        var fin = offset ^ checksum;
        fin = AesUtil.Encrypt128(ref key.EncryptKeySchedule, fin);
        offset = fin ^ adChecksum;

        if (remaining > 0)
        {
            ref var tmpRef = ref MemoryMarshal.GetReference(tmp);
            (Vector128.LoadUnsafe(ref tmpRef) ^ last).StoreUnsafe(ref tmpRef);
            Unsafe.CopyBlockUnaligned(ref Unsafe.AddByteOffset(ref ct, k * BytesPerBlock), ref tmpRef, (uint)remaining);
        }

        if (k == 3)
        {
            (ta2 ^ oa2).StoreUnsafe(ref ct, 2 * BytesPerBlock);
            (ta1 ^ oa1).StoreUnsafe(ref ct, 1 * BytesPerBlock);
            (ta0 ^ oa0).StoreUnsafe(ref ct);
        }
        else if (k == 2)
        {
            (ta1 ^ oa1).StoreUnsafe(ref ct, 1 * BytesPerBlock);
            (ta0 ^ oa0).StoreUnsafe(ref ct);
        }
        else if (k == 1)
        {
            (ta0 ^ oa0).StoreUnsafe(ref ct);
        }

        offset.StoreUnsafe(ref MemoryMarshal.GetReference(tmp));
        Unsafe.CopyBlockUnaligned(ref tag, ref MemoryMarshal.GetReference(tmp), (uint)tagLen);
    }

    private static bool AeDecrypt128(
        in OcbContext ctx,
        in AesKey key,
        ref byte ct, nuint ctLen,
        ref byte nonce,
        ref byte ad, nuint adLen,
        ref byte pt,
        ref byte tag, nuint tagLen)
    {
        Unsafe.SkipInit(out Vector128<byte> oa0);
        Unsafe.SkipInit(out Vector128<byte> oa1);
        Unsafe.SkipInit(out Vector128<byte> oa2);
        Unsafe.SkipInit(out Vector128<byte> oa3);
        Unsafe.SkipInit(out Vector128<byte> ta0);
        Unsafe.SkipInit(out Vector128<byte> ta1);
        Unsafe.SkipInit(out Vector128<byte> ta2);
        Unsafe.SkipInit(out Vector128<byte> ta3);

        var adChecksum = ProcessAd128(ctx, ref key.EncryptKeySchedule, ref ad, adLen);
        var offset = GenOffsetFromNonce128(ref nonce, ref key.EncryptKeySchedule, tagLen);
        var checksum  = Vector128<byte>.Zero;

        var l0 = ctx.L(0);
        var l1 = ctx.L(1);

        var (i, remaining) = Math.DivRem(ctLen, Bpi * 16);
        if (i > 0)
        {
            nuint blockNum = 0;
            oa3 = offset;
            do
            {
                blockNum += Bpi;
                var lLast = ctx.L(nuint.TrailingZeroCount(blockNum));
                var ct0 = Vector128.LoadUnsafe(ref ct);
                var ct1 = Vector128.LoadUnsafe(ref ct, 1 * BytesPerBlock);
                var ct2 = Vector128.LoadUnsafe(ref ct, 2 * BytesPerBlock);
                var ct3 = Vector128.LoadUnsafe(ref ct, 3 * BytesPerBlock);

                oa0 = oa3 ^ l0;
                ta0 = oa0 ^ ct0;

                oa1 = oa0 ^ l1;
                ta1 = oa1 ^ ct1;

                oa2 = oa1 ^ l0;
                ta2 = oa2 ^ ct2;

                oa3 = oa2 ^ lLast;
                ta3 = oa3 ^ ct3;

                AesUtil.Decrypt128(ref ta0, ref ta1, ref ta2, ref ta3, ref key.DecryptKeySchedule);

                var res0 = ta0 ^ oa0;
                checksum ^= res0;
                res0.StoreUnsafe(ref pt);

                var res1 = ta1 ^ oa1;
                checksum ^= res1;
                res1.StoreUnsafe(ref pt, 1 * BytesPerBlock);

                var res2 = ta2 ^ oa2;
                checksum ^= res2;
                res2.StoreUnsafe(ref pt, 2 * BytesPerBlock);

                var res3 = ta3 ^ oa3;
                checksum ^= res3;
                res3.StoreUnsafe(ref pt, 3 * BytesPerBlock);

                pt = ref Unsafe.AddByteOffset(ref pt, 4 * BytesPerBlock);
                ct = ref Unsafe.AddByteOffset(ref ct, 4 * BytesPerBlock);
            } while (--i > 0);
            offset = oa3;
        }

        Span<byte> tmp = stackalloc byte[Vector128<byte>.Count];
        ref var last = ref ta0;
        nuint k = 0;

        if (remaining > 0)
        {
            if (remaining >= 48)
            {
                var ct0 = Vector128.LoadUnsafe(ref ct);
                var ct1 = Vector128.LoadUnsafe(ref ct, 1 * BytesPerBlock);
                var ct2 = Vector128.LoadUnsafe(ref ct, 2 * BytesPerBlock);

                oa0 = offset ^ l0;
                ta0 = oa0 ^ ct0;

                oa1 = oa0 ^ l1;
                ta1 = oa1 ^ ct1;

                offset = oa2 = oa1 ^ l0;
                ta2 = oa2 ^ ct2;

                last = ref ta3;
                remaining -= 48;
                k = 3;
            }
            else if (remaining >= 32)
            {
                var ct0 = Vector128.LoadUnsafe(ref ct);
                var ct1 = Vector128.LoadUnsafe(ref ct, 1 * BytesPerBlock);

                oa0 = offset ^ l0;
                ta0 = oa0 ^ ct0;

                offset = oa1 = oa0 ^ l1;
                ta1 = oa1 ^ ct1;

                last = ref ta2;
                remaining -= 32;
                k = 2;
            }
            else if (remaining >= 16)
            {
                var ct0 = Vector128.LoadUnsafe(ref ct);

                offset = oa0 = offset ^ l0;
                ta0 = oa0 ^ ct0;

                last = ref ta1;
                remaining -= 16;
                k = 1;
            }

            if (remaining > 0) {
                offset ^= ctx.Lstar;
                var pad = AesUtil.Encrypt128(ref key.EncryptKeySchedule, offset);
                pad.StoreUnsafe(ref MemoryMarshal.GetReference(tmp));

                Unsafe.CopyBlockUnaligned(
                    destination: ref MemoryMarshal.GetReference(tmp),
                    source: ref Unsafe.AddByteOffset(ref ct, BytesPerBlock * k),
                    byteCount: (uint)remaining
                );

                var tmpV = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(tmp));
                tmpV ^= pad;
                tmpV.StoreUnsafe(ref MemoryMarshal.GetReference(tmp));
                tmp[(int)remaining] = (byte)0x80u;

                Unsafe.CopyBlockUnaligned(
                    destination: ref Unsafe.AddByteOffset(ref pt, BytesPerBlock * k),
                    source: ref MemoryMarshal.GetReference(tmp),
                    byteCount: (uint)remaining
                );

                checksum ^= Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(tmp));
            }
        }

        AesUtil.Decrypt128(ref ta0, ref ta1, ref ta2, ref ta3, ref key.DecryptKeySchedule);

        if (k == 3)
        {
            var res2 = ta2 ^ oa2;
            checksum ^= res2;
            res2.StoreUnsafe(ref pt, 2 * BytesPerBlock);

            var res1 = ta1 ^ oa1;
            checksum ^= res1;
            res1.StoreUnsafe(ref pt, 1 * BytesPerBlock);

            var res0 = ta0 ^ oa0;
            checksum ^= res0;
            res0.StoreUnsafe(ref pt);
        }
        else if (k == 2)
        {
            var res1 = ta1 ^ oa1;
            checksum ^= res1;
            res1.StoreUnsafe(ref pt, 1 * BytesPerBlock);

            var res0 = ta0 ^ oa0;
            checksum ^= res0;
            res0.StoreUnsafe(ref pt);
        }
        else if (k == 1)
        {
            var res0 = ta0 ^ oa0;
            checksum ^= res0;
            res0.StoreUnsafe(ref pt);
        }

        offset ^= ctx.Ldollar;
        var cTag = offset ^ checksum;
        cTag = AesUtil.Encrypt128(ref key.EncryptKeySchedule, cTag);
        cTag ^= adChecksum;

        if (tagLen == 16)
        {
            return cTag == Vector128.LoadUnsafe(ref tag);
        }
        else
        {
            cTag.StoreUnsafe(ref MemoryMarshal.GetReference(tmp));
            var actual = MemoryMarshal.CreateSpan(ref tag, (int)tagLen);
            var result = CryptographicOperations.FixedTimeEquals(tmp[..(int)tagLen], actual);
            return result;
        }
    }

    private static Vector128<byte> ProcessAd128(
        in OcbContext ctx,
        ref byte keySchedule,
        ref byte ad, nuint adLen)
    {
        Unsafe.SkipInit(out Vector128<byte> oa0);
        Unsafe.SkipInit(out Vector128<byte> oa1);
        Unsafe.SkipInit(out Vector128<byte> oa2);
        Unsafe.SkipInit(out Vector128<byte> ta0);
        Unsafe.SkipInit(out Vector128<byte> ta1);
        Unsafe.SkipInit(out Vector128<byte> ta2);
        Unsafe.SkipInit(out Vector128<byte> ta3);

        var adOffset = Vector128<byte>.Zero;
        var adChecksum = Vector128<byte>.Zero;
        var l0 = ctx.L(0);
        var l1 = ctx.L(1);
        var (i, remaining) = Math.DivRem(adLen, Bpi * 16);
        if (i > 0)
        {
            nuint adBlockNum = 0;
            do
            {
                adBlockNum += Bpi;
                var lLast = ctx.L(nuint.TrailingZeroCount(adBlockNum));
                var ad0 = Vector128.LoadUnsafe(ref ad);
                var ad1 = Vector128.LoadUnsafe(ref ad, 1 * BytesPerBlock);
                var ad2 = Vector128.LoadUnsafe(ref ad, 2 * BytesPerBlock);
                var ad3 = Vector128.LoadUnsafe(ref ad, 3 * BytesPerBlock);

                oa0 = adOffset ^ l0;
                ta0 = oa0 ^ ad0;

                oa1 = oa0 ^ l1;
                ta1 = oa1 ^ ad1;

                oa2 = adOffset ^ l1;
                ta2 = oa2 ^ ad2;

                adOffset = oa2 ^ lLast;
                ta3 = adOffset ^ ad3;

                AesUtil.Encrypt128(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);

                adChecksum ^= ta0;
                adChecksum ^= ta1;
                adChecksum ^= ta2;
                adChecksum ^= ta3;

                ad = ref Unsafe.AddByteOffset(ref ad, BytesPerBlock * 4);
            } while (--i > 0);
        }

        if (remaining == 0) return adChecksum;

        ref var last = ref ta0;
        nuint k = 0;
        if (remaining >= 48)
        {
            var ad0 = Vector128.LoadUnsafe(ref ad);
            var ad1 = Vector128.LoadUnsafe(ref ad, BytesPerBlock * 1);
            var ad2 = Vector128.LoadUnsafe(ref ad, BytesPerBlock * 2);

            adOffset ^= l0;
            ta0 = adOffset ^ ad0;

            adOffset ^= l1;
            ta1 = adOffset ^ ad1;

            adOffset ^= l0;
            ta2 = adOffset ^ ad2;

            last = ref ta3;
            remaining -= 48;
            k = 3;
        }
        else if (remaining >= 32)
        {
            var ad0 = Vector128.LoadUnsafe(ref ad);
            var ad1 = Vector128.LoadUnsafe(ref ad, BytesPerBlock * 1);

            adOffset ^= l0;
            ta0 = adOffset ^ ad0;

            adOffset ^= l1;
            ta1 = adOffset ^ ad1;

            last = ref ta2;
            remaining -= 32;
            k = 2;
        }
        else if (remaining >= 16)
        {
            var ad0 = Vector128.LoadUnsafe(ref ad);

            adOffset ^= l0;
            ta0 = adOffset ^ ad0;

            last = ref ta1;
            remaining -= 16;
            k = 1;
        }

        if (remaining > 0) {
            adOffset ^= ctx.Lstar;
            Span<byte> tmp = stackalloc byte[Vector128<byte>.Count];
            tmp.Clear();
            Unsafe.CopyBlockUnaligned(
                destination: ref MemoryMarshal.GetReference(tmp),
                source: ref Unsafe.AddByteOffset(ref ad, BytesPerBlock * k),
                byteCount: (uint)remaining
            );
            tmp[(int)remaining] = (byte)0x80u;
            last = adOffset ^ Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(tmp));
            k++;
        }

        AesUtil.Encrypt128(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);

        return k switch
        {
            4 => adChecksum ^ ta3 ^ ta2 ^ ta1 ^ ta0,
            3 => adChecksum ^ ta2 ^ ta1 ^ ta0,
            2 => adChecksum ^ ta1 ^ ta0,
            _ => adChecksum ^ ta0
        };
    }
}