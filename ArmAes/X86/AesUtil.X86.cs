using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace ArmAes;

internal static partial class AesUtil
{
    private static class X86
    {
        #region 128

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Encrypt128(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
            ref Vector128<byte> ta2,
            ref Vector128<byte> ta3,
            ref byte keySchedule)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);

            // ROUND 0 - whitening
            ta0 ^= key0;
            ta1 ^= key0;
            ta2 ^= key0;
            ta3 ^= key0;

            // ROUND 1
            ta0 = Aes.Encrypt(ta0, key1);
            ta1 = Aes.Encrypt(ta1, key1);
            ta2 = Aes.Encrypt(ta2, key1);
            ta3 = Aes.Encrypt(ta3, key1);

            // ROUND 2
            ta0 = Aes.Encrypt(ta0, key2);
            ta1 = Aes.Encrypt(ta1, key2);
            ta2 = Aes.Encrypt(ta2, key2);
            ta3 = Aes.Encrypt(ta3, key2);

            // ROUND 3
            ta0 = Aes.Encrypt(ta0, key3);
            ta1 = Aes.Encrypt(ta1, key3);
            ta2 = Aes.Encrypt(ta2, key3);
            ta3 = Aes.Encrypt(ta3, key3);

            // ROUND 4
            ta0 = Aes.Encrypt(ta0, key4);
            ta1 = Aes.Encrypt(ta1, key4);
            ta2 = Aes.Encrypt(ta2, key4);
            ta3 = Aes.Encrypt(ta3, key4);

            // ROUND 5
            ta0 = Aes.Encrypt(ta0, key5);
            ta1 = Aes.Encrypt(ta1, key5);
            ta2 = Aes.Encrypt(ta2, key5);
            ta3 = Aes.Encrypt(ta3, key5);

            // ROUND 6
            ta0 = Aes.Encrypt(ta0, key6);
            ta1 = Aes.Encrypt(ta1, key6);
            ta2 = Aes.Encrypt(ta2, key6);
            ta3 = Aes.Encrypt(ta3, key6);

            // ROUND 7
            ta0 = Aes.Encrypt(ta0, key7);
            ta1 = Aes.Encrypt(ta1, key7);
            ta2 = Aes.Encrypt(ta2, key7);
            ta3 = Aes.Encrypt(ta3, key7);

            // ROUND 8
            ta0 = Aes.Encrypt(ta0, key8);
            ta1 = Aes.Encrypt(ta1, key8);
            ta2 = Aes.Encrypt(ta2, key8);
            ta3 = Aes.Encrypt(ta3, key8);

            // ROUND 9
            ta0 = Aes.Encrypt(ta0, key9);
            ta1 = Aes.Encrypt(ta1, key9);
            ta2 = Aes.Encrypt(ta2, key9);
            ta3 = Aes.Encrypt(ta3, key9);

            // ROUND 9
            ta0 = Aes.EncryptLast(ta0, key10);
            ta1 = Aes.EncryptLast(ta1, key10);
            ta2 = Aes.EncryptLast(ta2, key10);
            ta3 = Aes.EncryptLast(ta3, key10);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Encrypt128(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
            ref byte keySchedule)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);

            // ROUND 0 - whitening
            ta0 ^= key0;
            ta1 ^= key0;

            // ROUND 1
            ta0 = Aes.Encrypt(ta0, key1);
            ta1 = Aes.Encrypt(ta1, key1);

            // ROUND 2
            ta0 = Aes.Encrypt(ta0, key2);
            ta1 = Aes.Encrypt(ta1, key2);

            // ROUND 3
            ta0 = Aes.Encrypt(ta0, key3);
            ta1 = Aes.Encrypt(ta1, key3);

            // ROUND 4
            ta0 = Aes.Encrypt(ta0, key4);
            ta1 = Aes.Encrypt(ta1, key4);

            // ROUND 5
            ta0 = Aes.Encrypt(ta0, key5);
            ta1 = Aes.Encrypt(ta1, key5);

            // ROUND 6
            ta0 = Aes.Encrypt(ta0, key6);
            ta1 = Aes.Encrypt(ta1, key6);

            // ROUND 7
            ta0 = Aes.Encrypt(ta0, key7);
            ta1 = Aes.Encrypt(ta1, key7);

            // ROUND 8
            ta0 = Aes.Encrypt(ta0, key8);
            ta1 = Aes.Encrypt(ta1, key8);

            // ROUND 9
            ta0 = Aes.Encrypt(ta0, key9);
            ta1 = Aes.Encrypt(ta1, key9);

            // ROUND 9
            ta0 = Aes.EncryptLast(ta0, key10);
            ta1 = Aes.EncryptLast(ta1, key10);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> Encrypt128(ref byte keySchedule, Vector128<byte> input)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);

            var block = input ^ key0;
            block = Aes.Encrypt(block, key1);
            block = Aes.Encrypt(block, key2);
            block = Aes.Encrypt(block, key3);
            block = Aes.Encrypt(block, key4);
            block = Aes.Encrypt(block, key5);
            block = Aes.Encrypt(block, key6);
            block = Aes.Encrypt(block, key7);
            block = Aes.Encrypt(block, key8);
            block = Aes.Encrypt(block, key9);
            return Aes.EncryptLast(block, key10);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Decrypt128(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
            ref Vector128<byte> ta2,
            ref Vector128<byte> ta3,
            ref byte keySchedule)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);

            // ROUND 0 - whitening
            ta0 ^= key0;
            ta1 ^= key0;
            ta2 ^= key0;
            ta3 ^= key0;

            // ROUND 1
            ta0 = Aes.Decrypt(ta0, key1);
            ta1 = Aes.Decrypt(ta1, key1);
            ta2 = Aes.Decrypt(ta2, key1);
            ta3 = Aes.Decrypt(ta3, key1);

            // ROUND 2
            ta0 = Aes.Decrypt(ta0, key2);
            ta1 = Aes.Decrypt(ta1, key2);
            ta2 = Aes.Decrypt(ta2, key2);
            ta3 = Aes.Decrypt(ta3, key2);

            // ROUND 3
            ta0 = Aes.Decrypt(ta0, key3);
            ta1 = Aes.Decrypt(ta1, key3);
            ta2 = Aes.Decrypt(ta2, key3);
            ta3 = Aes.Decrypt(ta3, key3);

            // ROUND 4
            ta0 = Aes.Decrypt(ta0, key4);
            ta1 = Aes.Decrypt(ta1, key4);
            ta2 = Aes.Decrypt(ta2, key4);
            ta3 = Aes.Decrypt(ta3, key4);

            // ROUND 5
            ta0 = Aes.Decrypt(ta0, key5);
            ta1 = Aes.Decrypt(ta1, key5);
            ta2 = Aes.Decrypt(ta2, key5);
            ta3 = Aes.Decrypt(ta3, key5);

            // ROUND 6
            ta0 = Aes.Decrypt(ta0, key6);
            ta1 = Aes.Decrypt(ta1, key6);
            ta2 = Aes.Decrypt(ta2, key6);
            ta3 = Aes.Decrypt(ta3, key6);

            // ROUND 7
            ta0 = Aes.Decrypt(ta0, key7);
            ta1 = Aes.Decrypt(ta1, key7);
            ta2 = Aes.Decrypt(ta2, key7);
            ta3 = Aes.Decrypt(ta3, key7);

            // ROUND 8
            ta0 = Aes.Decrypt(ta0, key8);
            ta1 = Aes.Decrypt(ta1, key8);
            ta2 = Aes.Decrypt(ta2, key8);
            ta3 = Aes.Decrypt(ta3, key8);

            // ROUND 9
            ta0 = Aes.Decrypt(ta0, key9);
            ta1 = Aes.Decrypt(ta1, key9);
            ta2 = Aes.Decrypt(ta2, key9);
            ta3 = Aes.Decrypt(ta3, key9);

            // ROUND 10
            ta0 = Aes.DecryptLast(ta0, key10);
            ta1 = Aes.DecryptLast(ta1, key10);
            ta2 = Aes.DecryptLast(ta2, key10);
            ta3 = Aes.DecryptLast(ta3, key10);
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
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);
            var key11 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 11);
            var key12 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 12);

            // ROUND 0 - whitening
            ta0 ^= key0;
            ta1 ^= key0;
            ta2 ^= key0;
            ta3 ^= key0;

            // ROUND 1
            ta0 = Aes.Encrypt(ta0, key1);
            ta1 = Aes.Encrypt(ta1, key1);
            ta2 = Aes.Encrypt(ta2, key1);
            ta3 = Aes.Encrypt(ta3, key1);

            // ROUND 2
            ta0 = Aes.Encrypt(ta0, key2);
            ta1 = Aes.Encrypt(ta1, key2);
            ta2 = Aes.Encrypt(ta2, key2);
            ta3 = Aes.Encrypt(ta3, key2);

            // ROUND 3
            ta0 = Aes.Encrypt(ta0, key3);
            ta1 = Aes.Encrypt(ta1, key3);
            ta2 = Aes.Encrypt(ta2, key3);
            ta3 = Aes.Encrypt(ta3, key3);

            // ROUND 4
            ta0 = Aes.Encrypt(ta0, key4);
            ta1 = Aes.Encrypt(ta1, key4);
            ta2 = Aes.Encrypt(ta2, key4);
            ta3 = Aes.Encrypt(ta3, key4);

            // ROUND 5
            ta0 = Aes.Encrypt(ta0, key5);
            ta1 = Aes.Encrypt(ta1, key5);
            ta2 = Aes.Encrypt(ta2, key5);
            ta3 = Aes.Encrypt(ta3, key5);

            // ROUND 6
            ta0 = Aes.Encrypt(ta0, key6);
            ta1 = Aes.Encrypt(ta1, key6);
            ta2 = Aes.Encrypt(ta2, key6);
            ta3 = Aes.Encrypt(ta3, key6);

            // ROUND 7
            ta0 = Aes.Encrypt(ta0, key7);
            ta1 = Aes.Encrypt(ta1, key7);
            ta2 = Aes.Encrypt(ta2, key7);
            ta3 = Aes.Encrypt(ta3, key7);

            // ROUND 8
            ta0 = Aes.Encrypt(ta0, key8);
            ta1 = Aes.Encrypt(ta1, key8);
            ta2 = Aes.Encrypt(ta2, key8);
            ta3 = Aes.Encrypt(ta3, key8);

            // ROUND 9
            ta0 = Aes.Encrypt(ta0, key9);
            ta1 = Aes.Encrypt(ta1, key9);
            ta2 = Aes.Encrypt(ta2, key9);
            ta3 = Aes.Encrypt(ta3, key9);

            // ROUND 10
            ta0 = Aes.Encrypt(ta0, key10);
            ta1 = Aes.Encrypt(ta1, key10);
            ta2 = Aes.Encrypt(ta2, key10);
            ta3 = Aes.Encrypt(ta3, key10);

            // ROUND 11
            ta0 = Aes.Encrypt(ta0, key11);
            ta1 = Aes.Encrypt(ta1, key11);
            ta2 = Aes.Encrypt(ta2, key11);
            ta3 = Aes.Encrypt(ta3, key11);

            // ROUND 12
            ta0 = Aes.EncryptLast(ta0, key12);
            ta1 = Aes.EncryptLast(ta1, key12);
            ta2 = Aes.EncryptLast(ta2, key12);
            ta3 = Aes.EncryptLast(ta3, key12);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Encrypt192(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
            ref byte keySchedule)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);
            var key11 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 11);
            var key12 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 12);

            // ROUND 0 - whitening
            ta0 ^= key0;
            ta1 ^= key0;

            // ROUND 1
            ta0 = Aes.Encrypt(ta0, key1);
            ta1 = Aes.Encrypt(ta1, key1);

            // ROUND 2
            ta0 = Aes.Encrypt(ta0, key2);
            ta1 = Aes.Encrypt(ta1, key2);

            // ROUND 3
            ta0 = Aes.Encrypt(ta0, key3);
            ta1 = Aes.Encrypt(ta1, key3);

            // ROUND 4
            ta0 = Aes.Encrypt(ta0, key4);
            ta1 = Aes.Encrypt(ta1, key4);

            // ROUND 5
            ta0 = Aes.Encrypt(ta0, key5);
            ta1 = Aes.Encrypt(ta1, key5);

            // ROUND 6
            ta0 = Aes.Encrypt(ta0, key6);
            ta1 = Aes.Encrypt(ta1, key6);

            // ROUND 7
            ta0 = Aes.Encrypt(ta0, key7);
            ta1 = Aes.Encrypt(ta1, key7);

            // ROUND 8
            ta0 = Aes.Encrypt(ta0, key8);
            ta1 = Aes.Encrypt(ta1, key8);

            // ROUND 9
            ta0 = Aes.Encrypt(ta0, key9);
            ta1 = Aes.Encrypt(ta1, key9);

            // ROUND 10
            ta0 = Aes.Encrypt(ta0, key10);
            ta1 = Aes.Encrypt(ta1, key10);

            // ROUND 11
            ta0 = Aes.Encrypt(ta0, key11);
            ta1 = Aes.Encrypt(ta1, key11);

            // ROUND 12
            ta0 = Aes.EncryptLast(ta0, key12);
            ta1 = Aes.EncryptLast(ta1, key12);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> Encrypt192(ref byte keySchedule, Vector128<byte> input)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);
            var key11 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 11);
            var key12 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 12);

            var block = input ^ key0;
            block = Aes.Encrypt(block, key1);
            block = Aes.Encrypt(block, key2);
            block = Aes.Encrypt(block, key3);
            block = Aes.Encrypt(block, key4);
            block = Aes.Encrypt(block, key5);
            block = Aes.Encrypt(block, key6);
            block = Aes.Encrypt(block, key7);
            block = Aes.Encrypt(block, key8);
            block = Aes.Encrypt(block, key9);
            block = Aes.Encrypt(block, key10);
            block = Aes.Encrypt(block, key11);
            return Aes.EncryptLast(block, key12);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Decrypt192(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
            ref Vector128<byte> ta2,
            ref Vector128<byte> ta3,
            ref byte keySchedule)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);
            var key11 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 11);
            var key12 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 12);

            // ROUND 0 - whitening
            ta0 ^= key0;
            ta1 ^= key0;
            ta2 ^= key0;
            ta3 ^= key0;

            // ROUND 1
            ta0 = Aes.Decrypt(ta0, key1);
            ta1 = Aes.Decrypt(ta1, key1);
            ta2 = Aes.Decrypt(ta2, key1);
            ta3 = Aes.Decrypt(ta3, key1);

            // ROUND 2
            ta0 = Aes.Decrypt(ta0, key2);
            ta1 = Aes.Decrypt(ta1, key2);
            ta2 = Aes.Decrypt(ta2, key2);
            ta3 = Aes.Decrypt(ta3, key2);

            // ROUND 3
            ta0 = Aes.Decrypt(ta0, key3);
            ta1 = Aes.Decrypt(ta1, key3);
            ta2 = Aes.Decrypt(ta2, key3);
            ta3 = Aes.Decrypt(ta3, key3);

            // ROUND 4
            ta0 = Aes.Decrypt(ta0, key4);
            ta1 = Aes.Decrypt(ta1, key4);
            ta2 = Aes.Decrypt(ta2, key4);
            ta3 = Aes.Decrypt(ta3, key4);

            // ROUND 5
            ta0 = Aes.Decrypt(ta0, key5);
            ta1 = Aes.Decrypt(ta1, key5);
            ta2 = Aes.Decrypt(ta2, key5);
            ta3 = Aes.Decrypt(ta3, key5);

            // ROUND 6
            ta0 = Aes.Decrypt(ta0, key6);
            ta1 = Aes.Decrypt(ta1, key6);
            ta2 = Aes.Decrypt(ta2, key6);
            ta3 = Aes.Decrypt(ta3, key6);

            // ROUND 7
            ta0 = Aes.Decrypt(ta0, key7);
            ta1 = Aes.Decrypt(ta1, key7);
            ta2 = Aes.Decrypt(ta2, key7);
            ta3 = Aes.Decrypt(ta3, key7);

            // ROUND 8
            ta0 = Aes.Decrypt(ta0, key8);
            ta1 = Aes.Decrypt(ta1, key8);
            ta2 = Aes.Decrypt(ta2, key8);
            ta3 = Aes.Decrypt(ta3, key8);

            // ROUND 9
            ta0 = Aes.Decrypt(ta0, key9);
            ta1 = Aes.Decrypt(ta1, key9);
            ta2 = Aes.Decrypt(ta2, key9);
            ta3 = Aes.Decrypt(ta3, key9);

            // ROUND 10
            ta0 = Aes.Decrypt(ta0, key10);
            ta1 = Aes.Decrypt(ta1, key10);
            ta2 = Aes.Decrypt(ta2, key10);
            ta3 = Aes.Decrypt(ta3, key10);

            // ROUND 11
            ta0 = Aes.Decrypt(ta0, key11);
            ta1 = Aes.Decrypt(ta1, key11);
            ta2 = Aes.Decrypt(ta2, key11);
            ta3 = Aes.Decrypt(ta3, key11);

            // ROUND 12
            ta0 = Aes.DecryptLast(ta0, key12);
            ta1 = Aes.DecryptLast(ta1, key12);
            ta2 = Aes.DecryptLast(ta2, key12);
            ta3 = Aes.DecryptLast(ta3, key12);
        }

        #endregion

        #region 256

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Encrypt256(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
            ref Vector128<byte> ta2,
            ref Vector128<byte> ta3,
            ref byte keySchedule)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);
            var key11 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 11);
            var key12 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 12);
            var key13 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 13);
            var key14 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 14);

            // ROUND 0
            ta0 ^= key0;
            ta1 ^= key0;
            ta2 ^= key0;
            ta3 ^= key0;

            // ROUND 1
            ta0 = Aes.Encrypt(ta0, key1);
            ta1 = Aes.Encrypt(ta1, key1);
            ta2 = Aes.Encrypt(ta2, key1);
            ta3 = Aes.Encrypt(ta3, key1);

            // ROUND 2
            ta0 = Aes.Encrypt(ta0, key2);
            ta1 = Aes.Encrypt(ta1, key2);
            ta2 = Aes.Encrypt(ta2, key2);
            ta3 = Aes.Encrypt(ta3, key2);

            // ROUND 3
            ta0 = Aes.Encrypt(ta0, key3);
            ta1 = Aes.Encrypt(ta1, key3);
            ta2 = Aes.Encrypt(ta2, key3);
            ta3 = Aes.Encrypt(ta3, key3);

            // ROUND 4
            ta0 = Aes.Encrypt(ta0, key4);
            ta1 = Aes.Encrypt(ta1, key4);
            ta2 = Aes.Encrypt(ta2, key4);
            ta3 = Aes.Encrypt(ta3, key4);

            // ROUND 5
            ta0 = Aes.Encrypt(ta0, key5);
            ta1 = Aes.Encrypt(ta1, key5);
            ta2 = Aes.Encrypt(ta2, key5);
            ta3 = Aes.Encrypt(ta3, key5);

            // ROUND 6
            ta0 = Aes.Encrypt(ta0, key6);
            ta1 = Aes.Encrypt(ta1, key6);
            ta2 = Aes.Encrypt(ta2, key6);
            ta3 = Aes.Encrypt(ta3, key6);

            // ROUND 7
            ta0 = Aes.Encrypt(ta0, key7);
            ta1 = Aes.Encrypt(ta1, key7);
            ta2 = Aes.Encrypt(ta2, key7);
            ta3 = Aes.Encrypt(ta3, key7);

            // ROUND 8
            ta0 = Aes.Encrypt(ta0, key8);
            ta1 = Aes.Encrypt(ta1, key8);
            ta2 = Aes.Encrypt(ta2, key8);
            ta3 = Aes.Encrypt(ta3, key8);

            // ROUND 9
            ta0 = Aes.Encrypt(ta0, key9);
            ta1 = Aes.Encrypt(ta1, key9);
            ta2 = Aes.Encrypt(ta2, key9);
            ta3 = Aes.Encrypt(ta3, key9);

            // ROUND 10
            ta0 = Aes.Encrypt(ta0, key10);
            ta1 = Aes.Encrypt(ta1, key10);
            ta2 = Aes.Encrypt(ta2, key10);
            ta3 = Aes.Encrypt(ta3, key10);

            // ROUND 11
            ta0 = Aes.Encrypt(ta0, key11);
            ta1 = Aes.Encrypt(ta1, key11);
            ta2 = Aes.Encrypt(ta2, key11);
            ta3 = Aes.Encrypt(ta3, key11);

            // ROUND 12
            ta0 = Aes.Encrypt(ta0, key12);
            ta1 = Aes.Encrypt(ta1, key12);
            ta2 = Aes.Encrypt(ta2, key12);
            ta3 = Aes.Encrypt(ta3, key12);

            // ROUND 13
            ta0 = Aes.Encrypt(ta0, key13);
            ta1 = Aes.Encrypt(ta1, key13);
            ta2 = Aes.Encrypt(ta2, key13);
            ta3 = Aes.Encrypt(ta3, key13);

            // ROUND 14
            ta0 = Aes.EncryptLast(ta0, key14);
            ta1 = Aes.EncryptLast(ta1, key14);
            ta2 = Aes.EncryptLast(ta2, key14);
            ta3 = Aes.EncryptLast(ta3, key14);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Encrypt256(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
            ref byte keySchedule)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);
            var key11 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 11);
            var key12 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 12);
            var key13 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 13);
            var key14 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 14);

            // ROUND 0
            ta0 ^= key0;
            ta1 ^= key0;

            // ROUND 1
            ta0 = Aes.Encrypt(ta0, key1);
            ta1 = Aes.Encrypt(ta1, key1);

            // ROUND 2
            ta0 = Aes.Encrypt(ta0, key2);
            ta1 = Aes.Encrypt(ta1, key2);

            // ROUND 3
            ta0 = Aes.Encrypt(ta0, key3);
            ta1 = Aes.Encrypt(ta1, key3);

            // ROUND 4
            ta0 = Aes.Encrypt(ta0, key4);
            ta1 = Aes.Encrypt(ta1, key4);

            // ROUND 5
            ta0 = Aes.Encrypt(ta0, key5);
            ta1 = Aes.Encrypt(ta1, key5);

            // ROUND 6
            ta0 = Aes.Encrypt(ta0, key6);
            ta1 = Aes.Encrypt(ta1, key6);

            // ROUND 7
            ta0 = Aes.Encrypt(ta0, key7);
            ta1 = Aes.Encrypt(ta1, key7);

            // ROUND 8
            ta0 = Aes.Encrypt(ta0, key8);
            ta1 = Aes.Encrypt(ta1, key8);

            // ROUND 9
            ta0 = Aes.Encrypt(ta0, key9);
            ta1 = Aes.Encrypt(ta1, key9);

            // ROUND 10
            ta0 = Aes.Encrypt(ta0, key10);
            ta1 = Aes.Encrypt(ta1, key10);

            // ROUND 11
            ta0 = Aes.Encrypt(ta0, key11);
            ta1 = Aes.Encrypt(ta1, key11);

            // ROUND 12
            ta0 = Aes.Encrypt(ta0, key12);
            ta1 = Aes.Encrypt(ta1, key12);

            // ROUND 13
            ta0 = Aes.Encrypt(ta0, key13);
            ta1 = Aes.Encrypt(ta1, key13);

            // ROUND 14
            ta0 = Aes.EncryptLast(ta0, key14);
            ta1 = Aes.EncryptLast(ta1, key14);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> Encrypt256(ref byte keySchedule, Vector128<byte> input)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);
            var key11 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 11);
            var key12 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 12);
            var key13 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 13);
            var key14 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 14);

            var block = input ^ key0;
            block = Aes.Encrypt(block, key1);
            block = Aes.Encrypt(block, key2);
            block = Aes.Encrypt(block, key3);
            block = Aes.Encrypt(block, key4);
            block = Aes.Encrypt(block, key5);
            block = Aes.Encrypt(block, key6);
            block = Aes.Encrypt(block, key7);
            block = Aes.Encrypt(block, key8);
            block = Aes.Encrypt(block, key9);
            block = Aes.Encrypt(block, key10);
            block = Aes.Encrypt(block, key11);
            block = Aes.Encrypt(block, key12);
            block = Aes.Encrypt(block, key13);
            return Aes.EncryptLast(block, key14);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Decrypt256(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
            ref Vector128<byte> ta2,
            ref Vector128<byte> ta3,
            ref byte keySchedule)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);
            var key11 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 11);
            var key12 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 12);
            var key13 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 13);
            var key14 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 14);

            // ROUND 0
            ta0 ^= key0;
            ta1 ^= key0;
            ta2 ^= key0;
            ta3 ^= key0;

            // ROUND 1
            ta0 = Aes.Decrypt(ta0, key1);
            ta1 = Aes.Decrypt(ta1, key1);
            ta2 = Aes.Decrypt(ta2, key1);
            ta3 = Aes.Decrypt(ta3, key1);

            // ROUND 2
            ta0 = Aes.Decrypt(ta0, key2);
            ta1 = Aes.Decrypt(ta1, key2);
            ta2 = Aes.Decrypt(ta2, key2);
            ta3 = Aes.Decrypt(ta3, key2);

            // ROUND 3
            ta0 = Aes.Decrypt(ta0, key3);
            ta1 = Aes.Decrypt(ta1, key3);
            ta2 = Aes.Decrypt(ta2, key3);
            ta3 = Aes.Decrypt(ta3, key3);

            // ROUND 4
            ta0 = Aes.Decrypt(ta0, key4);
            ta1 = Aes.Decrypt(ta1, key4);
            ta2 = Aes.Decrypt(ta2, key4);
            ta3 = Aes.Decrypt(ta3, key4);

            // ROUND 5
            ta0 = Aes.Decrypt(ta0, key5);
            ta1 = Aes.Decrypt(ta1, key5);
            ta2 = Aes.Decrypt(ta2, key5);
            ta3 = Aes.Decrypt(ta3, key5);

            // ROUND 6
            ta0 = Aes.Decrypt(ta0, key6);
            ta1 = Aes.Decrypt(ta1, key6);
            ta2 = Aes.Decrypt(ta2, key6);
            ta3 = Aes.Decrypt(ta3, key6);

            // ROUND 7
            ta0 = Aes.Decrypt(ta0, key7);
            ta1 = Aes.Decrypt(ta1, key7);
            ta2 = Aes.Decrypt(ta2, key7);
            ta3 = Aes.Decrypt(ta3, key7);

            // ROUND 8
            ta0 = Aes.Decrypt(ta0, key8);
            ta1 = Aes.Decrypt(ta1, key8);
            ta2 = Aes.Decrypt(ta2, key8);
            ta3 = Aes.Decrypt(ta3, key8);

            // ROUND 9
            ta0 = Aes.Decrypt(ta0, key9);
            ta1 = Aes.Decrypt(ta1, key9);
            ta2 = Aes.Decrypt(ta2, key9);
            ta3 = Aes.Decrypt(ta3, key9);

            // ROUND 10
            ta0 = Aes.Decrypt(ta0, key10);
            ta1 = Aes.Decrypt(ta1, key10);
            ta2 = Aes.Decrypt(ta2, key10);
            ta3 = Aes.Decrypt(ta3, key10);

            // ROUND 11
            ta0 = Aes.Decrypt(ta0, key11);
            ta1 = Aes.Decrypt(ta1, key11);
            ta2 = Aes.Decrypt(ta2, key11);
            ta3 = Aes.Decrypt(ta3, key11);

            // ROUND 12
            ta0 = Aes.Decrypt(ta0, key12);
            ta1 = Aes.Decrypt(ta1, key12);
            ta2 = Aes.Decrypt(ta2, key12);
            ta3 = Aes.Decrypt(ta3, key12);

            // ROUND 13
            ta0 = Aes.Decrypt(ta0, key13);
            ta1 = Aes.Decrypt(ta1, key13);
            ta2 = Aes.Decrypt(ta2, key13);
            ta3 = Aes.Decrypt(ta3, key13);

            // ROUND 14
            ta0 = Aes.DecryptLast(ta0, key14);
            ta1 = Aes.DecryptLast(ta1, key14);
            ta2 = Aes.DecryptLast(ta2, key14);
            ta3 = Aes.DecryptLast(ta3, key14);
        }

        #endregion
    }
}