using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;

namespace ArmAes;

internal static partial class AesUtil
{
    private static class Arm
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

            // ROUND 0
            var block0 = Aes.Encrypt(ta0, key0);
            block0 = Aes.MixColumns(block0);
            var block1 = Aes.Encrypt(ta1, key0);
            block1 = Aes.MixColumns(block1);
            var block2 = Aes.Encrypt(ta2, key0);
            block2 = Aes.MixColumns(block2);
            var block3 = Aes.Encrypt(ta3, key0);
            block3 = Aes.MixColumns(block3);

            // ROUND 1
            block0 = Aes.Encrypt(block0, key1);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key1);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key1);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key1);
            block3 = Aes.MixColumns(block3);

            // ROUND 2
            block0 = Aes.Encrypt(block0, key2);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key2);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key2);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key2);
            block3 = Aes.MixColumns(block3);

            // ROUND 3
            block0 = Aes.Encrypt(block0, key3);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key3);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key3);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key3);
            block3 = Aes.MixColumns(block3);

            // ROUND 4
            block0 = Aes.Encrypt(block0, key4);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key4);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key4);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key4);
            block3 = Aes.MixColumns(block3);

            // ROUND 5
            block0 = Aes.Encrypt(block0, key5);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key5);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key5);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key5);
            block3 = Aes.MixColumns(block3);

            // ROUND 6
            block0 = Aes.Encrypt(block0, key6);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key6);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key6);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key6);
            block3 = Aes.MixColumns(block3);

            // ROUND 7
            block0 = Aes.Encrypt(block0, key7);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key7);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key7);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key7);
            block3 = Aes.MixColumns(block3);

            // ROUND 8
            block0 = Aes.Encrypt(block0, key8);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key8);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key8);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key8);
            block3 = Aes.MixColumns(block3);

            // ROUND 9 + 10
            block0 = Aes.Encrypt(block0, key9);
            block0 ^= key10;
            block1 = Aes.Encrypt(block1, key9);
            block1 ^= key10;
            block2 = Aes.Encrypt(block2, key9);
            block2 ^= key10;
            block3 = Aes.Encrypt(block3, key9);
            block3 ^= key10;

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
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

            // ROUND 0
            var block0 = Aes.Encrypt(ta0, key0);
            block0 = Aes.MixColumns(block0);
            var block1 = Aes.Encrypt(ta1, key0);
            block1 = Aes.MixColumns(block1);

            // ROUND 1
            block0 = Aes.Encrypt(block0, key1);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key1);
            block1 = Aes.MixColumns(block1);

            // ROUND 2
            block0 = Aes.Encrypt(block0, key2);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key2);
            block1 = Aes.MixColumns(block1);

            // ROUND 3
            block0 = Aes.Encrypt(block0, key3);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key3);
            block1 = Aes.MixColumns(block1);

            // ROUND 4
            block0 = Aes.Encrypt(block0, key4);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key4);
            block1 = Aes.MixColumns(block1);

            // ROUND 5
            block0 = Aes.Encrypt(block0, key5);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key5);
            block1 = Aes.MixColumns(block1);

            // ROUND 6
            block0 = Aes.Encrypt(block0, key6);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key6);
            block1 = Aes.MixColumns(block1);

            // ROUND 7
            block0 = Aes.Encrypt(block0, key7);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key7);
            block1 = Aes.MixColumns(block1);

            // ROUND 8
            block0 = Aes.Encrypt(block0, key8);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key8);
            block1 = Aes.MixColumns(block1);

            // ROUND 9 + 10
            block0 = Aes.Encrypt(block0, key9);
            block0 ^= key10;
            block1 = Aes.Encrypt(block1, key9);
            block1 ^= key10;

            ta0 = block0;
            ta1 = block1;
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

            var block = Aes.Encrypt(input, key0);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key1);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key2);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key3);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key4);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key5);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key6);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key7);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key8);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key9);
            return block ^ key10;
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

            // ROUND 0
            var block0 = Aes.Decrypt(ta0, key0);
            block0 = Aes.InverseMixColumns(block0);
            var block1 = Aes.Decrypt(ta1, key0);
            block1 = Aes.InverseMixColumns(block1);
            var block2 = Aes.Decrypt(ta2, key0);
            block2 = Aes.InverseMixColumns(block2);
            var block3 = Aes.Decrypt(ta3, key0);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 1
            block0 = Aes.Decrypt(block0, key1);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key1);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key1);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key1);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 2
            block0 = Aes.Decrypt(block0, key2);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key2);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key2);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key2);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 3
            block0 = Aes.Decrypt(block0, key3);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key3);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key3);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key3);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 4
            block0 = Aes.Decrypt(block0, key4);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key4);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key4);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key4);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 5
            block0 = Aes.Decrypt(block0, key5);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key5);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key5);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key5);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 6
            block0 = Aes.Decrypt(block0, key6);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key6);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key6);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key6);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 7
            block0 = Aes.Decrypt(block0, key7);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key7);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key7);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key7);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 8
            block0 = Aes.Decrypt(block0, key8);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key8);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key8);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key8);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 9 + 10
            block0 = Aes.Decrypt(block0, key9);
            block0 ^= key10;
            block1 = Aes.Decrypt(block1, key9);
            block1 ^= key10;
            block2 = Aes.Decrypt(block2, key9);
            block2 ^= key10;
            block3 = Aes.Decrypt(block3, key9);
            block3 ^= key10;

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
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

            // ROUND 0
            var block0 = Aes.Encrypt(ta0, key0);
            block0 = Aes.MixColumns(block0);
            var block1 = Aes.Encrypt(ta1, key0);
            block1 = Aes.MixColumns(block1);
            var block2 = Aes.Encrypt(ta2, key0);
            block2 = Aes.MixColumns(block2);
            var block3 = Aes.Encrypt(ta3, key0);
            block3 = Aes.MixColumns(block3);

            // ROUND 1
            block0 = Aes.Encrypt(block0, key1);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key1);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key1);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key1);
            block3 = Aes.MixColumns(block3);

            // ROUND 2
            block0 = Aes.Encrypt(block0, key2);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key2);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key2);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key2);
            block3 = Aes.MixColumns(block3);

            // ROUND 3
            block0 = Aes.Encrypt(block0, key3);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key3);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key3);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key3);
            block3 = Aes.MixColumns(block3);

            // ROUND 4
            block0 = Aes.Encrypt(block0, key4);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key4);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key4);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key4);
            block3 = Aes.MixColumns(block3);

            // ROUND 5
            block0 = Aes.Encrypt(block0, key5);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key5);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key5);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key5);
            block3 = Aes.MixColumns(block3);

            // ROUND 6
            block0 = Aes.Encrypt(block0, key6);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key6);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key6);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key6);
            block3 = Aes.MixColumns(block3);

            // ROUND 7
            block0 = Aes.Encrypt(block0, key7);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key7);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key7);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key7);
            block3 = Aes.MixColumns(block3);

            // ROUND 8
            block0 = Aes.Encrypt(block0, key8);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key8);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key8);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key8);
            block3 = Aes.MixColumns(block3);

            // ROUND 9
            block0 = Aes.Encrypt(block0, key9);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key9);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key9);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key9);
            block3 = Aes.MixColumns(block3);

            // ROUND 10
            block0 = Aes.Encrypt(block0, key10);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key10);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key10);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key10);
            block3 = Aes.MixColumns(block3);

            // ROUND 11 + 12
            block0 = Aes.Encrypt(block0, key11);
            block0 ^= key12;
            block1 = Aes.Encrypt(block1, key11);
            block1 ^= key12;
            block2 = Aes.Encrypt(block2, key11);
            block2 ^= key12;
            block3 = Aes.Encrypt(block3, key11);
            block3 ^= key12;

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
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

            // ROUND 0
            var block0 = Aes.Encrypt(ta0, key0);
            block0 = Aes.MixColumns(block0);
            var block1 = Aes.Encrypt(ta1, key0);
            block1 = Aes.MixColumns(block1);

            // ROUND 1
            block0 = Aes.Encrypt(block0, key1);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key1);
            block1 = Aes.MixColumns(block1);

            // ROUND 2
            block0 = Aes.Encrypt(block0, key2);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key2);
            block1 = Aes.MixColumns(block1);

            // ROUND 3
            block0 = Aes.Encrypt(block0, key3);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key3);
            block1 = Aes.MixColumns(block1);

            // ROUND 4
            block0 = Aes.Encrypt(block0, key4);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key4);
            block1 = Aes.MixColumns(block1);

            // ROUND 5
            block0 = Aes.Encrypt(block0, key5);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key5);
            block1 = Aes.MixColumns(block1);

            // ROUND 6
            block0 = Aes.Encrypt(block0, key6);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key6);
            block1 = Aes.MixColumns(block1);

            // ROUND 7
            block0 = Aes.Encrypt(block0, key7);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key7);
            block1 = Aes.MixColumns(block1);

            // ROUND 8
            block0 = Aes.Encrypt(block0, key8);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key8);
            block1 = Aes.MixColumns(block1);

            // ROUND 9
            block0 = Aes.Encrypt(block0, key9);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key9);
            block1 = Aes.MixColumns(block1);

            // ROUND 10
            block0 = Aes.Encrypt(block0, key10);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key10);
            block1 = Aes.MixColumns(block1);

            // ROUND 11 + 12
            block0 = Aes.Encrypt(block0, key11);
            block0 ^= key12;
            block1 = Aes.Encrypt(block1, key11);
            block1 ^= key12;

            ta0 = block0;
            ta1 = block1;
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

            var block = Aes.Encrypt(input, key0);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key1);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key2);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key3);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key4);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key5);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key6);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key7);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key8);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key9);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key10);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key11);
            return block ^ key12;
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

            // ROUND 0
            var block0 = Aes.Decrypt(ta0, key0);
            block0 = Aes.InverseMixColumns(block0);
            var block1 = Aes.Decrypt(ta1, key0);
            block1 = Aes.InverseMixColumns(block1);
            var block2 = Aes.Decrypt(ta2, key0);
            block2 = Aes.InverseMixColumns(block2);
            var block3 = Aes.Decrypt(ta3, key0);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 1
            block0 = Aes.Decrypt(block0, key1);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key1);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key1);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key1);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 2
            block0 = Aes.Decrypt(block0, key2);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key2);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key2);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key2);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 3
            block0 = Aes.Decrypt(block0, key3);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key3);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key3);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key3);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 4
            block0 = Aes.Decrypt(block0, key4);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key4);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key4);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key4);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 5
            block0 = Aes.Decrypt(block0, key5);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key5);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key5);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key5);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 6
            block0 = Aes.Decrypt(block0, key6);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key6);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key6);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key6);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 7
            block0 = Aes.Decrypt(block0, key7);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key7);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key7);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key7);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 8
            block0 = Aes.Decrypt(block0, key8);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key8);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key8);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key8);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 9
            block0 = Aes.Decrypt(block0, key9);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key9);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key9);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key9);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 10
            block0 = Aes.Decrypt(block0, key10);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key10);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key10);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key10);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 11 + 12
            block0 = Aes.Decrypt(block0, key11);
            block0 ^= key12;
            block1 = Aes.Decrypt(block1, key11);
            block1 ^= key12;
            block2 = Aes.Decrypt(block2, key11);
            block2 ^= key12;
            block3 = Aes.Decrypt(block3, key11);
            block3 ^= key12;

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
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
            var block0 = Aes.Encrypt(ta0, key0);
            block0 = Aes.MixColumns(block0);
            var block1 = Aes.Encrypt(ta1, key0);
            block1 = Aes.MixColumns(block1);
            var block2 = Aes.Encrypt(ta2, key0);
            block2 = Aes.MixColumns(block2);
            var block3 = Aes.Encrypt(ta3, key0);
            block3 = Aes.MixColumns(block3);

            // ROUND 1
            block0 = Aes.Encrypt(block0, key1);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key1);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key1);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key1);
            block3 = Aes.MixColumns(block3);

            // ROUND 2
            block0 = Aes.Encrypt(block0, key2);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key2);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key2);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key2);
            block3 = Aes.MixColumns(block3);

            // ROUND 3
            block0 = Aes.Encrypt(block0, key3);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key3);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key3);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key3);
            block3 = Aes.MixColumns(block3);

            // ROUND 4
            block0 = Aes.Encrypt(block0, key4);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key4);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key4);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key4);
            block3 = Aes.MixColumns(block3);

            // ROUND 5
            block0 = Aes.Encrypt(block0, key5);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key5);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key5);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key5);
            block3 = Aes.MixColumns(block3);

            // ROUND 6
            block0 = Aes.Encrypt(block0, key6);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key6);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key6);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key6);
            block3 = Aes.MixColumns(block3);

            // ROUND 7
            block0 = Aes.Encrypt(block0, key7);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key7);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key7);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key7);
            block3 = Aes.MixColumns(block3);

            // ROUND 8
            block0 = Aes.Encrypt(block0, key8);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key8);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key8);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key8);
            block3 = Aes.MixColumns(block3);

            // ROUND 9
            block0 = Aes.Encrypt(block0, key9);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key9);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key9);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key9);
            block3 = Aes.MixColumns(block3);

            // ROUND 10
            block0 = Aes.Encrypt(block0, key10);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key10);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key10);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key10);
            block3 = Aes.MixColumns(block3);

            // ROUND 11
            block0 = Aes.Encrypt(block0, key11);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key11);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key11);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key11);
            block3 = Aes.MixColumns(block3);

            // ROUND 12
            block0 = Aes.Encrypt(block0, key12);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key12);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key12);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key12);
            block3 = Aes.MixColumns(block3);

            // ROUND 13 + 14
            block0 = Aes.Encrypt(block0, key13);
            block0 ^= key14;
            block1 = Aes.Encrypt(block1, key13);
            block1 ^= key14;
            block2 = Aes.Encrypt(block2, key13);
            block2 ^= key14;
            block3 = Aes.Encrypt(block3, key13);
            block3 ^= key14;

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
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
            var block0 = Aes.Encrypt(ta0, key0);
            block0 = Aes.MixColumns(block0);
            var block1 = Aes.Encrypt(ta1, key0);
            block1 = Aes.MixColumns(block1);

            // ROUND 1
            block0 = Aes.Encrypt(block0, key1);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key1);
            block1 = Aes.MixColumns(block1);

            // ROUND 2
            block0 = Aes.Encrypt(block0, key2);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key2);
            block1 = Aes.MixColumns(block1);

            // ROUND 3
            block0 = Aes.Encrypt(block0, key3);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key3);
            block1 = Aes.MixColumns(block1);

            // ROUND 4
            block0 = Aes.Encrypt(block0, key4);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key4);
            block1 = Aes.MixColumns(block1);

            // ROUND 5
            block0 = Aes.Encrypt(block0, key5);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key5);
            block1 = Aes.MixColumns(block1);

            // ROUND 6
            block0 = Aes.Encrypt(block0, key6);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key6);
            block1 = Aes.MixColumns(block1);

            // ROUND 7
            block0 = Aes.Encrypt(block0, key7);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key7);
            block1 = Aes.MixColumns(block1);

            // ROUND 8
            block0 = Aes.Encrypt(block0, key8);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key8);
            block1 = Aes.MixColumns(block1);

            // ROUND 9
            block0 = Aes.Encrypt(block0, key9);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key9);
            block1 = Aes.MixColumns(block1);

            // ROUND 10
            block0 = Aes.Encrypt(block0, key10);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key10);
            block1 = Aes.MixColumns(block1);

            // ROUND 11
            block0 = Aes.Encrypt(block0, key11);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key11);
            block1 = Aes.MixColumns(block1);

            // ROUND 12
            block0 = Aes.Encrypt(block0, key12);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key12);
            block1 = Aes.MixColumns(block1);

            // ROUND 13 + 14
            block0 = Aes.Encrypt(block0, key13);
            block0 ^= key14;
            block1 = Aes.Encrypt(block1, key13);
            block1 ^= key14;

            ta0 = block0;
            ta1 = block1;
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

            var block = Aes.Encrypt(input, key0);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key1);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key2);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key3);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key4);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key5);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key6);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key7);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key8);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key9);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key10);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key11);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key12);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key13);
            return block ^ key14;
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
            var block0 = Aes.Decrypt(ta0, key0);
            block0 = Aes.InverseMixColumns(block0);
            var block1 = Aes.Decrypt(ta1, key0);
            block1 = Aes.InverseMixColumns(block1);
            var block2 = Aes.Decrypt(ta2, key0);
            block2 = Aes.InverseMixColumns(block2);
            var block3 = Aes.Decrypt(ta3, key0);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 1
            block0 = Aes.Decrypt(block0, key1);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key1);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key1);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key1);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 2
            block0 = Aes.Decrypt(block0, key2);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key2);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key2);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key2);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 3
            block0 = Aes.Decrypt(block0, key3);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key3);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key3);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key3);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 4
            block0 = Aes.Decrypt(block0, key4);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key4);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key4);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key4);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 5
            block0 = Aes.Decrypt(block0, key5);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key5);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key5);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key5);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 6
            block0 = Aes.Decrypt(block0, key6);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key6);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key6);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key6);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 7
            block0 = Aes.Decrypt(block0, key7);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key7);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key7);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key7);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 8
            block0 = Aes.Decrypt(block0, key8);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key8);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key8);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key8);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 9
            block0 = Aes.Decrypt(block0, key9);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key9);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key9);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key9);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 10
            block0 = Aes.Decrypt(block0, key10);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key10);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key10);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key10);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 11
            block0 = Aes.Decrypt(block0, key11);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key11);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key11);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key11);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 12
            block0 = Aes.Decrypt(block0, key12);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key12);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key12);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key12);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 13 + 14
            block0 = Aes.Decrypt(block0, key13);
            block0 ^= key14;
            block1 = Aes.Decrypt(block1, key13);
            block1 ^= key14;
            block2 = Aes.Decrypt(block2, key13);
            block2 ^= key14;
            block3 = Aes.Decrypt(block3, key13);
            block3 ^= key14;

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
        }

        #endregion
    }
}