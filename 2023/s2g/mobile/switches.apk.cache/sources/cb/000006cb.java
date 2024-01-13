package kotlin;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import kotlin.jvm.internal.Intrinsics;
import s2g.project.game.BuildConfig;

/* compiled from: BigIntegers.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000(\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u000b\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0002\b\u0003\u001a\u0015\u0010\u0000\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0001H\u0087\f\u001a\r\u0010\u0003\u001a\u00020\u0001*\u00020\u0001H\u0087\n\u001a\u0015\u0010\u0004\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0001H\u0087\n\u001a\r\u0010\u0005\u001a\u00020\u0001*\u00020\u0001H\u0087\n\u001a\r\u0010\u0006\u001a\u00020\u0001*\u00020\u0001H\u0087\b\u001a\u0015\u0010\u0007\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0001H\u0087\n\u001a\u0015\u0010\b\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0001H\u0087\f\u001a\u0015\u0010\t\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0001H\u0087\n\u001a\u0015\u0010\n\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0001H\u0087\n\u001a\u0015\u0010\u000b\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\f\u001a\u00020\rH\u0087\f\u001a\u0015\u0010\u000e\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\f\u001a\u00020\rH\u0087\f\u001a\u0015\u0010\u000f\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0001H\u0087\n\u001a\r\u0010\u0010\u001a\u00020\u0011*\u00020\u0001H\u0087\b\u001a!\u0010\u0010\u001a\u00020\u0011*\u00020\u00012\b\b\u0002\u0010\u0012\u001a\u00020\r2\b\b\u0002\u0010\u0013\u001a\u00020\u0014H\u0087\b\u001a\r\u0010\u0015\u001a\u00020\u0001*\u00020\rH\u0087\b\u001a\r\u0010\u0015\u001a\u00020\u0001*\u00020\u0016H\u0087\b\u001a\r\u0010\u0017\u001a\u00020\u0001*\u00020\u0001H\u0087\n\u001a\u0015\u0010\u0018\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0001H\u0087\f¨\u0006\u0019"}, d2 = {"and", "Ljava/math/BigInteger;", "other", "dec", "div", "inc", "inv", "minus", "or", "plus", "rem", "shl", "n", BuildConfig.FLAVOR, "shr", "times", "toBigDecimal", "Ljava/math/BigDecimal;", "scale", "mathContext", "Ljava/math/MathContext;", "toBigInteger", BuildConfig.FLAVOR, "unaryMinus", "xor", "kotlin-stdlib"}, k = 5, mv = {1, 1, 15}, xi = 1, xs = "kotlin/MathKt")
/* loaded from: classes.dex */
class MathKt__BigIntegersKt extends MathKt__BigDecimalsKt {
    private static final BigInteger plus(BigInteger plus, BigInteger other) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        BigInteger add = plus.add(other);
        Intrinsics.checkExpressionValueIsNotNull(add, "this.add(other)");
        return add;
    }

    private static final BigInteger minus(BigInteger minus, BigInteger other) {
        Intrinsics.checkParameterIsNotNull(minus, "$this$minus");
        BigInteger subtract = minus.subtract(other);
        Intrinsics.checkExpressionValueIsNotNull(subtract, "this.subtract(other)");
        return subtract;
    }

    private static final BigInteger times(BigInteger times, BigInteger other) {
        Intrinsics.checkParameterIsNotNull(times, "$this$times");
        BigInteger multiply = times.multiply(other);
        Intrinsics.checkExpressionValueIsNotNull(multiply, "this.multiply(other)");
        return multiply;
    }

    private static final BigInteger div(BigInteger div, BigInteger other) {
        Intrinsics.checkParameterIsNotNull(div, "$this$div");
        BigInteger divide = div.divide(other);
        Intrinsics.checkExpressionValueIsNotNull(divide, "this.divide(other)");
        return divide;
    }

    private static final BigInteger rem(BigInteger rem, BigInteger other) {
        Intrinsics.checkParameterIsNotNull(rem, "$this$rem");
        BigInteger remainder = rem.remainder(other);
        Intrinsics.checkExpressionValueIsNotNull(remainder, "this.remainder(other)");
        return remainder;
    }

    private static final BigInteger unaryMinus(BigInteger unaryMinus) {
        Intrinsics.checkParameterIsNotNull(unaryMinus, "$this$unaryMinus");
        BigInteger negate = unaryMinus.negate();
        Intrinsics.checkExpressionValueIsNotNull(negate, "this.negate()");
        return negate;
    }

    private static final BigInteger inc(BigInteger inc) {
        Intrinsics.checkParameterIsNotNull(inc, "$this$inc");
        BigInteger add = inc.add(BigInteger.ONE);
        Intrinsics.checkExpressionValueIsNotNull(add, "this.add(BigInteger.ONE)");
        return add;
    }

    private static final BigInteger dec(BigInteger dec) {
        Intrinsics.checkParameterIsNotNull(dec, "$this$dec");
        BigInteger subtract = dec.subtract(BigInteger.ONE);
        Intrinsics.checkExpressionValueIsNotNull(subtract, "this.subtract(BigInteger.ONE)");
        return subtract;
    }

    private static final BigInteger inv(BigInteger $this$inv) {
        BigInteger not = $this$inv.not();
        Intrinsics.checkExpressionValueIsNotNull(not, "this.not()");
        return not;
    }

    private static final BigInteger and(BigInteger $this$and, BigInteger other) {
        BigInteger and = $this$and.and(other);
        Intrinsics.checkExpressionValueIsNotNull(and, "this.and(other)");
        return and;
    }

    private static final BigInteger or(BigInteger $this$or, BigInteger other) {
        BigInteger or = $this$or.or(other);
        Intrinsics.checkExpressionValueIsNotNull(or, "this.or(other)");
        return or;
    }

    private static final BigInteger xor(BigInteger $this$xor, BigInteger other) {
        BigInteger xor = $this$xor.xor(other);
        Intrinsics.checkExpressionValueIsNotNull(xor, "this.xor(other)");
        return xor;
    }

    private static final BigInteger shl(BigInteger $this$shl, int n) {
        BigInteger shiftLeft = $this$shl.shiftLeft(n);
        Intrinsics.checkExpressionValueIsNotNull(shiftLeft, "this.shiftLeft(n)");
        return shiftLeft;
    }

    private static final BigInteger shr(BigInteger $this$shr, int n) {
        BigInteger shiftRight = $this$shr.shiftRight(n);
        Intrinsics.checkExpressionValueIsNotNull(shiftRight, "this.shiftRight(n)");
        return shiftRight;
    }

    private static final BigInteger toBigInteger(int $this$toBigInteger) {
        BigInteger valueOf = BigInteger.valueOf($this$toBigInteger);
        Intrinsics.checkExpressionValueIsNotNull(valueOf, "BigInteger.valueOf(this.toLong())");
        return valueOf;
    }

    private static final BigInteger toBigInteger(long $this$toBigInteger) {
        BigInteger valueOf = BigInteger.valueOf($this$toBigInteger);
        Intrinsics.checkExpressionValueIsNotNull(valueOf, "BigInteger.valueOf(this)");
        return valueOf;
    }

    private static final BigDecimal toBigDecimal(BigInteger $this$toBigDecimal) {
        return new BigDecimal($this$toBigDecimal);
    }

    static /* synthetic */ BigDecimal toBigDecimal$default(BigInteger $this$toBigDecimal, int scale, MathContext mathContext, int i, Object obj) {
        if ((i & 1) != 0) {
            scale = 0;
        }
        if ((i & 2) != 0) {
            MathContext mathContext2 = MathContext.UNLIMITED;
            Intrinsics.checkExpressionValueIsNotNull(mathContext2, "MathContext.UNLIMITED");
            mathContext = mathContext2;
        }
        return new BigDecimal($this$toBigDecimal, scale, mathContext);
    }

    private static final BigDecimal toBigDecimal(BigInteger $this$toBigDecimal, int scale, MathContext mathContext) {
        return new BigDecimal($this$toBigDecimal, scale, mathContext);
    }
}