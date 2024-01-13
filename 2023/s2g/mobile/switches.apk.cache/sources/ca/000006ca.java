package kotlin;

import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;
import kotlin.jvm.internal.Intrinsics;
import s2g.project.game.BuildConfig;

/* compiled from: BigDecimals.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000$\n\u0000\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0010\u0006\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0002\u0010\b\n\u0002\u0010\t\n\u0002\b\u0002\u001a\r\u0010\u0000\u001a\u00020\u0001*\u00020\u0001H\u0087\n\u001a\u0015\u0010\u0002\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0001H\u0087\n\u001a\r\u0010\u0004\u001a\u00020\u0001*\u00020\u0001H\u0087\n\u001a\u0015\u0010\u0005\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0001H\u0087\n\u001a\u0015\u0010\u0006\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0001H\u0087\n\u001a\u0015\u0010\u0007\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0001H\u0087\n\u001a\u0015\u0010\b\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0001H\u0087\n\u001a\u0015\u0010\t\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0001H\u0087\n\u001a\r\u0010\n\u001a\u00020\u0001*\u00020\u000bH\u0087\b\u001a\u0015\u0010\n\u001a\u00020\u0001*\u00020\u000b2\u0006\u0010\f\u001a\u00020\rH\u0087\b\u001a\r\u0010\n\u001a\u00020\u0001*\u00020\u000eH\u0087\b\u001a\u0015\u0010\n\u001a\u00020\u0001*\u00020\u000e2\u0006\u0010\f\u001a\u00020\rH\u0087\b\u001a\r\u0010\n\u001a\u00020\u0001*\u00020\u000fH\u0087\b\u001a\u0015\u0010\n\u001a\u00020\u0001*\u00020\u000f2\u0006\u0010\f\u001a\u00020\rH\u0087\b\u001a\r\u0010\n\u001a\u00020\u0001*\u00020\u0010H\u0087\b\u001a\u0015\u0010\n\u001a\u00020\u0001*\u00020\u00102\u0006\u0010\f\u001a\u00020\rH\u0087\b\u001a\r\u0010\u0011\u001a\u00020\u0001*\u00020\u0001H\u0087\n¨\u0006\u0012"}, d2 = {"dec", "Ljava/math/BigDecimal;", "div", "other", "inc", "minus", "mod", "plus", "rem", "times", "toBigDecimal", BuildConfig.FLAVOR, "mathContext", "Ljava/math/MathContext;", BuildConfig.FLAVOR, BuildConfig.FLAVOR, BuildConfig.FLAVOR, "unaryMinus", "kotlin-stdlib"}, k = 5, mv = {1, 1, 15}, xi = 1, xs = "kotlin/MathKt")
/* loaded from: classes.dex */
class MathKt__BigDecimalsKt {
    private static final BigDecimal plus(BigDecimal plus, BigDecimal other) {
        Intrinsics.checkParameterIsNotNull(plus, "$this$plus");
        BigDecimal add = plus.add(other);
        Intrinsics.checkExpressionValueIsNotNull(add, "this.add(other)");
        return add;
    }

    private static final BigDecimal minus(BigDecimal minus, BigDecimal other) {
        Intrinsics.checkParameterIsNotNull(minus, "$this$minus");
        BigDecimal subtract = minus.subtract(other);
        Intrinsics.checkExpressionValueIsNotNull(subtract, "this.subtract(other)");
        return subtract;
    }

    private static final BigDecimal times(BigDecimal times, BigDecimal other) {
        Intrinsics.checkParameterIsNotNull(times, "$this$times");
        BigDecimal multiply = times.multiply(other);
        Intrinsics.checkExpressionValueIsNotNull(multiply, "this.multiply(other)");
        return multiply;
    }

    private static final BigDecimal div(BigDecimal div, BigDecimal other) {
        Intrinsics.checkParameterIsNotNull(div, "$this$div");
        BigDecimal divide = div.divide(other, RoundingMode.HALF_EVEN);
        Intrinsics.checkExpressionValueIsNotNull(divide, "this.divide(other, RoundingMode.HALF_EVEN)");
        return divide;
    }

    @Deprecated(level = DeprecationLevel.ERROR, message = "Use rem(other) instead", replaceWith = @ReplaceWith(expression = "rem(other)", imports = {}))
    private static final BigDecimal mod(BigDecimal mod, BigDecimal other) {
        Intrinsics.checkParameterIsNotNull(mod, "$this$mod");
        BigDecimal remainder = mod.remainder(other);
        Intrinsics.checkExpressionValueIsNotNull(remainder, "this.remainder(other)");
        return remainder;
    }

    private static final BigDecimal rem(BigDecimal rem, BigDecimal other) {
        Intrinsics.checkParameterIsNotNull(rem, "$this$rem");
        BigDecimal remainder = rem.remainder(other);
        Intrinsics.checkExpressionValueIsNotNull(remainder, "this.remainder(other)");
        return remainder;
    }

    private static final BigDecimal unaryMinus(BigDecimal unaryMinus) {
        Intrinsics.checkParameterIsNotNull(unaryMinus, "$this$unaryMinus");
        BigDecimal negate = unaryMinus.negate();
        Intrinsics.checkExpressionValueIsNotNull(negate, "this.negate()");
        return negate;
    }

    private static final BigDecimal inc(BigDecimal inc) {
        Intrinsics.checkParameterIsNotNull(inc, "$this$inc");
        BigDecimal add = inc.add(BigDecimal.ONE);
        Intrinsics.checkExpressionValueIsNotNull(add, "this.add(BigDecimal.ONE)");
        return add;
    }

    private static final BigDecimal dec(BigDecimal dec) {
        Intrinsics.checkParameterIsNotNull(dec, "$this$dec");
        BigDecimal subtract = dec.subtract(BigDecimal.ONE);
        Intrinsics.checkExpressionValueIsNotNull(subtract, "this.subtract(BigDecimal.ONE)");
        return subtract;
    }

    private static final BigDecimal toBigDecimal(int $this$toBigDecimal) {
        BigDecimal valueOf = BigDecimal.valueOf($this$toBigDecimal);
        Intrinsics.checkExpressionValueIsNotNull(valueOf, "BigDecimal.valueOf(this.toLong())");
        return valueOf;
    }

    private static final BigDecimal toBigDecimal(int $this$toBigDecimal, MathContext mathContext) {
        return new BigDecimal($this$toBigDecimal, mathContext);
    }

    private static final BigDecimal toBigDecimal(long $this$toBigDecimal) {
        BigDecimal valueOf = BigDecimal.valueOf($this$toBigDecimal);
        Intrinsics.checkExpressionValueIsNotNull(valueOf, "BigDecimal.valueOf(this)");
        return valueOf;
    }

    private static final BigDecimal toBigDecimal(long $this$toBigDecimal, MathContext mathContext) {
        return new BigDecimal($this$toBigDecimal, mathContext);
    }

    private static final BigDecimal toBigDecimal(float $this$toBigDecimal) {
        return new BigDecimal(String.valueOf($this$toBigDecimal));
    }

    private static final BigDecimal toBigDecimal(float $this$toBigDecimal, MathContext mathContext) {
        return new BigDecimal(String.valueOf($this$toBigDecimal), mathContext);
    }

    private static final BigDecimal toBigDecimal(double $this$toBigDecimal) {
        return new BigDecimal(String.valueOf($this$toBigDecimal));
    }

    private static final BigDecimal toBigDecimal(double $this$toBigDecimal, MathContext mathContext) {
        return new BigDecimal(String.valueOf($this$toBigDecimal), mathContext);
    }
}