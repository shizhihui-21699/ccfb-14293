package com.atm.protocol;

/**
 * 命令处理结果。ok=false 时携带拒绝码，dispatcher 不会触发任何出钞动作。
 */
public record Result(ResultCode code, String detail) {

    public static Result ok() {
        return new Result(ResultCode.OK, null);
    }

    public static Result ok(String detail) {
        return new Result(ResultCode.OK, detail);
    }

    public static Result reject(ResultCode code) {
        return new Result(code, null);
    }

    public static Result reject(ResultCode code, String detail) {
        return new Result(code, detail);
    }

    public boolean success() {
        return code == ResultCode.OK;
    }
}
