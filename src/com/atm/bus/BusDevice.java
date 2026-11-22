package com.atm.bus;

/**
 * 总线设备接口。任何能物理接触线缆的设备都可以实现它并接入——
 * 包括合法终端、出钞模块，也包括攻击者的小电脑。总线本身不做任何准入控制，
 * 准入完全依赖消息层的密码学认证。
 */
public interface BusDevice {

    /** 设备标识（仅用于日志与 AAD 绑定，本身不构成可信凭证）。 */
    String deviceId();

    /**
     * 收到一帧。实现方必须自行处理所有异常：非法帧、认证失败帧都应当
     * 静默丢弃，绝不能让异常破坏总线对其他设备的投递。
     */
    void onFrame(BusFrame frame, PhysicalBus bus);
}
