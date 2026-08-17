/*
 * example_packers.yar - 外部 YARA 扩展壳库示例规则
 *
 * 编写约定见同目录 README.md: meta.packer 必选 (壳族名), weight 1-5 可选 (默认 2),
 * desc 可选。命中后作为精确特征进入壳识别融合判定。
 *
 * 三条示例分别演示: 字符串特征 / hex 模式 + 节名 / 复合条件。
 */

/* 1) MPRESS 压缩标记 (overlay) - 字符串特征 */
rule Packer_MPRESS_Magic {
    meta:
        packer = "MPRESS"
        weight = 3
        desc = "MPRESS 压缩标记"
    strings:
        $m = "MPRESS" nocase
    condition:
        uint16(0) == 0x5A4D and $m
}

/* 2) 自定义壳 AcmePack (演示外部规则独立生效) - hex + 特征节名 */
rule Packer_AcmePack {
    meta:
        packer = "AcmePack"
        weight = 3
        desc = "AcmePack 特征: EP 字节模式 + .acme 节"
    strings:
        $ep = { 53 56 57 E8 ?? ?? ?? ?? 5F 5E 5B }
        $sec = ".acme" ascii
    condition:
        uint16(0) == 0x5A4D and ($ep or $sec)
}

/* 3) 复合条件 - 自定义壳 BetaShield (演示 weight 权重与多条证据累加) */
rule Packer_BetaShield {
    meta:
        packer = "BetaShield"
        weight = 2
        desc = "BetaShield 标记 + 特征节"
    strings:
        $mark = "BetaShield" ascii
        $sec  = ".beta0" ascii
    condition:
        uint16(0) == 0x5A4D and $mark and $sec
}
