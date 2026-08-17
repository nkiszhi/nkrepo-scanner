# 外部 YARA 扩展壳库

本目录下所有 `.yar` / `.yara` 规则在服务启动时自动编译加载，命中后作为
**精确特征** 进入壳 / Packer 识别，与内置 DIE + PEiD 特征使用同一融合判定体系
（权重累加 → 置信度 high/medium/low → packed_score）。

## 规则编写约定（meta 字段）

| meta 字段   | 必选 | 说明                                                        |
| ----------- | ---- | ----------------------------------------------------------- |
| `packer`    | 是   | 壳族名称（Web 端显示名）；缺省时取规则名                    |
| `weight`    | 否   | 证据权重 1-5，默认 2。与内置特征同一量纲：overlay magic=3、节名/EP=2、文件内 magic=1 |
| `desc`      | 否   | 证据描述，默认 `YARA 规则 <name> 命中`                      |
| `confidence`| 否   | 可选；缺省由融合判定推导（权重 ≥3 high / ≥2 medium / 其余 low） |

## 示例

```yara
/*
 * 检测 MPRESS 压缩标记 (overlay)
 */
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
```

## 提示

- 建议在 condition 中加 `uint16(0) == 0x5A4D`（PE 魔数）前置条件，避免非 PE 文件误命中；
- 多条规则命中同一 `packer` 壳族时权重累加；
- 单个规则文件编译失败不影响其它规则（启动日志会输出警告）；
- 修改规则后需重启服务生效；
- 目录路径可在 `config.json` 的 `packer.rules_dir` 修改（默认 `packer_rules`）。
