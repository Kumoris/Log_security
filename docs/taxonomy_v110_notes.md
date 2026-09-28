# 统一分类 1.1.0：七组个人属性候选

本次将受控目录从 42 个细类扩展到 49 个。新增项目属于 `PII`，与正文、JSON 结构和应用日志共用同一份分类规则；没有建立第二套互不兼容的分类。分类器输出仍是字段名线索，不能证明值属于真实个人或已经泄露。

术语参考 [NIST SP 800-122 第 2.1–2.2 节](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-122.pdf)：出生、人口属性、宗教，以及教育和就业信息，在与个人关联或可关联时可能构成个人信息。这里用作分类依据，不据此判断某条 GitHub 内容的法律性质。

| 新细类 | 支持的字段例子 | 必须保留的边界 |
|---|---|---|
| `PII.birth_date` | `date_of_birth`、`birthdate`、`dob` | 字段名不证明字符串是有效生日或对应真实个人 |
| `PII.age` | `user.age`、`patient_age`、`age_in_years` | 普通 `age`、`cache.age` 不据此分类 |
| `PII.sex_gender` | `gender`、`gender_identity`、`biological_sex` | 枚举、字段定义和界面标签也会命中，需要审核 |
| `PII.ethnicity` | `ethnicity`、`ethnic_origin`、`patient.race` | 普通 `race` 不据此分类；不能证明是个人属性 |
| `PII.religious_belief` | `religion`、`religious_affiliation` | 宗教名称或翻译标签不等于个人信仰记录 |
| `PII.education` | `education_level`、`highest_degree`、`student.school` | 普通 `school`、`degree` 不据此分类 |
| `PII.employment` | `employment_status`、`employer_name`、`employee.job_title` | 普通 `job`、`employer` 不据此分类 |

数据依据是冻结 AIDev 正文列的一次实际探查：4,034,221 个源单元格中得到 858 个固定属性字段赋值线索，包含空值、声明、引用和字面赋值。政治观点及性取向在本次有限键集合探查中为零，不表示数据集中不存在，也不表示相关语义已覆盖。[完整探查](personal_attribute_probe_v049.json)

有意选取的 27 条证据、23 个源单元格已按原字符位置回读：26 条得到预期新类型，剩余一条为空值，因此不输出候选。21 个字面赋值样本中，8 个仍无法凭有限形态区分属性值与标签、映射等用途；这不是总体误差率。[定点复核](personal_attribute_replay_v049.json)

原目录和原观察结果保留其 `1.0.0` 来源版本。新目录的七个新增细类，对旧来源应显示“未评估”，计数为空，不能补成零。只有使用 `1.1.0` 实际完成的对应扫描范围，才能报告该范围内的零观察。新旧来源计数单位不同，不能直接相加。

`$object.field` 的共享规则已修复，JSON 和正文会将支持的点式表达式保留为引用；没有据此解析实际值或跨节点传播类型。旧分类器结果在新版本下合并会在写入前拒绝，须用新版重跑，避免给历史候选错误加上新版本标签。

所有结果继续使用 `human_review_status=pending`、`runtime_confirmed=false`、`new_type_status=not_established`。有限目录不等于现实敏感类型全集；任意语义、其他语言字段和完整 Git 历史仍有缺口。
