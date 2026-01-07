import numpy as np
import matplotlib.pyplot as plt
import math

lam = 0.1
# 设置中文显示
plt.rcParams["font.sans-serif"] = ["SimHei", "Microsoft YaHei", "Arial Unicode MS"]
plt.rcParams["axes.unicode_minus"] = False  # 解决负号显示问题
x = np.linspace(0, 30, 61)  # 0,0.5,1,...,30


# 1. 概率密度函数（PDF）:f(x) = λ * e^(-λx) (x≥0)
def exponential_pdf(x_val, lambda_val):
    if x_val < 0:
        return 0.0
    pdf_val = lambda_val * math.exp(-lambda_val * x_val)
    if x_val in [1, 5, 10, 15]:
        print(f"λ={lambda_val}, x={x_val}, PDF({x_val}) = {pdf_val:.6f}")
    return pdf_val


# 2. 累积分布函数（CDF）:F(x) = 1 - e^(-λx) (x≥0)
def exponential_cdf(x_val, lambda_val):
    if x_val < 0:
        return 0.0
    cdf_val = 1 - math.exp(-lambda_val * x_val)
    if x_val in [1, 5, 10, 15]:
        print(f"λ={lambda_val}, x={x_val}, CDF({x_val}) = {cdf_val:.6f}")
    return cdf_val


# 计算PDF和CDF的数值
pdf_vals = np.array([exponential_pdf(x_val, lam) for x_val in x])
print("--" * 20)
cdf_vals = np.array([exponential_cdf(x_val, lam) for x_val in x])

# 额外计算关键区间概率（0-1/5-6分钟）
p_0_1 = exponential_cdf(1, lam) - exponential_cdf(0, lam)
p_5_6 = exponential_cdf(6, lam) - exponential_cdf(5, lam)
print(f"\n关键区间概率:")
print(f"0~1分钟事件发生的概率:{p_0_1:.6f} ({p_0_1*100:.2f}%)")
print(f"5~6分钟事件发生的概率:{p_5_6:.6f} ({p_5_6*100:.2f}%)")

# 3. 同画布双图可视化
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 9), sharex=False)

# 上方子图:绘制PDF
ax1.plot(
    x,
    pdf_vals,
    color="#1f77b4",
    linewidth=2.5,
    marker="o",
    markersize=4,
    label=f"PDF (λ = {lam})",
)
ax1.fill_between(x, pdf_vals, color="#1f77b4", alpha=0.3)
ax1.set_title(
    f"指数分布 概率密度函数(PDF) & 累积分布函数(CDF) (λ = {lam}, 平均10分钟/次)",
    fontsize=12,
    fontweight="bold",
)
ax1.set_ylabel("Probability Density f(x)", fontsize=10)  # 注意是密度而非概率
ax1.set_xlabel("Time Interval (minutes)", fontsize=10)
ax1.set_xlim(0, 30)  # 设置x轴范围
ax1.set_ylim(0, max(pdf_vals) + 0.01)  # 设置y轴范围，确保起点为0
ax1.set_xticks(np.arange(0, 31, 1))  # 刻度
ax1.legend(fontsize=9)
ax1.grid(axis="y", alpha=0.3)

# 标注PDF关键点位
for x_val in [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]:
    pdf_val = exponential_pdf(x_val, lam)
    ax1.text(
        x_val,
        pdf_val + 0.002,
        f"x={x_val}\nf(x)={pdf_val:.4f}",
        ha="center",
        va="bottom",
        fontsize=8,
        color="#1f77b4",
        bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="#1f77b4", alpha=0.7),
    )

# 下方子图:绘制CDF连续型折线+填充
ax2.plot(
    x,
    cdf_vals,
    color="#d62728",
    linewidth=2.5,
    marker="o",
    markersize=4,
    label=f"CDF (λ = {lam})",
)
ax2.fill_between(x, cdf_vals, color="#d62728", alpha=0.3)
ax2.set_xlabel("Time Interval (minutes)", fontsize=10)
ax2.set_ylabel("Cumulative Probability P(X≤x)", fontsize=10)
ax2.set_ylim(0, 1.1)  # CDF取值范围[0,1]
ax2.set_xlim(0, 30)  # 设置x轴范围，与PDF图一致
ax2.set_xticks(np.arange(0, 31, 1))
ax2.legend(fontsize=9)
ax2.grid(alpha=0.3)

# 标注CDF关键点位
for x_val in [2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30]:
    cdf_val = exponential_cdf(x_val, lam)
    ax2.text(
        x_val + 0.5,
        cdf_val,
        f"x={x_val}\nF(x)={cdf_val:.4f}",
        ha="left",
        va="center",
        fontsize=8,
        color="#000000",
        bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="#d62728", alpha=0.7),
    )

# 标注关键区间概率
ax1.axvspan(0, 1, color="orange", alpha=0.2, label="0~1分钟区间")
ax1.axvspan(5, 6, color="green", alpha=0.2, label="5~6分钟区间")
ax1.legend(fontsize=8)

plt.tight_layout()
plt.show()
