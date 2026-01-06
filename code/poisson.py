import numpy as np
import matplotlib.pyplot as plt
import math

# 泊松分布
# λ值（核心参数）
lam = 10
plt.rcParams["axes.unicode_minus"] = False  # 解决负号显示异常
x = np.arange(0, lam + 10, 1)  # 适当缩小x范围


# 1. 概率质量函数（PMF）
def poisson_pmf(k, lambda_val):

    pmf_val = (math.exp(-lambda_val) * (lambda_val**k)) / math.factorial(k)
    print(f"lambda={lambda_val}, k={k}, PMF({k}) = {pmf_val:.6f}")
    return pmf_val


# 2. 累积分布函数（CDF）
def poisson_cdf(k, lambda_val):
    cdf_sum = 0
    for i in range(int(k) + 1):
        cdf_sum += poisson_pmf(i, lambda_val)
    print(f"lambda={lambda_val}, k={k}, CDF({k}) = {cdf_sum:.6f}")
    return cdf_sum


# 计算PMF和CDF的数值
pmf_vals = np.array([poisson_pmf(k_val, lam) for k_val in x])
print("--" * 20)
cdf_vals = np.array([poisson_cdf(k_val, lam) for k_val in x])

# 3. 同画布双图可视化2行1列
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 9), sharex=False)

# 上方子图：绘制PMF + 显示x轴 + 标注每个点的y值
ax1.bar(x, pmf_vals, color="#1f77b4", alpha=0.7, width=0.8, label=f"PMF (λ = {lam})")
ax1.plot(x, pmf_vals, color="#1f77b4", linewidth=2, marker="o", markersize=4)
ax1.set_title(
    f"Poisson Distribution PMF (Top) & CDF (Bottom) (λ = {lam})",
    fontsize=12,
    fontweight="bold",
)
ax1.set_ylabel("Probability P(X=k)", fontsize=10)
ax1.set_xlabel("Number of Events (k)", fontsize=10)
ax1.set_xticks(x)  # 清晰整数x轴刻度
ax1.legend(fontsize=9)
ax1.grid(axis="y", alpha=0.3)

# 为PMF每个(x,y)点标注y值
for k_val, pmf_val in zip(x, pmf_vals):
    # 标注位置：条形图上方居中，y值轻微上移避免重叠
    ax1.text(
        k_val,
        pmf_val + 0.005,
        f"{pmf_val:.4f}",
        ha="center",
        va="bottom",
        fontsize=8,
        color="#1f77b4",
    )

# 下方子图：绘制CDF + 显示x轴 + 标注每个点的y值
ax2.step(
    x, cdf_vals, color="#d62728", linewidth=2.5, where="post", label=f"CDF (λ = {lam})"
)
ax2.fill_between(x, cdf_vals, color="#d62728", alpha=0.3)
ax2.set_xlabel("Number of Events (k)", fontsize=10)
ax2.set_ylabel("Cumulative Probability P(X≤k)", fontsize=10)
ax2.set_ylim(0, 1.05)  # CDF取值范围[0,1]
ax2.set_xticks(x)  # 清晰整数x轴刻度
ax2.legend(fontsize=9)
ax2.grid(alpha=0.3)

# 为CDF每个(x,y)点标注y值
for k_val, cdf_val in zip(x, cdf_vals):
    # 标注位置：阶梯点右侧，y值水平对齐，避免重叠
    ax2.text(
        k_val + 0.1,
        cdf_val,
        f"{cdf_val:.4f}",
        ha="left",
        va="center",
        fontsize=8,
        color="#000000",
    )

plt.tight_layout()  # 自动调整间距，防止标注和标签重叠
plt.show()
