import numpy as np
import matplotlib.pyplot as plt
import matplotlib.animation as animation


def update(frameNum, img, grid, N):
    """更新网格状态"""
    newGrid = grid.copy()
    for i in range(N):
        for j in range(N):
            # 计算摩尔邻域的活元胞数量（周期边界条件）
            total = int(
                (
                    grid[i, (j - 1) % N]
                    + grid[i, (j + 1) % N]
                    + grid[(i - 1) % N, j]
                    + grid[(i + 1) % N, j]
                    + grid[(i - 1) % N, (j - 1) % N]
                    + grid[(i - 1) % N, (j + 1) % N]
                    + grid[(i + 1) % N, (j - 1) % N]
                    + grid[(i + 1) % N, (j + 1) % N]
                )
            )

            # 应用康威生命游戏规则
            if grid[i, j] == 1:
                newGrid[i, j] = 1 if (total == 2 or total == 3) else 0
            else:
                newGrid[i, j] = 1 if total == 3 else 0

    img.set_data(newGrid)
    grid[:] = newGrid[:]
    return (img,)


# 初始化参数
N = 100  # 网格大小
grid = np.random.choice([0, 1], N * N, p=[0.8, 0.2]).reshape(N, N)  # 随机初始状态

# 设置动画
fig, ax = plt.subplots()
img = ax.imshow(grid, interpolation="nearest", cmap="binary")
ani = animation.FuncAnimation(
    fig, update, fargs=(img, grid, N), frames=100, interval=50, blit=True
)

plt.show()
