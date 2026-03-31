import random
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional
from collections import defaultdict


@dataclass
class User:
    atom_in: Set[int] = field(default_factory=set)
    atom_new: Set[int] = field(default_factory=set)
    atom_out: Set[int] = field(default_factory=set)
    linkout: Set[str] = field(default_factory=set)

    def add_atom(self, atom: int, is_origin: bool):
        """
        为用户添加原子，并根据规则决定是否传播

        Args:
            atom: 原子值
            is_origin: 是否为原点原子
        """
        # 避免重复添加
        if atom in self.atom_in or atom in self.atom_new:
            return

        # 原点原子：加入atom_in和atom_out
        if is_origin:
            self.atom_in.add(atom)
            self.atom_out.add(atom)
            return

        # 零原子：只加入atom_in，不传播
        if atom == 0:
            self.atom_in.add(atom)
            return

        # 普通原子：加入atom_new缓存区
        self.atom_new.add(atom)

        # 阈值检查：缓存区达到2个原子或待传播队列为空时触发
        if len(self.atom_new) >= 2 or len(self.atom_out) == 0:
            if not self.atom_new:
                return

            # 随机选择一个原子传播
            selected_atom = random.choice(list(self.atom_new))
            self.atom_out.add(selected_atom)

            # 合并所有新原子到atom_in
            self.atom_in = self.atom_in | self.atom_new
            self.atom_new.clear()


class MockDatabase:
    """
    模拟数据库操作，用于存储和读取用户数据
    在实际应用中，这里应该替换为真实的数据库实现
    """

    def __init__(self):
        self._users: Dict[str, User] = {}

    def read_user(self, user_hash: str) -> Optional[User]:
        """
        从数据库读取用户数据

        Args:
            user_hash: 用户哈希值

        Returns:
            User对象，如果用户不存在则返回None
        """
        return self._users.get(user_hash)

    def write_user(self, user_hash: str, user: User) -> bool:
        """
        将用户数据写入数据库

        Args:
            user_hash: 用户哈希值
            user: User对象

        Returns:
            写入是否成功
        """
        try:
            self._users[user_hash] = user
            return True
        except Exception:
            return False

    def user_exists(self, user_hash: str) -> bool:
        """
        检查用户是否存在

        Args:
            user_hash: 用户哈希值

        Returns:
            用户是否存在
        """
        return user_hash in self._users


def add_atoms_and_propagate(
    user_hash_start: str,
    atoms: List[int],
    is_origin: bool,
    database: Optional[MockDatabase] = None,
) -> bool:
    """
    批量添加原子并传播的核心函数

    该函数实现了比特币v0.1.0中的原子传播机制：
    1. 从起始用户开始添加原子
    2. 根据用户关联关系传播原子
    3. 使用双向map交替处理入向和出向原子

    Args:
        user_hash_start: 起始用户哈希值
        atoms: 待传播的原子列表
        is_origin: 是否为原点原子（只有第一次传播为true）
        database: 数据库对象，如果为None则使用默认的模拟数据库

    Returns:
        操作是否成功

    业务逻辑说明：
    - 使用两个字典交替处理，避免循环依赖
    - 只在原子集合发生变化时才写入数据库
    - 只有产生新的待传播原子时才继续传播
    - 原点原子只在第一次传播时为true，后续传播都为false
    """
    print(f"add_atoms_and_propagate: {user_hash_start}, {atoms}, {is_origin}")    

    # 使用提供的数据库或创建新的模拟数据库
    db = database or MockDatabase()

    # 创建两个传播队列，交替使用
    # propagate_queues[0]用于处理当前轮次的用户
    # propagate_queues[1]用于准备下一轮次的用户
    propagate_queues: List[Dict[str, List[int]]] = [
        defaultdict(list),
        defaultdict(list),
    ]

    # 初始化第一个队列，将起始用户和待传播的原子加入
    propagate_queues[0][user_hash_start] = atoms

    # 传播循环：交替处理两个队列，直到队列为空
    side = 0
    while propagate_queues[side]:
        # 当前轮次的队列和下一轮次的队列
        current_queue = propagate_queues[side]
        next_queue = propagate_queues[1 - side]

        # 遍历当前队列中的所有用户
        for user_hash, received_atoms in current_queue.items():
            # 从数据库读取用户数据
            user = db.read_user(user_hash)

            # 如果用户不存在，创建新用户
            if user is None:
                user = User()
                # 写入新用户到数据库
                if not db.write_user(user_hash, user):
                    return False

            # 记录原子数量变化，用于判断是否需要写入数据库
            original_in_size = len(user.atom_in)
            original_new_size = len(user.atom_new)
            original_out = user.atom_out.copy()
            original_out_size = len(original_out)

            # 为用户添加所有接收到的原子
            for atom in received_atoms:
                user.add_atom(atom, is_origin)

            # 仅仅第一次传播的是原子原点，后续传播的原子都不是原点原子
            is_origin = False

            # 如果原子集合没有变化，跳过后续处理
            if (
                len(user.atom_in) == original_in_size
                and len(user.atom_new) == original_new_size
            ):
                continue

            # 检查是否有新的待传播原子
            if len(user.atom_out) > original_out_size:
                # 获取新增的待传播原子
                new_atoms = list(user.atom_out - original_out)

                # 将新增原子传播给所有关联用户
                for linked_user_hash in user.linkout:
                    next_queue[linked_user_hash].extend(new_atoms)

            # 将更新后的用户数据写回数据库
            if not db.write_user(user_hash, user):
                return False

        # 完成当前轮次处理后，清空当前队列
        current_queue.clear()
        side = 1 - side

    return True


def add_atoms_and_propagate_v2(
    user_hash_start: str,
    atoms: List[int],
    is_origin: bool,
    database: Optional[MockDatabase] = None,
) -> bool:
    """
    批量添加原子并传播的优化版本

    优化点：
    1. 使用集合操作提高效率
    2. 减少不必要的数据复制
    3. 更清晰的变量命名
    4. 使用side变量实现高效的队列切换，避免copy操作
    5. 完成当前轮次后清空当前队列，逻辑更通畅

    Args:
        user_hash_start: 起始用户哈希值
        atoms: 待传播的原子列表
        is_origin: 是否为原点原子
        database: 数据库对象

    Returns:
        操作是否成功
    """
    print(f"add_atoms_and_propagate_v2: {user_hash_start}, {atoms}, {is_origin}")    
    db = database or MockDatabase()

    # 使用两个字典交替处理，避免copy操作
    # propagation_0和propagation_1交替使用，side变量控制当前使用哪一个
    propagation_0: Dict[str, Set[int]] = {user_hash_start: set(atoms)}
    propagation_1: Dict[str, Set[int]] = {}
    side = 0  # 控制当前使用的传播队列：0表示propagation_0，1表示propagation_1

    # 使用列表存储两个字典，便于通过side变量快速切换
    propagation_queues = [propagation_0, propagation_1]

    while propagation_queues[side]:
        # 获取当前轮次和下一轮次的传播队列
        current_queue = propagation_queues[side]
        next_queue = propagation_queues[1 - side]

        # 清空下一轮次的队列，准备接收新的传播数据
        next_queue.clear()

        for user_hash, received_atoms in current_queue.items():
            user = db.read_user(user_hash)

            if user is None:
                user = User()
                if not db.write_user(user_hash, user):
                    return False

            # 记录原始状态：保存原始大小，避免copy操作
            # 通过比较大小来判断是否有变化，而不是比较集合内容
            original_in_size = len(user.atom_in)
            original_new_size = len(user.atom_new)
            original_out = user.atom_out.copy()  # 必须copy，否则引用会跟着变化
            original_out_size = len(original_out)

            # 添加原子
            for atom in received_atoms:
                user.add_atom(atom, is_origin)

            is_origin = False

            # 检查是否有变化：通过比较大小来判断
            if (len(user.atom_in) == original_in_size and 
                len(user.atom_new) == original_new_size):
                continue

            # 检查是否有新的待传播原子
            if len(user.atom_out) > original_out_size:
                # 获取新增的待传播原子：通过大小差来判断新增的原子
                # 由于add_atom方法保证原子不重复，新增的原子就是size差值
                new_out_atoms = user.atom_out - original_out
                if new_out_atoms:
                    # 传播给关联用户
                    for linked_hash in user.linkout:
                        if linked_hash not in next_queue:
                            next_queue[linked_hash] = set()
                        next_queue[linked_hash].update(new_out_atoms)

            # 写入数据库
            if not db.write_user(user_hash, user):
                return False

        # 完成当前轮次处理后，清空当前队列
        current_queue.clear()
        
        # 切换传播队列：通过改变side变量来切换，避免copy操作
        side = 1 - side

    return True


# 使用示例
if __name__ == "__main__":
    # 创建模拟数据库
    db = MockDatabase()

    # 创建测试用户
    user_a = User(atom_in={10, 20}, atom_out={50, 60, 70}, linkout={"user_b", "user_c"})
    user_b = User(atom_in={30}, atom_out={40}, linkout={"user_d"})
    user_c = User(atom_in=set(), atom_out=set(), linkout=set())
    user_d = User(atom_in=set(), atom_out=set(), linkout=set())

    # 写入用户数据
    db.write_user("user_a", user_a)
    db.write_user("user_b", user_b)
    db.write_user("user_c", user_c)
    db.write_user("user_d", user_d)

    # 模拟User A评论User B，触发原子传播
    success = add_atoms_and_propagate_v2(
        user_hash_start="user_b", atoms=[50, 60, 70], is_origin=False, database=db
    )

    print(f"传播操作{'成功' if success else '失败'}")

    # 查看传播结果
    print("\n传播后的用户状态：")
    for user_hash in ["user_a", "user_b", "user_c", "user_d"]:
        user = db.read_user(user_hash)
        if user:
            print(f"{user_hash}:")
            print(f"  atom_in: {user.atom_in}")
            print(f"  atom_new: {user.atom_new}")
            print(f"  atom_out: {user.atom_out}")
            print(f"  linkout: {user.linkout}")
