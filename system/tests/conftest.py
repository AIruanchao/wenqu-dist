import pytest


@pytest.fixture
def td(tmp_path):
    """统一临时目录 fixture（与各测试文件 __main__ 自跑器的 td 语义一致）。"""
    return tmp_path
