import pytest


@pytest.fixture
def td(tmp_path):
    """统一临时目录 fixture（与各测试文件 __main__ 自跑器的 td 语义一致）。"""
    return tmp_path


@pytest.fixture
def root(tmp_path):
    """test_ac_* 族的语料根 fixture（与各文件 __main__ 自跑器的 root/td 语义一致）。"""
    return tmp_path
