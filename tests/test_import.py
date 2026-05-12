def test_import_xphylax():
    import importlib
    module = importlib.import_module("xphylax")
    assert module is not None
