from pestilentia.web.mugshot import generate_mugshot


def test_mugshot_deterministic():
    img1 = generate_mugshot("lockbit", size=128)
    img2 = generate_mugshot("lockbit", size=128)
    assert list(img1.tobytes()) == list(img2.tobytes())


def test_mugshot_different_names():
    img1 = generate_mugshot("lockbit", size=128)
    img2 = generate_mugshot("alphv", size=128)
    assert list(img1.tobytes()) != list(img2.tobytes())


def test_mugshot_respects_size():
    img = generate_mugshot("test", size=512)
    assert img.size == (512, 512)


def test_mugshot_empty_name():
    img = generate_mugshot("", size=128)
    assert img.size == (128, 128)


def test_mugshot_long_name():
    img = generate_mugshot("a" * 500, size=128)
    assert img.size == (128, 128)
