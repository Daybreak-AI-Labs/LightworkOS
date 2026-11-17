from text import slugify


def test_simple_title():
    assert slugify("Hello World") == "hello-world"
