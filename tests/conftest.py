"""pytest-опции для consistency-теста. B вызывает: pytest --model-path <art> [--consistency-script <s>]."""


def pytest_addoption(parser):
    parser.addoption("--model-path", action="store", default="",
                     help="путь к артефакту модели для проверки train↔serve")
    parser.addoption("--consistency-script", action="store", default="",
                     help="(опц.) внешний скрипт consistency-проверки")
