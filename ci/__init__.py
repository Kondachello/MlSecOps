"""ci/ — CI-обучение (retrain в проде) и связанные workflow-помощники.

retrain.py — запускается из gates-runner-а по триггеру /promote, переобучает модель
с нуля под сервисным аккаунтом `ci`, новый ран получает security.origin=ci_trained.
"""
