# Публичная поставка ARA VPN 0.1.1

Организация: [ARA VPN](https://github.com/ARA-VPN-Project).
Репозиторий: [ARA-VPN](https://github.com/ARA-VPN-Project/ARA-VPN).
Выпуск: [v0.1.1](https://github.com/ARA-VPN-Project/ARA-VPN/releases/tag/v0.1.1).

Публичное дерево создаёт release/export-source.sh. Не загружайте рабочую папку
целиком: частный inventory и эксплуатационные материалы остаются вне экспорта.
До push проверяются diff, секреты, ссылки и лицензионный комплект.

В GitHub Release публикуются четыре компонента для каждой объявленной архитектуры
amd64/armhf, install.sh и configure-panel.sh, архитектурные SHA256SUMS,
BOOTSTRAP-SHA256SUMS, RELEASE-SHA256SUMS, исходники ARA и отчёт приёмки.
Обязательные отдельные source-ассеты: THIRD-PARTY-SOURCES.tar.gz и
NAIVEPROXY-SOURCES-72a06c9f.tar.gz. Они предоставляются бесплатно рядом с бинарниками.

Корневой install.sh в репозитории — короткий version-pinned launcher. Ассет
install.sh в Release — проверяемый Debian bootstrap. Launcher проверяет SHA-256
bootstrap и передаёт pinned manifest; bootstrap проверяет SHA-256 и идентичность
каждого пакета. Это разные уровни установки с одинаковым именем файла.

Лицензия ARA — AGPL-3.0-or-later. Движок и прочие зависимости сохраняют свои
условия. [Лицензионная приёмка](LICENSE_ACCEPTANCE_0.1.1.md) ·
[Проверка секретов](PUBLICATION_SECURITY_0.1.1.md) · [Исходники компонентов](../SOURCES.md).

При обновлении выпуска заново сверить бинарники, версии, источники и хеши,
обновить pinned launcher, документацию и release notes. Новые возможности
принимаются отдельно; публикация не расширяет границы ARM, Docker или DPI.
После публикации обязательно проверить реальные публичные ссылки и installer
--check с GitHub на Debian. Пользовательская команда находится в README.md.
