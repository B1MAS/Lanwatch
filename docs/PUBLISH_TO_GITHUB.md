# Публикация LANwatch на GitHub

## 1. Создать пустой репозиторий

1. Откройте <https://github.com/new> под профилем `B1MAS`.
2. В поле **Repository name** укажите `lanwatch`.
3. В описание вставьте:

   ```text
   Local security monitor for home and small networks: router adapters, anomaly detection, local dashboard and SIEM exports.
   ```

4. Выберите **Public**.
5. Не добавляйте README, `.gitignore` и лицензию: они уже находятся в проекте.
6. Нажмите **Create repository**.

## 2. Отправить подготовленный проект

Откройте терминал внутри распакованной папки `lanwatch` и выполните:

```sh
git init
git add .
git status
git commit -m "Initial public release of LANwatch"
git branch -M main
git remote add origin https://github.com/B1MAS/lanwatch.git
git push -u origin main
```

Перед `git commit` команда `git status` должна показывать исходный код,
документацию, тесты и изображения. В списке не должно быть `.lanwatch/`, `.env`,
`*.sqlite3`, `lanwatch-probe.json`, экспортов событий, `build/` и
`*.egg-info/`.

Если Git попросит имя автора:

```sh
git config user.name "Пушняков Дмитрий"
git config user.email "ВАШ_NOREPLY_АДРЕС_ИЗ_GITHUB"
```

Адрес для приватных коммитов можно скопировать в GitHub: **Settings → Emails →
Keep my email addresses private**. Обычный пароль аккаунта для `git push` не
используется. Удобнее авторизоваться через GitHub CLI командой `gh auth login`
или применить personal access token вместо пароля.

## 3. Оформить страницу репозитория

В блоке **About** нажмите шестерёнку и добавьте темы:

```text
cybersecurity, network-monitoring, home-network, security-monitoring, router,
openwrt, python, siem, wazuh, blue-team
```

После загрузки откройте вкладку **Actions** и убедитесь, что workflow `tests`
завершился зелёным статусом. Затем проверьте README и все четыре изображения.

## 4. Создать первый релиз

В локальном репозитории:

```sh
git tag -a v0.5.1 -m "LANwatch v0.5.1"
git push origin v0.5.1
```

На GitHub откройте **Releases → Draft a new release**, выберите тег `v0.5.1`,
заголовок `LANwatch v0.5.1` и приложите исходный архив. В описании можно указать:

```text
First public release of LANwatch: Xiaomi MiWiFi and experimental OpenWrt
adapters, local dashboard, SQLite history, read-only security audit, SIEM
exports and Wazuh examples.
```
