# CASE-001 PowerShell Command Execution

## Обзор

В контролируемой лабораторной среде была проведена симуляция техники
PowerShell с использованием Atomic Red Team.

После выполнения теста полученные события Windows были проанализированы
в Wazuh SIEM.

**MITRE ATT&CK:** T1059.001 — PowerShell  
**Tactic:** Execution  
**Atomic Test:** T1059.001-17 — PowerShell Command Execution  
**SIEM:** Wazuh  
**Источник логов:** Windows Security Event Log  
**Event ID:** 4688 — Process Creation  

---

## 1. Симуляция атаки

Для генерации активности использовался Atomic Red Team.

Был выполнен тест:

**T1059.001-17 — PowerShell Command Execution**

Тест имитирует выполнение команд через PowerShell на Windows-хосте.

<img width="1841" height="588" alt="00-atomic-red-team" src="https://github.com/user-attachments/assets/8d0c2c42-7457-4c1a-99fc-59cfd59ec8c8" />



---

## 2. Detection

После запуска Atomic Red Team были получены события создания процессов Windows.

В Wazuh обнаружены события **Windows Event ID 4688 — Process Creation**,
связанные с выполненной активностью.

<img width="923" height="1043" alt="Снимок экрана от 2026-09-07 10-50-18" src="https://github.com/user-attachments/assets/7e996c78-fef9-4616-b472-ba97e080bb57" />

---

## 3. Validation

Для проверки активности были проанализированы события создания процессов
в Wazuh.

Проверены:

- имя процесса;
- command line;
- parent process;
- пользователь;
- хост;
- время события.

В событиях была обнаружена активность PowerShell и связанных процессов,
соответствующая выполненному тесту Atomic Red Team.

<img width="923" height="1043" alt="Снимок экрана от 2026-09-07 10-53-02" src="https://github.com/user-attachments/assets/94a9d1fa-0c19-49b3-8132-15f39f9af3c3" />


---

## 4. Scope

Для определения масштаба активности были проверены:

- затронутый Windows-хост;
- учётная запись пользователя;
- связанные процессы;
- command-line arguments;
- события в соответствующем временном диапазоне.

Признаков распространения активности на другие хосты в рамках
проведённого анализа обнаружено не было.

---

## 5. Evidence

В ходе расследования были получены следующие артефакты:

- Windows Event ID 4688;
- выполнение PowerShell;
- command-line arguments;
- parent/child process;
- пользователь;
- информация о хосте;
- результат выполнения Atomic Red Team.

<img width="923" height="1043" alt="Снимок экрана от 2026-09-07 10-59-02" src="https://github.com/user-attachments/assets/2c4a423c-7ffb-469c-9de8-3d2b6d2d1bc5" />


---

## 6. MITRE ATT&CK

**Tactic:** Execution  
**Technique:** T1059 — Command and Scripting Interpreter  
**Sub-technique:** T1059.001 — PowerShell

Наблюдаемая активность соответствует использованию PowerShell
для выполнения команд.

---

## 7. Severity / Priority

**Severity:** Medium  
**Priority:** Low

Выполнение команд через PowerShell потенциально может быть связано
с вредоносной активностью и требует проверки.

После Validation было установлено, что активность была намеренно
сгенерирована в лабораторной среде с помощью Atomic Red Team.

Поэтому Priority был снижен до Low.

---

## 8. Verdict

**Verdict: Benign Positive (BP)**

Активность действительно происходила и была зафиксирована средствами
мониторинга, однако являлась частью разрешённой лабораторной симуляции.

**Escalation:** не требуется.  
**Containment:** не требуется.

---

## Вывод

Atomic Red Team успешно сгенерировал активность, соответствующую
MITRE ATT&CK T1059.001 — PowerShell.

События создания процессов были получены и проанализированы в Wazuh.
Windows Event ID 4688 позволил исследовать процесс, command line,
пользователя и связанные процессы.

Расследование проведено по схеме:

**Detection → Validation → Scope → Evidence → Verdict**

**Итоговый Verdict: Benign Positive (BP).**
