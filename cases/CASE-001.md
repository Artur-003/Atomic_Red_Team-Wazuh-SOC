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

![ART](PowerShell.ART.png)


---

## 2. Detection

После запуска Atomic Red Team были получены события создания процессов Windows.

В Wazuh обнаружены события **Windows Event ID 4688 — Process Creation**,
связанные с выполненной активностью.

![Wazuh Detection](../screenshots/CASE-001/01-wazuh-process-creation.png)

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

![Process Details](../screenshots/CASE-001/02-suspicious-command.png)

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

![Event Evidence](../screenshots/CASE-001/03-powershell-execution.png)

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

## Вывод аналитика

Atomic Red Team успешно сгенерировал активность, соответствующую
MITRE ATT&CK T1059.001 — PowerShell.

События создания процессов были получены и проанализированы в Wazuh.
Windows Event ID 4688 позволил исследовать процесс, command line,
пользователя и связанные процессы.

Расследование проведено по схеме:

**Detection → Validation → Scope → Evidence → Verdict**

**Итоговый Verdict: Benign Positive (BP).**
